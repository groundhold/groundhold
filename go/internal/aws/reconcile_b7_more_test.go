package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file rounds out BATCH 7 reconcile coverage: the ByPID tier-1 fast paths
// (rc7ACMByPID, rc7EFSByPID, rc7GuardDutyByPID) were previously exercised only via
// their positive (owned, matching) case indirectly through reconcileX, leaving the
// "found but foreign" fallthrough and the no-pid scan (rc7PodIdentityScan)
// completely untested (0% coverage).

// ---- acm: rc7ACMByPID ------------------------------------------------------

func TestRc7ACMByPID_ForeignFallsThroughToScan(t *testing.T) {
	// acmServer's DescribeCertificate/ListCertificates both answer the SAME fixed
	// cert regardless of the ARN queried, tagged "someone-else" — a valid-format
	// pid resolves to a live cert that is NOT ours, so rc7ACMByPID must decline
	// (ok=false) and fall through to the list scan, which also finds no owned
	// match -> failed (never adopts the foreign cert via the pid shortcut).
	srv := acmServer(t, "someone-else", "app.example.com", "ELIGIBLE")
	defer srv.Close()
	d := acmDriver(t, srv)
	pid := acmProviderID("us-east-1", "000000000000", "12345678-1234-1234-1234-123456789012")

	res := d.Reconcile("web", "prod", map[string]any{
		"target": "aws.acm/x", "operation": "create", "generation": 1, "targetProviderId": pid})
	if res.Status != "failed" {
		t.Fatalf("a foreign cert at our pid must fall through to a failed list scan, got %+v", res)
	}
}

func TestRc7ACMByPID_MalformedPIDFallsThrough(t *testing.T) {
	srv := acmServer(t, "web", "app.example.com", "ELIGIBLE")
	defer srv.Close()
	d := acmDriver(t, srv)

	res := d.Reconcile("web", "prod", map[string]any{
		"target": "aws.acm/x", "operation": "create", "generation": 1, "targetProviderId": "garbage"})
	if res.Status != "succeeded" {
		t.Fatalf("a malformed pid must fall through to the list scan (still succeeds via the listed cert), got %+v", res)
	}
}

// ---- efs: rc7EFSByPID -------------------------------------------------------

func TestRc7EFSByPID_ForeignFallsThroughToScan(t *testing.T) {
	srv := efsServer(t, "someone-else", "", "")
	defer srv.Close()
	d := efsDriver(t, srv)
	pid := efsProviderID("eu-central-1", "000000000000", "fs-0123456789abcdef0")

	res := d.Reconcile("shared", "prod", map[string]any{
		"target": "aws.efs/x", "operation": "create", "generation": 1, "targetProviderId": pid})
	if res.Status != "failed" {
		t.Fatalf("a foreign file system at our pid must fall through to a failed list scan, got %+v", res)
	}
}

// ---- guardduty: rc7GuardDutyByPID -------------------------------------------

func TestRc7GuardDutyByPID_Succeeds(t *testing.T) {
	f := &fakeGuardDuty{
		detectorID: gdDetectorID, exists: true, status: "ENABLED",
		tags: map[string]string{
			"groundhold-capability": sanitizeTag(gdCap), "groundhold-environment": sanitizeTag("prod")}}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := guardDutyDriver(t, srv)
	pid := guardDutyProviderID(gdRegion, gdDetectorID)

	res := d.Reconcile(gdCap, "prod", map[string]any{
		"target": "aws.guardduty/x", "operation": "create", "generation": 1, "targetProviderId": pid})
	if res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("an owned detector at our pid must conclude succeeded via the tier-1 path, got %+v", res)
	}
}

func TestRc7GuardDutyByPID_ForeignFallsThroughToScan(t *testing.T) {
	f := &fakeGuardDuty{
		detectorID: gdDetectorID, exists: true, status: "ENABLED",
		tags: map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"}}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := guardDutyDriver(t, srv)
	pid := guardDutyProviderID(gdRegion, gdDetectorID)

	res := d.Reconcile(gdCap, "prod", map[string]any{
		"target": "aws.guardduty/x", "operation": "create", "generation": 1, "targetProviderId": pid})
	if res.Status != "failed" {
		t.Fatalf("a foreign detector at our pid must fall through to a failed list scan, got %+v", res)
	}
}

// ---- backupplan: rc7BackupPlanByPID -----------------------------------------

func TestRc7BackupPlanByPID_ForeignFallsThroughToScan(t *testing.T) {
	srv := bkpServer(t, "someone-else")
	defer srv.Close()
	d := bkpDriver(t, srv)
	pid := "backupplan:eu-central-1:plan-abc"

	res := d.Reconcile("archive", "prod", map[string]any{
		"target": "aws.backupplan/x", "operation": "create", "generation": 1, "targetProviderId": pid})
	if res.Status != "failed" {
		t.Fatalf("a foreign plan at our pid must fall through to a failed list scan, got %+v", res)
	}
}

func TestRc7BackupPlanByPID_MalformedPIDFallsThrough(t *testing.T) {
	srv := bkpServer(t, "archive")
	defer srv.Close()
	d := bkpDriver(t, srv)

	res := d.Reconcile("archive", "prod", map[string]any{
		"target": "aws.backupplan/x", "operation": "create", "generation": 1, "targetProviderId": "not-a-pid"})
	if res.Status != "failed" {
		t.Fatalf("a malformed pid must fall through to the list scan; got %+v", res)
	}
}

// ---- eks-podidentity: rc7PodIdentityScan (no-pid list scan) -----------------

// eksPodIDScanServer is a minimal ListClusters/ListPodIdentityAssociations/
// describe fake for the SCAN path (as opposed to fakePodID, which is keyed to one
// cluster/association pinned by a providerId). The per-association describe
// response carries `tags` — the field the discovery-shaped fakePodID server never
// populates.
func eksPodIDScanServer(t *testing.T, cluster, assocID, ns, sa string, tags map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/clusters":
			_, _ = w.Write([]byte(`{"clusters":["` + cluster + `"]}`))
		case "/clusters/" + cluster + "/pod-identity-associations":
			_, _ = w.Write([]byte(`{"associations":[{"associationId":"` + assocID +
				`","namespace":"` + ns + `","serviceAccount":"` + sa + `"}]}`))
		case "/clusters/" + cluster + "/pod-identity-associations/" + assocID:
			tagJSON := "{"
			first := true
			for k, v := range tags {
				if !first {
					tagJSON += ","
				}
				first = false
				tagJSON += `"` + k + `":"` + v + `"`
			}
			tagJSON += "}"
			_, _ = w.Write([]byte(`{"association":{"associationId":"` + assocID +
				`","namespace":"` + ns + `","serviceAccount":"` + sa + `","tags":` + tagJSON + `}}`))
		default:
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
		}
	}))
}

func TestRc7PodIdentityScan_Succeeds(t *testing.T) {
	srv := eksPodIDScanServer(t, "acme-prod", "a-1", "kube-system", "ebs-csi-controller-sa",
		map[string]string{"groundhold-capability": sanitizeTag(eksPodIDCap), "groundhold-environment": sanitizeTag("prod")})
	defer srv.Close()
	d := eksProvDriver(t, srv)

	res := d.Reconcile(eksPodIDCap, "prod", map[string]any{
		"target": "aws.eks-podidentity/x", "operation": "create", "generation": 1})
	want := eksPodIdentityProviderID("eu-central-1", "acme-prod", "kube-system", "ebs-csi-controller-sa")
	if res.Status != "succeeded" || res.ProviderID != want {
		t.Fatalf("an owned association found by the no-pid scan must conclude succeeded with %q, got %+v", want, res)
	}
}

func TestRc7PodIdentityScan_NoOwnedMatchFails(t *testing.T) {
	srv := eksPodIDScanServer(t, "acme-prod", "a-1", "kube-system", "ebs-csi-controller-sa",
		map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"})
	defer srv.Close()
	d := eksProvDriver(t, srv)

	res := d.Reconcile(eksPodIDCap, "prod", map[string]any{
		"target": "aws.eks-podidentity/x", "operation": "create", "generation": 1})
	if res.Status != "failed" {
		t.Fatalf("no owned association across all clusters must conclude failed, got %+v", res)
	}
}

func TestRc7PodIdentityScan_ListClustersUnreadableIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()
	d := eksProvDriver(t, srv)

	res := d.Reconcile(eksPodIDCap, "prod", map[string]any{
		"target": "aws.eks-podidentity/x", "operation": "create", "generation": 1})
	if res.Status != "unknown" {
		t.Fatalf("an unreadable ListClusters must conclude unknown, got %+v", res)
	}
}

func TestRc7PodIdentityScan_RegionlessIsUnknown(t *testing.T) {
	d := NewDriver("")
	res := d.Reconcile(eksPodIDCap, "prod", map[string]any{
		"target": "aws.eks-podidentity/x", "operation": "create", "generation": 1})
	if res.Status != "unknown" {
		t.Fatalf("a regionless driver must refuse to scan and conclude unknown, got %+v", res)
	}
}

// ---- backupplan: the actual LIST-SCAN closure (rc7ListBackupPlans returning a
// REAL plan id, so the per-id read/tag-match closure in reconcileBackupPlan
// executes) — bkpServer's list and per-id GET share one path prefix and always
// answer the SAME single-plan body, so ListBackupPlans decodes to an empty
// BackupPlansList and the per-id closure never runs under it. This dedicated
// server distinguishes the two paths.

func bkpListServer(t *testing.T, planID, capLabel string) *httptest.Server {
	t.Helper()
	const arn = "arn:aws:backup:eu-central-1:000000000000:backup-plan:" + "PLANARN"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/backup/plans/":
			_, _ = w.Write([]byte(`{"BackupPlansList":[{"BackupPlanId":"` + planID + `"}]}`))
		case r.Method == "GET" && r.URL.Path == "/backup/plans/"+planID+"/":
			_, _ = w.Write([]byte(`{"BackupPlanId":"` + planID + `","BackupPlanArn":"` + arn + `"}`))
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/tags/"):
			_, _ = w.Write([]byte(`{"Tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestReconcileBackupPlan_ListScanSucceeds(t *testing.T) {
	srv := bkpListServer(t, "plan-xyz", "archive")
	defer srv.Close()
	d := bkpDriver(t, srv)

	res := d.Reconcile("archive", "prod", map[string]any{
		"target": "aws.backupplan/x", "operation": "create", "generation": 1})
	want := backupPlanProviderID("eu-central-1", "plan-xyz")
	if res.Status != "succeeded" || res.ProviderID != want {
		t.Fatalf("a listed owned plan must conclude succeeded with %q, got %+v", want, res)
	}
}

func TestReconcileBackupPlan_ListScanForeignFails(t *testing.T) {
	srv := bkpListServer(t, "plan-xyz", "someone-else")
	defer srv.Close()
	d := bkpDriver(t, srv)

	res := d.Reconcile("archive", "prod", map[string]any{
		"target": "aws.backupplan/x", "operation": "create", "generation": 1})
	if res.Status != "failed" {
		t.Fatalf("a listed foreign plan must conclude failed, got %+v", res)
	}
}

func TestReconcileBackupPlan_RegionlessIsUnknown(t *testing.T) {
	d := NewDriver("")
	res := d.Reconcile("archive", "prod", map[string]any{
		"target": "aws.backupplan/x", "operation": "create", "generation": 1})
	if res.Status != "unknown" {
		t.Fatalf("a regionless driver must refuse to scan and conclude unknown, got %+v", res)
	}
}

// ---- route53: the actual LIST-SCAN closure (rc7ListHostedZones + the per-zone
// read) — r53Server serves no ListHostedZones at all (always 404), so
// TestReconcileRoute53_NoListIsUnknown only exercises the list-unreadable branch.
// This dedicated server lists a real zone so the per-zone tag-match closure runs.

func r53ListServer(t *testing.T, zoneID, tagCap string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/2013-04-01/hostedzone":
			_, _ = w.Write([]byte(`<ListHostedZonesResponse><HostedZones>` +
				`<HostedZone><Id>/hostedzone/` + zoneID + `</Id><Name>example.com.</Name></HostedZone>` +
				`</HostedZones><IsTruncated>false</IsTruncated></ListHostedZonesResponse>`))
		case r.Method == "GET" && r.URL.Path == "/2013-04-01/hostedzone/"+zoneID:
			_, _ = w.Write([]byte(`<GetHostedZoneResponse><HostedZone>` +
				`<Id>/hostedzone/` + zoneID + `</Id><Name>example.com.</Name>` +
				`<Config><PrivateZone>false</PrivateZone></Config></HostedZone></GetHostedZoneResponse>`))
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/2013-04-01/tags/"):
			_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ResourceTagSet><Tags>` +
				`<Tag><Key>groundhold-capability</Key><Value>` + tagCap + `</Value></Tag>` +
				`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
				`</Tags></ResourceTagSet></ListTagsForResourceResponse>`))
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestReconcileRoute53_ListScanSucceeds(t *testing.T) {
	srv := r53ListServer(t, "Z999XYZ", "apex")
	defer srv.Close()
	d := r53Driver(t, srv)

	res := d.Reconcile("apex", "prod", map[string]any{
		"target": "aws.route53/x", "operation": "create", "generation": 1})
	want := r53ProviderID("Z999XYZ")
	if res.Status != "succeeded" || res.ProviderID != want {
		t.Fatalf("a listed owned zone must conclude succeeded with %q, got %+v", want, res)
	}
}

func TestReconcileRoute53_ListScanForeignFails(t *testing.T) {
	srv := r53ListServer(t, "Z999XYZ", "someone-else")
	defer srv.Close()
	d := r53Driver(t, srv)

	res := d.Reconcile("apex", "prod", map[string]any{
		"target": "aws.route53/x", "operation": "create", "generation": 1})
	if res.Status != "failed" {
		t.Fatalf("a listed foreign zone must conclude failed, got %+v", res)
	}
}
