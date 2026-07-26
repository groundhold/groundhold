package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// gcsServer routes the JSON API v1 calls. IAM is stateful: the bucket IAM GET
// returns an allUsers objectViewer binding only after the PUT, so a public
// create's read-modify-write-confirm runs end to end.
func gcsServer(t *testing.T, bucketJSON string, putIamStatus int, putIamBody string, deleteStatus int) *httptest.Server {
	t.Helper()
	granted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case strings.HasSuffix(p, "/iam") && r.Method == "GET":
				if granted {
					_, _ = w.Write([]byte(`{"etag":"e1","version":3,"bindings":[` +
						`{"role":"roles/storage.objectViewer","members":["allUsers"]}]}`))
				} else {
					_, _ = w.Write([]byte(`{"etag":"e1","version":3,"bindings":[]}`))
				}
			case strings.HasSuffix(p, "/iam") && r.Method == "PUT":
				if putIamStatus != 0 && putIamStatus != 200 {
					w.WriteHeader(putIamStatus)
					_, _ = w.Write([]byte(putIamBody))
					return
				}
				granted = true
				_, _ = w.Write([]byte(`{"etag":"e2"}`))
			case r.Method == "POST" && strings.HasSuffix(p, "/b"):
				_, _ = w.Write([]byte(`{"name":"the-bucket"}`))
			case r.Method == "DELETE":
				if deleteStatus != 0 && deleteStatus != 204 {
					w.WriteHeader(deleteStatus)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			case r.Method == "GET": // buckets.get
				_, _ = w.Write([]byte(bucketJSON))
			default:
				w.WriteHeader(500)
			}
		}))
}

func gcsDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.GcsBaseURL = srv.URL
	d.ProjNumber = "111" // pre-resolved so tests don't need a CRM mock (D82)
	return d
}

func TestGCSCreatePublicGrantsViewer(t *testing.T) {
	srv := gcsServer(t, "", 200, "", 0)
	defer srv.Close()
	d := gcsDriver(t, srv)
	attrs := map[string]any{"location.region": "europe-central2",
		"network.publicExposure": true, "encryption.atRest": true, "service.managed": true}
	res := d.createGCS("assets", "prod", attrs, nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "gcs:acme-prod:") {
		t.Fatalf("got %+v, want succeeded + gcs-prefixed id", res)
	}
}

func TestGCSPublicBlockedByDRSIsFailed(t *testing.T) {
	srv := gcsServer(t, "", 400,
		`{"error":{"message":"domain restricted sharing forbids allUsers"}}`, 0)
	defer srv.Close()
	d := gcsDriver(t, srv)
	attrs := map[string]any{"location.region": "europe-central2",
		"network.publicExposure": true, "encryption.atRest": true, "service.managed": true}
	res := d.createGCS("assets", "prod", attrs, nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "domain-restricted-sharing") {
		t.Fatalf("got %+v, want failed on DRS", res)
	}
}

func TestGCSDeleteRetentionLockRefuses(t *testing.T) {
	bucket := `{"projectNumber":"111","labels":{"groundhold-capability":"assets","groundhold-environment":"prod"},` +
		`"retentionPolicy":{"isLocked":true}}`
	srv := gcsServer(t, bucket, 200, "", 0)
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.deleteGCS("assets", "prod", "gcs:acme-prod:the-bucket")
	if res.Status != "failed" || !strings.Contains(res.Reason, "LOCKED") {
		t.Fatalf("got %+v, want failed on locked retention", res)
	}
}

func TestGCSDeleteNonEmptyRefuses(t *testing.T) {
	bucket := `{"metageneration":"1","projectNumber":"111","labels":{"groundhold-capability":"assets","groundhold-environment":"prod"}}`
	srv := gcsServer(t, bucket, 200, "", http.StatusConflict)
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.deleteGCS("assets", "prod", "gcs:acme-prod:the-bucket")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not empty") {
		t.Fatalf("got %+v, want failed on non-empty bucket", res)
	}
}

func TestGCSDeleteOursSucceeds(t *testing.T) {
	bucket := `{"metageneration":"1","projectNumber":"111","labels":{"groundhold-capability":"assets","groundhold-environment":"prod"}}`
	srv := gcsServer(t, bucket, 200, "", 204)
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.deleteGCS("assets", "prod", "gcs:acme-prod:the-bucket")
	if res.Status != "succeeded" {
		t.Fatalf("got %+v, want succeeded", res)
	}
}

// D82: a bucket that is ours BY LABELS but lives in another project (different
// projectNumber) must be refused — labels are forgeable in the global namespace.
func TestGCSDeleteForeignProjectNumberRefused(t *testing.T) {
	bucket := `{"metageneration":"1","projectNumber":"999","labels":{` +
		`"groundhold-capability":"assets","groundhold-environment":"prod"}}`
	srv := gcsServer(t, bucket, 200, "", 204)
	defer srv.Close()
	d := gcsDriver(t, srv) // ProjNumber "111"
	res := d.deleteGCS("assets", "prod", "gcs:acme-prod:the-bucket")
	if res.Status != "failed" || !strings.Contains(res.Reason, "cross-project") {
		t.Fatalf("a foreign-project bucket must be refused, got %+v", res)
	}
}

func TestGCSCrossProjectRefused(t *testing.T) {
	srv := gcsServer(t, "{}", 200, "", 204)
	defer srv.Close()
	d := gcsDriver(t, srv) // d.Project == "acme-prod"
	res := d.deleteGCS("assets", "prod", "gcs:other-proj:the-bucket")
	if res.Status != "failed" || !strings.Contains(res.Reason, "cross-project") {
		t.Fatalf("got %+v, want cross-project refusal", res)
	}
}

func TestGCSDeleteMetagenerationConflictRefuses(t *testing.T) {
	bucket := `{"metageneration":"7","projectNumber":"111","labels":{"groundhold-capability":"assets",` +
		`"groundhold-environment":"prod"}}`
	srv := gcsServer(t, bucket, 200, "", http.StatusPreconditionFailed)
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.deleteGCS("assets", "prod", "gcs:acme-prod:the-bucket")
	if res.Status != "failed" || !strings.Contains(res.Reason, "metageneration conflict") {
		t.Fatalf("got %+v, want failed on metageneration conflict", res)
	}
}

func TestGCSBuilderDefaultsPrivate(t *testing.T) {
	// review #2: publicExposure is not a required attribute; when absent the wire
	// request must still ENFORCE prevention, matching the shell's default so an
	// idempotent retry of our own bucket does not read as drift.
	attrs := map[string]any{"location.region": "europe-central2",
		"encryption.atRest": true, "service.managed": true}
	req, err := BuildGCSCreateRequest("acme-prod", "prod", "assets", attrs, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	iam := req.Body["iamConfiguration"].(map[string]any)
	if iam["publicAccessPrevention"] != "enforced" {
		t.Fatalf("absent publicExposure must default to enforced, got %v",
			iam["publicAccessPrevention"])
	}
}

func TestObserveGCSFineGrainedIsDiagnostic(t *testing.T) {
	// review #1 + #4: uniform bucket-level access OFF means object ACLs can expose
	// data the IAM policy never mentions, so publicExposure must be a diagnostic
	// (not a measured false); retention.minimum must be emitted from the period.
	bucket := `{"location":"EUROPE-CENTRAL2","metageneration":"3","projectNumber":"111",` +
		`"retentionPolicy":{"retentionPeriod":"604800"},` +
		`"iamConfiguration":{"publicAccessPrevention":"inherited",` +
		`"uniformBucketLevelAccess":{"enabled":false}}}`
	srv := gcsServer(t, bucket, 200, "", 0)
	defer srv.Close()
	d := gcsDriver(t, srv)
	obs, diags, err := d.observeGCS("assets", "gcs:acme-prod:the-bucket")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "network.publicExposure" {
			t.Fatalf("publicExposure must not be measured when UBLA is off, got %+v", o)
		}
	}
	var sawDiag, sawRetention bool
	for _, dg := range diags {
		if strings.Contains(dg, "uniform bucket-level access is off") {
			sawDiag = true
		}
	}
	for _, o := range obs {
		if o.Path == "retention.minimum" && o.Value == "604800s" {
			sawRetention = true
		}
	}
	if !sawDiag {
		t.Errorf("want a UBLA-off diagnostic, got %v", diags)
	}
	if !sawRetention {
		t.Errorf("want retention.minimum=604800s observed, got %+v", obs)
	}
}

func TestObserveGCSDualRegionReplication(t *testing.T) {
	// A configurable dual-region bucket: location.region + replication.destinationRegion
	// are MEASURED from customPlacementConfig (the peers), not from the continent-level
	// Location; replication.enabled reads true.
	bucket := `{"location":"EU","metageneration":"3","projectNumber":"111",` +
		`"rpo":"ASYNC_TURBO",` +
		`"customPlacementConfig":{"dataLocations":["EUROPE-WEST1","EUROPE-NORTH1"]},` +
		`"iamConfiguration":{"publicAccessPrevention":"enforced",` +
		`"uniformBucketLevelAccess":{"enabled":true}}}`
	srv := gcsServer(t, bucket, 200, "", 0)
	defer srv.Close()
	d := gcsDriver(t, srv)
	obs, _, err := d.observeGCS("assets", "gcs:acme-prod:the-bucket")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "europe-west1" {
		t.Fatalf("location.region must be the primary dataLocation, got %v", got["location.region"])
	}
	if got["replication.enabled"] != true {
		t.Fatalf("dual-region must observe replication.enabled=true, got %v", got["replication.enabled"])
	}
	if got["replication.destinationRegion"] != "europe-north1" {
		t.Fatalf("destinationRegion must be MEASURED from the second peer, got %v", got["replication.destinationRegion"])
	}
}

func TestObserveGCSRegionalNoReplication(t *testing.T) {
	// A plain regional bucket: replication.enabled=false, no destinationRegion.
	bucket := `{"location":"EUROPE-CENTRAL2","metageneration":"3","projectNumber":"111",` +
		`"iamConfiguration":{"publicAccessPrevention":"enforced",` +
		`"uniformBucketLevelAccess":{"enabled":true}}}`
	srv := gcsServer(t, bucket, 200, "", 0)
	defer srv.Close()
	d := gcsDriver(t, srv)
	obs, _, err := d.observeGCS("assets", "gcs:acme-prod:the-bucket")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "replication.destinationRegion" {
			t.Fatalf("a regional bucket must not report a destinationRegion, got %+v", o)
		}
		if o.Path == "replication.enabled" && o.Value != false {
			t.Fatalf("a regional bucket must observe replication.enabled=false, got %+v", o)
		}
		if o.Path == "location.region" && o.Value != "europe-central2" {
			t.Fatalf("regional location.region=%v", o.Value)
		}
	}
}

func TestSameProjectUnpinnedIsNoOp(t *testing.T) {
	// Found live: observe/discover build the driver with no pinned project
	// (the project rides in each providerId), so the cross-project guard must
	// no-op on an empty pin — but still bite when a project IS pinned (apply).
	d := NewDriver("")
	if err := d.sameProject("example-project"); err != nil {
		t.Fatalf("unpinned project must not refuse a read: %v", err)
	}
	d2 := NewDriver("acme-prod")
	if err := d2.sameProject("other-proj"); err == nil {
		t.Fatal("a pinned project must still refuse a cross-project providerId")
	}
}

func TestSplitGcsProviderID(t *testing.T) {
	if _, _, err := splitGcsProviderID("gcs:proj:my.bucket_name-1"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	for _, b := range []string{
		"proj:name",          // no service token
		"cloudrun:proj:name", // wrong token
		"gcs:proj:name:x",    // too many parts
		"gcs:proj:UP",        // uppercase bucket
		"gcs:proj:a/b",       // slash
	} {
		if _, _, err := splitGcsProviderID(b); err == nil {
			t.Errorf("accepted malformed/foreign gcs id: %q", b)
		}
	}
}
