package aws

import (
	"strings"
	"testing"
)

// BATCH 7 reconcile: server-assigned ids WITH a list wrapper + ownership tags. Each
// service pins (a) a live listed/resolvable resource with OUR tags -> succeeded with
// the right server-id providerId, and (b) one negative (a readable, complete list with
// no owned match -> failed, or an unreadable read -> unknown). Every test drives the
// public Reconcile dispatch, so the switch wiring is exercised too.

// ---- route53 (global; tier-1 pid path; list unreadable on this fake) -------

func TestReconcileRoute53_ByProviderIDSucceeds(t *testing.T) {
	srv := r53Server(t, "apex", "false")
	defer srv.Close()
	d := r53Driver(t, srv)

	res := d.Reconcile("apex", "prod", map[string]any{
		"target": "aws.route53/x", "operation": "create", "generation": 1,
		"targetProviderId": "r53:Z123ABC"})
	if res.Status != "succeeded" || res.ProviderID != "r53:Z123ABC" {
		t.Fatalf("a live owned zone at our pid must conclude succeeded with the id, got %+v", res)
	}
}

func TestReconcileRoute53_NoListIsUnknown(t *testing.T) {
	// no pid -> list scan; this fake serves no ListHostedZones, so the list is
	// unreadable -> unknown (never a fabricated "failed").
	srv := r53Server(t, "apex", "false")
	defer srv.Close()
	d := r53Driver(t, srv)

	res := d.Reconcile("apex", "prod", map[string]any{
		"target": "aws.route53/x", "operation": "create", "generation": 1})
	if res.Status != "unknown" {
		t.Fatalf("an unreadable hosted-zone list must be unknown, got %+v", res)
	}
}

// ---- acm (region-scoped; list scan via ListCertificates) -------------------

func TestReconcileACM_ListScanSucceeds(t *testing.T) {
	srv := acmServer(t, "web", "app.example.com", "ELIGIBLE")
	defer srv.Close()
	d := acmDriver(t, srv)

	res := d.Reconcile("web", "prod", map[string]any{
		"target": "aws.acm/x", "operation": "create", "generation": 1})
	if res.Status != "succeeded" {
		t.Fatalf("a listed certificate carrying our tags must conclude succeeded, got %+v", res)
	}
	want := acmProviderID("us-east-1", "000000000000", "12345678-1234-1234-1234-123456789012")
	if res.ProviderID != want {
		t.Fatalf("providerId = %q, want the certificate's server id %q", res.ProviderID, want)
	}
}

func TestReconcileACM_NoOwnedMatchFails(t *testing.T) {
	srv := acmServer(t, "someone-else", "app.example.com", "ELIGIBLE")
	defer srv.Close()
	d := acmDriver(t, srv)

	res := d.Reconcile("web", "prod", map[string]any{
		"target": "aws.acm/x", "operation": "create", "generation": 1})
	if res.Status != "failed" {
		t.Fatalf("a complete list with no owned certificate must conclude failed, got %+v", res)
	}
}

// ---- efs (region-scoped; async ready-state; list scan) ---------------------

func TestReconcileEFS_ListScanSucceeds(t *testing.T) {
	srv := efsServer(t, "shared", "", "")
	defer srv.Close()
	d := efsDriver(t, srv)

	res := d.Reconcile("shared", "prod", map[string]any{
		"target": "aws.efs/x", "operation": "create", "generation": 1})
	if res.Status != "succeeded" {
		t.Fatalf("an available owned file system must conclude succeeded, got %+v", res)
	}
	want := efsProviderID("eu-central-1", "000000000000", "fs-0123456789abcdef0")
	if res.ProviderID != want {
		t.Fatalf("providerId = %q, want %q", res.ProviderID, want)
	}
}

func TestReconcileEFS_NoOwnedMatchFails(t *testing.T) {
	srv := efsServer(t, "someone-else", "", "")
	defer srv.Close()
	d := efsDriver(t, srv)

	res := d.Reconcile("shared", "prod", map[string]any{
		"target": "aws.efs/x", "operation": "create", "generation": 1})
	if res.Status != "failed" {
		t.Fatalf("a complete list with no owned file system must conclude failed, got %+v", res)
	}
}

// ---- eks-podidentity (deterministic pid; authoritative conclude) -----------

func TestReconcileEKSPodIdentity_ByProviderIDSucceeds(t *testing.T) {
	f := newFakePodID()
	f.exists = true
	f.tags = map[string]string{
		"groundhold-capability": sanitizeTag(eksPodIDCap), "groundhold-environment": sanitizeTag("prod")}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)

	res := d.Reconcile(eksPodIDCap, "prod", map[string]any{
		"target": "aws.eks-podidentity/x", "operation": "create", "generation": 1,
		"targetProviderId": podIDPID()})
	if res.Status != "succeeded" || res.ProviderID != podIDPID() {
		t.Fatalf("an owned association at our pid must conclude succeeded with the pid, got %+v", res)
	}
}

func TestReconcileEKSPodIdentity_ForeignFails(t *testing.T) {
	f := newFakePodID()
	f.exists = true
	f.tags = map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)

	res := d.Reconcile(eksPodIDCap, "prod", map[string]any{
		"target": "aws.eks-podidentity/x", "operation": "create", "generation": 1,
		"targetProviderId": podIDPID()})
	if res.Status != "failed" {
		t.Fatalf("a foreign association at our identity must conclude failed, got %+v", res)
	}
}

// ---- backupplan (region-scoped; tier-1 pid path) ---------------------------

func TestReconcileBackupPlan_ByProviderIDSucceeds(t *testing.T) {
	srv := bkpServer(t, "archive")
	defer srv.Close()
	d := bkpDriver(t, srv)

	res := d.Reconcile("archive", "prod", map[string]any{
		"target": "aws.backupplan/x", "operation": "create", "generation": 1,
		"targetProviderId": "backupplan:eu-central-1:plan-abc"})
	if res.Status != "succeeded" || res.ProviderID != "backupplan:eu-central-1:plan-abc" {
		t.Fatalf("a live owned plan at our pid must conclude succeeded with the id, got %+v", res)
	}
}

func TestReconcileBackupPlan_NoPlansFails(t *testing.T) {
	// no pid -> list scan; this fake serves no BackupPlansList, so the (readable,
	// complete) list has no owned match -> failed.
	srv := bkpServer(t, "archive")
	defer srv.Close()
	d := bkpDriver(t, srv)

	res := d.Reconcile("archive", "prod", map[string]any{
		"target": "aws.backupplan/x", "operation": "create", "generation": 1})
	if res.Status != "failed" {
		t.Fatalf("a complete plan list with no owned match must conclude failed, got %+v", res)
	}
}

// ---- guardduty (region-scoped; singleton detector; list scan) --------------

func TestReconcileGuardDuty_ListScanSucceeds(t *testing.T) {
	f := &fakeGuardDuty{
		detectorID: gdDetectorID, exists: true, status: "ENABLED",
		tags: map[string]string{
			"groundhold-capability": sanitizeTag(gdCap), "groundhold-environment": sanitizeTag("prod")}}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := guardDutyDriver(t, srv)

	res := d.Reconcile(gdCap, "prod", map[string]any{
		"target": "aws.guardduty/x", "operation": "create", "generation": 1})
	if res.Status != "succeeded" {
		t.Fatalf("an owned detector must conclude succeeded, got %+v", res)
	}
	if res.ProviderID != guardDutyProviderID(gdRegion, gdDetectorID) {
		t.Fatalf("providerId = %q, want the detector's server id", res.ProviderID)
	}
}

func TestReconcileGuardDuty_NoDetectorFails(t *testing.T) {
	f := &fakeGuardDuty{detectorID: gdDetectorID, exists: false, status: "ENABLED"}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := guardDutyDriver(t, srv)

	res := d.Reconcile(gdCap, "prod", map[string]any{
		"target": "aws.guardduty/x", "operation": "create", "generation": 1})
	if res.Status != "failed" {
		t.Fatalf("an empty (complete) detector list must conclude failed, got %+v", res)
	}
}

// an unwired service still fails closed to unknown (guards the switch default).
func TestReconcileBatch7_UnwiredStillUnknown(t *testing.T) {
	d := NewDriver("eu-central-1")
	if u := d.Reconcile("x", "prod", map[string]any{"target": "aws.nope/x"}); u.Status != "unknown" ||
		!strings.Contains(u.Reason, "not wired") {
		t.Fatalf("an unwired service must reconcile unknown, got %+v", u)
	}
}
