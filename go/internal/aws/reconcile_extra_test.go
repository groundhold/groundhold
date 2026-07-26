package aws

import (
	"strings"
	"testing"
)

// TestReconcileEKS_ActiveClusterAndNodegroup: a pending EKS create whose cluster AND
// managed node group are live-ACTIVE and carry our ownership tags concludes succeeded
// with the recomputed pid — the async path Acme hit (create returned unknown without
// waiting to ACTIVE, so resume must conclude it). The name is recomputed from
// (environment, capability, generation) exactly as create derived it, so this works on
// a receipt that never carried a providerID.
func TestReconcileEKS_ActiveClusterAndNodegroup(t *testing.T) {
	f := newFakeEKS()
	f.clusterExists, f.ngExists = true, true
	f.clusterStatus, f.ngStatus = "ACTIVE", "ACTIVE"
	f.tags = map[string]string{
		"groundhold-capability":  sanitizeTag(eksCap),
		"groundhold-environment": sanitizeTag("prod"),
	}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksDriver(t, srv)

	receipt := map[string]any{"target": "aws.eks/x", "operation": "create", "generation": 1}
	res := d.Reconcile(eksCap, "prod", receipt)
	if res.Status != "succeeded" {
		t.Fatalf("ACTIVE owned cluster+nodegroup must reconcile succeeded, got %+v", res)
	}
	if res.ProviderID != eksProviderID("eu-central-1", eksTestName) {
		t.Fatalf("providerId = %q, want the recomputed cluster pid", res.ProviderID)
	}

	// node group still CREATING -> the create is not done -> unknown (stay pending).
	f.ngStatus = "CREATING"
	if r := d.Reconcile(eksCap, "prod", receipt); r.Status != "unknown" {
		t.Fatalf("a still-creating node group must keep the receipt unknown, got %+v", r)
	}

	// cluster absent -> the create did not land -> failed (re-plan recreates).
	f.clusterExists = false
	if r := d.Reconcile(eksCap, "prod", receipt); r.Status != "failed" {
		t.Fatalf("an absent cluster must reconcile failed, got %+v", r)
	}

	// a foreign cluster (no ownership tags) is NOT attributed to our create.
	f.clusterExists = true
	f.tags = map[string]string{}
	if r := d.Reconcile(eksCap, "prod", receipt); r.Status != "unknown" {
		t.Fatalf("a cluster without our tags must not be claimed, got %+v", r)
	}
}

// TestReconcileEKS_EmptyRegion: the honest-refusal guard (D219 sibling) applies to
// every wired service — a region-less driver names the missing region rather than
// failing opaque.
func TestReconcileEKS_EmptyRegion(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	d := NewDriver("")
	r := d.Reconcile(eksCap, "prod", map[string]any{"target": "aws.eks/x", "generation": 1})
	if r.Status != "unknown" || !strings.Contains(r.Reason, "region") {
		t.Fatalf("region-less eks reconcile must name the missing region, got %+v", r)
	}
}

// TestReconcileElastiCache_Available: a pending Redis replication-group create whose
// group is live-"available" concludes succeeded with the recomputed pid. The id is a
// deterministic function of account+env+capability+generation, so reconcile recomputes
// it and reads DescribeReplicationGroups directly.
func TestReconcileElastiCache_Available(t *testing.T) {
	srv := ecServer(t, "sessions", "true", "true", "enabled", "")
	defer srv.Close()
	d := ecDriver(t, srv) // d.Account = 000000000000

	receipt := map[string]any{"target": "aws.elasticache/x", "operation": "create", "generation": 1}
	res := d.Reconcile("sessions", "prod", receipt)
	if res.Status != "succeeded" {
		t.Fatalf("an available replication group must reconcile succeeded, got %+v", res)
	}
	wantID := ecacheID("000000000000", "prod", "sessions", 1)
	if res.ProviderID != ecacheProviderID("eu-central-1", "000000000000", wantID) {
		t.Fatalf("providerId = %q, want the recomputed replication-group pid", res.ProviderID)
	}
}

// TestReconcileElastiCache_ForeignTagsNotClaimed: an available replication group that
// sits at our recomputed id but carries SOMEONE ELSE's tags must NOT be attributed to
// our create (the create's own collision branch returns failed on a tag mismatch).
// Reconcile refuses to conclude succeeded — it returns unknown rather than binding a
// foreign database into the ledger.
func TestReconcileElastiCache_ForeignTagsNotClaimed(t *testing.T) {
	srv := ecServer(t, "someone-elses-cap", "true", "true", "enabled", "") // foreign capability tag
	defer srv.Close()
	d := ecDriver(t, srv)

	receipt := map[string]any{"target": "aws.elasticache/x", "operation": "create", "generation": 1}
	res := d.Reconcile("sessions", "prod", receipt)
	if res.Status != "unknown" {
		t.Fatalf("a foreign-owned group must NOT be claimed as succeeded, got %+v", res)
	}
}
