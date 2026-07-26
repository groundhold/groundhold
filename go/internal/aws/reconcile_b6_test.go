package aws

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestReconcileS3_TaggedBucketSucceeds: a pending bucket create whose bucket carries our
// ownership tags at the deterministic name concludes succeeded with the recomputed pid.
// The name is recomputed from (account, environment, capability, generation) exactly as
// create derived it — this works on a receipt that never carried a providerID.
func TestReconcileS3_TaggedBucketSucceeds(t *testing.T) {
	srv := s3Server(t, 200, "")
	defer srv.Close()
	d := s3TestDriver(t, srv)
	// create first so the bucket is tagged (the fake tracks tag state).
	if r := d.createS3("000000000000", "prod", "assets", s3Attrs(), nil, 1); r.Status != "succeeded" {
		t.Fatalf("setup create must succeed, got %+v", r)
	}

	receipt := map[string]any{"target": "aws.s3/x", "operation": "create", "generation": 1}
	res := d.Reconcile("assets", "prod", receipt)
	if res.Status != "succeeded" {
		t.Fatalf("an owned bucket must reconcile succeeded, got %+v", res)
	}
	want := s3ProviderID("eu-central-1", BucketName("000000000000", "prod", "assets", 1))
	if res.ProviderID != want {
		t.Fatalf("providerId = %q, want the recomputed bucket pid %q", res.ProviderID, want)
	}
}

// TestReconcileS3_AbsentBucketFails: a readable read with no owned tags (no create ever
// tagged the bucket) means the create did not land as ours -> failed (re-plan recreates).
func TestReconcileS3_AbsentBucketFails(t *testing.T) {
	srv := s3Server(t, 200, "") // fresh server: GET tagging -> 404 NoSuchTagSet (untagged)
	defer srv.Close()
	d := s3TestDriver(t, srv)
	receipt := map[string]any{"target": "aws.s3/x", "operation": "create", "generation": 1}
	if res := d.Reconcile("assets", "prod", receipt); res.Status != "failed" {
		t.Fatalf("a readable no-owned-tags answer must reconcile failed, got %+v", res)
	}
}

// TestReconcileEBS_OwnedScheduleSucceeds: a pending schedule create whose schedule is
// present and carries our Description marker concludes succeeded with the recomputed pid.
func TestReconcileEBS_OwnedScheduleSucceeds(t *testing.T) {
	srv := ebsServer(t, "nightly", "ENABLED")
	defer srv.Close()
	d := ebsDriver(t, srv)

	receipt := map[string]any{"target": "aws.eventbridgescheduler/x", "operation": "create", "generation": 1}
	res := d.Reconcile("nightly", "prod", receipt)
	if res.Status != "succeeded" {
		t.Fatalf("an owned schedule must reconcile succeeded, got %+v", res)
	}
	if res.ProviderID != ebsProviderID("eu-central-1", EBSName("prod", "nightly", 1)) {
		t.Fatalf("providerId = %q, want the recomputed schedule pid", res.ProviderID)
	}
}

// TestReconcileEBS_AbsentScheduleFails: a readable "does not exist" (GetSchedule 404)
// means the create did not land -> failed.
func TestReconcileEBS_AbsentScheduleFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"__type":"ResourceNotFoundException","message":"no schedule"}`, http.StatusNotFound)
	}))
	defer srv.Close()
	d := ebsDriver(t, srv)
	receipt := map[string]any{"target": "aws.eventbridgescheduler/x", "operation": "create", "generation": 1}
	if res := d.Reconcile("nightly", "prod", receipt); res.Status != "failed" {
		t.Fatalf("an absent schedule must reconcile failed, got %+v", res)
	}
}

// TestReconcileChangefeed_OwnedRuleWithTargetSucceeds: the rule region rides in the
// recorded providerId (it is derived from the feed.target ARN, not the capability). An
// owned rule WITH a target concludes succeeded; a missing recorded pid refuses honestly.
func TestReconcileChangefeed_OwnedRuleWithTargetSucceeds(t *testing.T) {
	f := newCFFake()
	rule := CFRuleName("prod", "changes", 1)
	f.rule = &cfRuleDoc{Name: rule, State: "ENABLED", Description: awsOwnerMarker("changes", "prod")}
	f.targets = []cfTarget{{Id: "t0", Arn: "arn:aws:sqs:eu-central-1:000000000000:infra-changes"}}
	srv := f.server(t)
	defer srv.Close()
	d := chfDriver(t, srv)

	pid := changefeedProviderID("eu-central-1", rule)
	receipt := map[string]any{"target": "aws.changefeed/x", "operation": "create",
		"generation": 1, "targetProviderId": pid}
	if res := d.Reconcile("changes", "prod", receipt); res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("an owned rule with a target must reconcile succeeded WITH the pid, got %+v", res)
	}

	// no recorded providerId -> the region is unrecoverable -> honest unknown.
	bare := map[string]any{"target": "aws.changefeed/x", "operation": "create", "generation": 1}
	if res := d.Reconcile("changes", "prod", bare); res.Status != "unknown" {
		t.Fatalf("a changefeed receipt with no recorded providerId must reconcile unknown, got %+v", res)
	}
}

// TestReconcileChangefeed_AbsentRuleFails: a readable DescribeRule "not found" means the
// create did not land -> failed.
func TestReconcileChangefeed_AbsentRuleFails(t *testing.T) {
	f := newCFFake() // no rule seeded
	srv := f.server(t)
	defer srv.Close()
	d := chfDriver(t, srv)
	pid := changefeedProviderID("eu-central-1", CFRuleName("prod", "changes", 1))
	receipt := map[string]any{"target": "aws.changefeed/x", "operation": "create",
		"generation": 1, "targetProviderId": pid}
	if res := d.Reconcile("changes", "prod", receipt); res.Status != "failed" {
		t.Fatalf("an absent rule must reconcile failed, got %+v", res)
	}
}

// TestReconcileSESSending_OwnedIdentitySucceeds: the sending domain rides in the recorded
// providerId (it is an operand). A found, owned (tagged) identity concludes succeeded
// (DKIM verification is async — the create does not block on it).
func TestReconcileSESSending_OwnedIdentitySucceeds(t *testing.T) {
	f := newFakeSES()
	f.identityExists = true // an identity already stands, carrying our tags
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesDriver(t, srv)

	pid := sesSendingProviderID(sesRegion, sesDomain)
	receipt := map[string]any{"target": "aws.ses-sending/x", "operation": "create",
		"generation": 1, "targetProviderId": pid}
	if res := d.Reconcile(sesCap, "prod", receipt); res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("an owned identity must reconcile succeeded WITH the pid, got %+v", res)
	}

	// no recorded providerId -> the domain is unrecoverable -> honest unknown.
	bare := map[string]any{"target": "aws.ses-sending/x", "operation": "create", "generation": 1}
	if res := d.Reconcile(sesCap, "prod", bare); res.Status != "unknown" {
		t.Fatalf("a ses-sending receipt with no recorded providerId must reconcile unknown, got %+v", res)
	}
}

// TestReconcileSESSending_AbsentIdentityFails: a readable GetEmailIdentity 404 means the
// create did not land -> failed.
func TestReconcileSESSending_AbsentIdentityFails(t *testing.T) {
	f := newFakeSES() // identityExists = false
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesDriver(t, srv)
	pid := sesSendingProviderID(sesRegion, sesDomain)
	receipt := map[string]any{"target": "aws.ses-sending/x", "operation": "create",
		"generation": 1, "targetProviderId": pid}
	if res := d.Reconcile(sesCap, "prod", receipt); res.Status != "failed" {
		t.Fatalf("an absent identity must reconcile failed, got %+v", res)
	}
}

// TestReconcileSESInbound_ActiveRuleSucceeds: ownership is the deterministic NAME carried
// by the recorded providerId (there are no tags). A present rule whose rule set is the
// ACTIVE one concludes succeeded; an inactive set is a half-built pipeline -> unknown.
func TestReconcileSESInbound_ActiveRuleSucceeds(t *testing.T) {
	f := newFakeSESInb()
	f.ruleSetExists, f.ruleExists = true, true
	f.active = sesInbRuleSet // our set is the active one
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesInbDriver(t, srv)

	pid := sesInboundProviderID(sesInbRegion, sesInbRuleSet, sesInbRuleNm)
	receipt := map[string]any{"target": "aws.ses-inbound/x", "operation": "create",
		"generation": 1, "targetProviderId": pid}
	if res := d.Reconcile("capability.email.inbound", "prod", receipt); res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("a present rule in the active set must reconcile succeeded WITH the pid, got %+v", res)
	}

	// rule present but the set is NOT active -> a half-built pipeline -> unknown.
	f.active = ""
	if res := d.Reconcile("capability.email.inbound", "prod", receipt); res.Status != "unknown" {
		t.Fatalf("an inactive rule set must keep the receipt unknown, got %+v", res)
	}
}

// TestReconcileSESInbound_AbsentRuleFails: a readable DescribeReceiptRule "does not
// exist" means the create did not land -> failed.
func TestReconcileSESInbound_AbsentRuleFails(t *testing.T) {
	f := newFakeSESInb() // ruleExists = false
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesInbDriver(t, srv)
	pid := sesInboundProviderID(sesInbRegion, sesInbRuleSet, sesInbRuleNm)
	receipt := map[string]any{"target": "aws.ses-inbound/x", "operation": "create",
		"generation": 1, "targetProviderId": pid}
	if res := d.Reconcile("capability.email.inbound", "prod", receipt); res.Status != "failed" {
		t.Fatalf("an absent rule must reconcile failed, got %+v", res)
	}
}
