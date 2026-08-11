package aws

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// This file rounds out ses_inbound_net.go coverage: sesInbIsAlreadyExists and
// ensureSESInboundActive were both previously untested (0% each), and
// createSESInbound's repair-existing path (the "found" branch that calls
// ensureSESInboundActive) was never exercised.

// ---- sesInbIsAlreadyExists / sesInbIsNotFound: PURE status classifiers -----

func TestSesInbIsAlreadyExists(t *testing.T) {
	if !sesInbIsAlreadyExists(400, []byte(sesInbErrXML("AlreadyExists"))) {
		t.Fatal("an AlreadyExists error code must report true")
	}
	if sesInbIsAlreadyExists(400, []byte(sesInbErrXML("RuleDoesNotExist"))) {
		t.Fatal("a DoesNotExist error must not report AlreadyExists")
	}
	if sesInbIsAlreadyExists(200, nil) {
		t.Fatal("a clean 200 with no error body must not report AlreadyExists")
	}
}

func TestSesInbIsNotFound(t *testing.T) {
	if !sesInbIsNotFound(400, []byte(sesInbErrXML("RuleDoesNotExist"))) {
		t.Fatal("RuleDoesNotExist must report not-found")
	}
	if !sesInbIsNotFound(400, []byte(sesInbErrXML("RuleSetDoesNotExist"))) {
		t.Fatal("RuleSetDoesNotExist must report not-found")
	}
	if sesInbIsNotFound(400, []byte(sesInbErrXML("AlreadyExists"))) {
		t.Fatal("an AlreadyExists error must not report not-found")
	}
}

// ---- createSESInbound: the "found" repair branch (ensureSESInboundActive) --

func TestSESInbound_CreateRepairsExistingRule(t *testing.T) {
	f := newFakeSESInb()
	f.ruleSetExists, f.ruleExists = true, true
	f.scanEnabled, f.hasS3 = false, false // stale shape, to be repaired
	f.active = ""                         // not yet active
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesInbDriver(t, srv)
	attrs, impl := sesInbCandidate()

	res := d.createSESInbound(sesInbRegion, "prod", sesInbCap, attrs, impl, 1)
	if res.Status != "succeeded" {
		t.Fatalf("repairing an existing rule (ours by name) must succeed, got %+v", res)
	}
	if res.ProviderID != sesInboundProviderID(sesInbRegion, sesInbRuleSet, sesInbRuleNm) {
		t.Fatalf("repair must carry the deterministic pid, got %q", res.ProviderID)
	}
	joined := strings.Join(f.order, ",")
	if joined != "UpdateReceiptRule,SetActiveReceiptRuleSet" {
		t.Fatalf("repair order = %v, want UpdateReceiptRule then SetActiveReceiptRuleSet "+
			"(no CreateReceiptRuleSet/CreateReceiptRule for an already-existing rule)", f.order)
	}
	if !f.scanEnabled || !f.hasS3 {
		t.Fatalf("repair must re-put the desired shape (scan+sink), got scan=%v s3=%v", f.scanEnabled, f.hasS3)
	}
	if f.active != sesInbRuleSet {
		t.Fatalf("repair must (re-)activate the rule set, active=%q", f.active)
	}
}

// TestEnsureSESInboundActive_UpdateFailIsUnknown: the rule ALREADY exists, so ANY
// UpdateReceiptRule failure is unknown WITH the pid (a partial to reconcile),
// never a bare "failed" that hides the standing rule.
func TestEnsureSESInboundActive_UpdateFailIsUnknown(t *testing.T) {
	attrs, impl := sesInbCandidate()
	plan, err := BuildSESInbound("prod", sesInbCap, attrs, impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	pid := sesInboundProviderID(sesInbRegion, plan.RuleSetName, plan.RuleName)

	// A server that fails UpdateReceiptRule with a transport-shaped 500 — the
	// rule already exists, so the failure must be unknown WITH the pid, never a
	// bare "failed" that hides the standing rule.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, sesInbErrXML("InternalFailure"), http.StatusInternalServerError)
	}))
	defer srv.Close()
	d := sesInbDriver(t, srv)

	res := d.ensureSESInboundActive(sesInbRegion, pid, plan, true)
	if res.Status != "unknown" || res.ProviderID != pid {
		t.Fatalf("an UpdateReceiptRule failure on an existing rule must be unknown WITH the pid, got %+v", res)
	}
}

func TestEnsureSESInboundActive_NoActivateSucceedsWithoutSettingActive(t *testing.T) {
	f := newFakeSESInb()
	f.ruleSetExists, f.ruleExists = true, true
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesInbDriver(t, srv)
	attrs, impl := sesInbCandidate()
	plan, err := BuildSESInbound("prod", sesInbCap, attrs, impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	pid := sesInboundProviderID(sesInbRegion, plan.RuleSetName, plan.RuleName)

	res := d.ensureSESInboundActive(sesInbRegion, pid, plan, false)
	if res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("activate=false must succeed without touching activation, got %+v", res)
	}
	for _, o := range f.order {
		if o == "SetActiveReceiptRuleSet" {
			t.Fatalf("activate=false must not call SetActiveReceiptRuleSet: %v", f.order)
		}
	}
}

func sesInbRole(_ *http.Request, body []byte) certifynet.Role {
	if v, err := url.ParseQuery(string(body)); err == nil {
		a := v.Get("Action")
		if strings.HasPrefix(a, "Describe") || strings.HasPrefix(a, "List") {
			return certifynet.RoleRead
		}
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingSESInbound enrols ses-inbound in the D391 gate. The rule set and
// rule are NAME-addressed, so the existing pair is bound and repaired in place — the
// per-driver test pins the exact call order (UpdateReceiptRule, never a Create); the
// gate pins the identity and that the repair stays a repair.
func TestAdoptsExistingSESInbound(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	attrs, impl := sesInbCandidate()
	p := &certifynet.ExistingProbe{
		Name:     "aws/ses-inbound",
		Classify: sesInbRole,
		ExistingServer: func() *httptest.Server {
			f := newFakeSESInb()
			f.ruleSetExists, f.ruleExists = true, true
			f.scanEnabled, f.hasS3 = false, false // stale shape, to be repaired
			f.active = ""
			return f.handler(t, nil)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(sesInbRegion)
			d.HTTP = &http.Client{Transport: rt}
			d.SESBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.PollInterval = 0
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("ses-inbound", sesInbCap, "prod", attrs, impl, "k", 1)
		},
		PID:              sesInboundProviderID(sesInbRegion, sesInbRuleSet, sesInbRuleNm),
		AllowedMutations: 2, // UpdateReceiptRule + SetActiveReceiptRuleSet
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
