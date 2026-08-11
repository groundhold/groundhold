package main

import (
	"bytes"
	"strings"
	"testing"

	"groundhold/internal/compiler"
	"groundhold/internal/contract"
)

// D721. A capability the compiler could not plan was carried in plan.blocked and
// never spoken by `plan`, which printed the JSON and exited 0. The no-op renderer
// named the capabilities deliberately left alone; nothing named the ones that fell
// out of the deployment. A pilot applied 24 actions for a 27-capability contract
// believing it complete.
func TestPlanSpeaksTheCapabilitiesItCouldNotPlan(t *testing.T) {
	doc := &compiler.Document{}
	doc.Plan.Actions = []compiler.Action{{Capability: "api", Operation: "update"}}
	doc.Plan.Blocked = []compiler.BlockedCapability{
		{Capability: "web", Reason: "implementation.url_auth=iam contradicts network.publicExposure: true"},
	}
	c := &contract.Contract{Capabilities: map[string]map[string]any{
		"api": {}, "web": {}, "db": {},
	}}

	var b bytes.Buffer
	renderBlocked(&b, doc, c)
	got := b.String()

	for _, want := range []string{
		"COULD NOT BE PLANNED",
		"web",
		"url_auth=iam contradicts network.publicExposure",
		"declares 3 capability(ies); this plan covers 1",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the plan does not say %q; it said:\n%s", want, got)
		}
	}
}

// A plan with nothing blocked must print nothing here — a line on the path every
// deployment runs is noise, and noise is how a real warning stops being read.
func TestNothingIsPrintedWhenEveryCapabilityWasPlanned(t *testing.T) {
	doc := &compiler.Document{}
	doc.Plan.Actions = []compiler.Action{{Capability: "api", Operation: "update"}}
	var b bytes.Buffer
	renderBlocked(&b, doc, &contract.Contract{Capabilities: map[string]map[string]any{"api": {}}})
	if b.Len() != 0 {
		t.Fatalf("a complete plan printed a blocked notice:\n%s", b.String())
	}
}

// D721: a witness capability that is not bound is blocked AND recorded in `witnessed`
// with its own reason (D177), and the conformance suite decides such a plan is a
// success. It must be spoken, but it is accounted for — so it must not turn the plan
// into a refusal. Without this distinction the fix overturns a decided case.
func TestABlockedWitnessIsSpokenButDoesNotRefuseThePlan(t *testing.T) {
	doc := &compiler.Document{}
	doc.Plan.Actions = []compiler.Action{{Capability: "repo", Operation: "create"}}
	doc.Plan.Witnessed = []compiler.WitnessRecord{
		{Capability: "gitops-root", Reason: "not-authorable-and-unbound"},
	}
	doc.Plan.Blocked = []compiler.BlockedCapability{
		{Capability: "gitops-root", Reason: "witness capability is not bound"},
	}
	var b bytes.Buffer
	unaccounted := renderBlocked(&b, doc, &contract.Contract{
		Capabilities: map[string]map[string]any{"repo": {}, "gitops-root": {}}})
	if !strings.Contains(b.String(), "gitops-root") {
		t.Errorf("a blocked witness must still be named:\n%s", b.String())
	}
	if len(unaccounted) != 0 {
		t.Fatalf("a witness recorded in `witnessed` is accounted for, so it must not "+
			"make the plan a refusal; got %v", unaccounted)
	}
}

// The reported case: blocked and named in no other channel. That one refuses.
func TestACapabilityNamedNowhereElseRefusesThePlan(t *testing.T) {
	doc := &compiler.Document{}
	doc.Plan.Actions = []compiler.Action{{Capability: "api", Operation: "update"}}
	doc.Plan.Blocked = []compiler.BlockedCapability{
		{Capability: "web", Reason: "implementation.url_auth=iam contradicts network.publicExposure: true"},
	}
	var b bytes.Buffer
	unaccounted := renderBlocked(&b, doc, &contract.Contract{
		Capabilities: map[string]map[string]any{"api": {}, "web": {}}})
	if len(unaccounted) != 1 || unaccounted[0] != "web" {
		t.Fatalf("a capability that fell out of the deployment and is named nowhere "+
			"else must make the plan a refusal, got %v", unaccounted)
	}
}
