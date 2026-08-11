package main

import (
	"bytes"
	"strings"
	"testing"

	"groundhold/internal/compiler"
)

// D531, from the field: a new capability was added to the contract and `plan`'s
// human summary printed 21 lines of "no-op (bound, observed==declared)" and
// nothing else. The capability that CREATES A RESOURCE did not appear at all —
// not as create, not as unbound, not as genesis. Reading only the summary (and it
// is the last thing on screen, so that is natural) the conclusion was "the plan
// does nothing", while the JSON carried `a-create-s3-stan`.
//
// Their sentence names the defect exactly: the summary omits the category that
// CHANGES THE WORLD, so attention is distributed inversely to risk. A bound,
// converged capability is harmless by definition; an unbound one is a new
// resource, a new cost and a new surface.
func TestPlanSummaryNamesTheActionsNotJustTheNoOps(t *testing.T) {
	doc := &compiler.Document{}
	doc.Plan.Actions = []compiler.Action{
		{ID: "a-create-s3-stan", Capability: "s3-stan", Operation: "create", Target: "aws.s3/s3-stan"},
	}
	doc.Plan.NoOp = []compiler.NoOpCapability{
		{Capability: "api", Reason: "bound, observed==declared"},
		{Capability: "web", Reason: "bound, observed==declared"},
	}

	var b bytes.Buffer
	renderNoOp(&b, doc)
	out := b.String()

	if !strings.Contains(out, "s3-stan") {
		t.Fatalf("the summary never names the capability that creates a resource:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "create") {
		t.Errorf("the summary does not say a resource will be CREATED:\n%s", out)
	}
	// The no-ops still belong there — they answer "why did nothing happen to these".
	if !strings.Contains(out, "api: no-op") {
		t.Errorf("the no-op lines were lost:\n%s", out)
	}
	// What changes the world must not be buried below what does not.
	if strings.Index(out, "s3-stan") > strings.Index(out, "api: no-op") {
		t.Errorf("the create is printed BELOW the no-ops; the last thing on screen "+
			"should be the thing that changes the world:\n%s", out)
	}
}

// A plan with no actions must stay exactly as it was — silence about actions is
// correct when there are none, and inventing a line would be noise on the
// steady-state path every deployment runs.
func TestPlanSummaryUnchangedWhenNothingHappens(t *testing.T) {
	doc := &compiler.Document{}
	doc.Plan.NoOp = []compiler.NoOpCapability{
		{Capability: "api", Reason: "bound, observed==declared"},
	}
	var b bytes.Buffer
	renderNoOp(&b, doc)
	if got := b.String(); got != "api: no-op (bound, observed==declared)\n" {
		t.Errorf("a plan with no actions changed its summary: %q", got)
	}
}
