package apply

import (
	"strings"
	"testing"

	"groundhold/internal/verify"

	"groundhold/internal/cloudfake"
	"groundhold/internal/provider"
)

// D325: invariant 1 was enforced only if the PLAN asked for it.
//
// "unknown or unverifiable on a hard constraint blocks execution — no exceptions,
// no flags to bypass it" is the project's first rule. apply re-verifies the
// candidate itself and holds the report — but it only consults `report.Executable`
// inside the loop over the plan's `preconditions`, when it meets one of type
// report-executable. Strip that entry and the check never runs.
//
// apply defends against hand-authored plans everywhere else and says so out loud
// (D47: "autonomy is an UNCONDITIONAL executor gate — a hand-authored plan must
// not bypass compiler policy"; D48 repeats it for replacement consent). Invariant
// 1 was the one gate that WAS bypassable that way: the plan carries the
// instruction to check it.
func TestApplyRefusesAPlanThatOmitsTheExecutablePrecondition(t *testing.T) {
	c, cand, plan := setupPlan(t)

	// a hand-authored plan that simply does not ask to be checked. The
	// preconditions live INSIDE the plan body, which is what apply reads.
	inner, _ := plan["plan"].(map[string]any)
	if inner == nil {
		t.Fatal("plan document has no inner plan body")
	}
	inner["preconditions"] = []any{}

	lp := freshLedger(t)
	w := cloudfake.New(0)
	res := Apply(c, cand, nil, plan, lp, &worldFake{Fake: &provider.Fake{}, w: w, record: true},
		pfAt, false)

	if res.Status == "applied" {
		t.Fatalf("a plan with no report-executable precondition APPLIED — invariant 1 "+
			"is enforced only when the plan asks for it, so a hand-authored plan "+
			"opts out of the project's first rule.\ncreated: %v", w.CreatedIDs())
	}
	if !strings.Contains(strings.Join(res.Reasons, " "), "report-executable") {
		t.Errorf("the refusal must name the missing precondition; got %v", res.Reasons)
	}
}

// The same hole from the other side: a plan may not swap the precondition for a
// different one and thereby skip the check.
func TestApplyRefusesAPlanWithOnlyOtherPreconditions(t *testing.T) {
	c, cand, plan := setupPlan(t)
	inner, _ := plan["plan"].(map[string]any)
	if inner == nil {
		t.Fatal("plan document has no inner plan body")
	}
	inner["preconditions"] = []any{map[string]any{"type": "no-assumed-basis"}}

	lp := freshLedger(t)
	w := cloudfake.New(0)
	res := Apply(c, cand, nil, plan, lp, &worldFake{Fake: &provider.Fake{}, w: w, record: true},
		pfAt, false)
	if res.Status == "applied" {
		t.Fatalf("a plan carrying only OTHER preconditions applied — invariant 1 must "+
			"not be substitutable.\ncreated: %v", w.CreatedIDs())
	}
}

// And the compiler must keep emitting it, so honest plans always carry it: if this
// ever stops being true, every real plan starts refusing and the cause is here.
func TestCompiledPlansCarryTheExecutablePrecondition(t *testing.T) {
	_, _, plan := setupPlan(t)
	inner, _ := plan["plan"].(map[string]any)
	pre, _ := inner["preconditions"].([]any)
	found := false
	for _, it := range pre {
		if m, ok := it.(map[string]any); ok {
			if s, _ := m["type"].(string); s == "report-executable" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("the compiler stopped emitting report-executable — every honest plan "+
			"must carry it (D195: mandatory, the thesis); got %v", pre)
	}
}

// The claim made airtight: a NON-EXECUTABLE candidate applied through a plan that
// omits the precondition. The two tests above show the check does not run; this
// shows what that buys an attacker — a hard constraint that verify could not
// prove, executed anyway.
//
// The attack needs no crypto: the read-set carries the candidate's own hash, so a
// hand-authored plan for a candidate you supply matches by construction. Building
// a plan document is the whole exploit.
func TestNonExecutableCandidateCannotApplyViaAHandAuthoredPlan(t *testing.T) {
	c, cand, plan := setupPlan(t)

	// a candidate whose hard constraint verify cannot prove: the contract demands
	// a value the candidate does not declare at all -> unknown -> not executable.
	delete(cand.Capabilities["db"], "location.region")
	rep, err := verify.Verify(c, cand, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Executable {
		t.Fatalf("fixture is wrong — the candidate must NOT be executable: %+v", rep.Summary)
	}

	inner, _ := plan["plan"].(map[string]any)
	// the hand-authored part: match the read-set to the candidate we supply, and
	// simply do not ask to be checked.
	reads, _ := inner["reads"].(map[string]any)
	reads["candidateHash"] = rep.CandidateHash
	reads["contractHash"] = rep.ContractHash
	inner["preconditions"] = []any{}

	lp := freshLedger(t)
	w := cloudfake.New(0)
	res := Apply(c, cand, nil, plan, lp, &worldFake{Fake: &provider.Fake{}, w: w, record: true},
		pfAt, false)
	if res.Status == "applied" {
		t.Fatalf("a candidate verify declared NOT EXECUTABLE was applied — invariant 1 "+
			"(\"unknown on a hard constraint blocks execution, no exceptions\") was "+
			"bypassed by omitting one line from the plan.\ncreated: %v\nblocking: %v",
			w.CreatedIDs(), rep.BlockingReasons)
	}
}
