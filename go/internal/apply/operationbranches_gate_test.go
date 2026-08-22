package apply

import (
	"sort"
	"testing"

	"groundhold/internal/perr"
	"groundhold/internal/plan"
	"groundhold/internal/provider"
)

// D1177 pays a debt D1174 recorded in writing rather than leaving to be discovered.
//
// D1174 classified the plan's operations into what the executor APPLIES
// (`apply.SupportedOperations`) and what merely LOADS (`plan.LoadOnlyOperations`), and
// gated the classification two ways: the two sets must partition `plan.Operations`, and
// every declared-supported operation must have a `case` branch in this file. The second
// check reads the switch as TEXT. Its own comment says so and names the gap: D317's
// lesson is that scraping an implementation is not the same as asking it, and asking
// would mean applying a one-action plan per operation and looking at what comes back.
//
// It turned out the harness already existed — `setupPlan` compiles a real plan and
// `Apply` runs it against the fake provider, both in this package — so the debt was
// smaller than the note claimed. Recording it was still right: the note is what made
// the next pass look, and an unpaid debt that is written down costs a search, while one
// that is not costs a defect.
//
// The precedent for the shape is `aws/updateforeign_gate_test.go`, which does not trust
// its own register either: it calls `Update` and asserts the driver really refuses.
//
// What this catches that the text scan cannot: a `case` branch that exists and falls
// through, a branch guarded by a condition that is never true, or a refusal routed to
// the wrong error code. None of those change the text the scan reads.
func TestTheExecutorReallyAppliesWhatItDeclares(t *testing.T) {
	// The vacuity floor first. If the two registers were empty this would assert
	// nothing at all, cheerfully (D328).
	if len(SupportedOperations) == 0 || len(plan.LoadOnlyOperations) == 0 {
		t.Fatal("one of the operation registers is EMPTY — this gate would be comparing " +
			"nothing against nothing")
	}

	setOperation := func(t *testing.T, planDoc map[string]any, op string) {
		t.Helper()
		body, _ := planDoc["plan"].(map[string]any)
		acts, _ := body["actions"].([]any)
		if len(acts) == 0 {
			t.Fatal("the compiled fixture has no actions — nothing to re-aim, and this " +
				"test would pass having exercised no branch")
		}
		for _, it := range acts {
			a, _ := it.(map[string]any)
			a["operation"] = op
		}
	}

	// Iterate the ACCEPTED set, not the two registers. The first draft walked
	// `LoadOnlyOperations` and `SupportedOperations`, and the meter killed it with a
	// mutant that simply deletes `replace` from the load-only register: the operation
	// is then in neither list, this test never generates a case for it, and a plan
	// carrying it walks into the executor unexamined. Walking `plan.Operations`
	// instead means every operation the LOADER admits gets asked, whatever the
	// registers happen to say — which is the property that actually matters.
	//
	// It is also rule (p) in its own right: I verified that mutant by hand with a
	// TWO-part edit (drop it from load-only AND add it to supported) and it died. The
	// meter applies one part. A mutant checked a different way than the meter checks
	// it is not checked.
	accepted := make([]string, 0, len(plan.Operations))
	for op := range plan.Operations {
		accepted = append(accepted, op)
	}
	sort.Strings(accepted)
	if len(accepted) == 0 {
		t.Fatal("the loader accepts NO operations — this gate would generate no cases")
	}

	var loadOnly []string
	for _, op := range accepted {
		if !SupportedOperations[op] {
			loadOnly = append(loadOnly, op)
		}
	}

	// Every operation the executor does NOT apply must come back as
	// `unsupported-operation`, before the lease and before any mutation. This is the
	// half that matters: a plan our loader accepts and our executor silently ignores
	// would report success having done nothing.
	for _, op := range loadOnly {
		t.Run("not-applied/"+op, func(t *testing.T) {
			c, cand, planDoc := setupPlan(t)
			setOperation(t, planDoc, op)
			res := Apply(c, cand, nil, planDoc, freshLedger(t), &provider.Fake{}, pfAt, false)
			if res.Code != perr.UnsupportedOperation {
				t.Errorf("the loader ACCEPTS %q, the executor does not declare it "+
					"supported, and it answered %q (exit %d) rather than "+
					"unsupported-operation. Either it applies it after all — move it "+
					"into SupportedOperations and say so in spec/sealed-plan.md — or "+
					"it is doing something to a plan it is documented to turn away.",
					op, res.Code, res.Exit)
			}
		})
	}

	// The other direction, and the reason this is not just the same check twice: an
	// operation DECLARED supported must not be refused as unsupported. A branch that
	// exists in the text but falls through to the default would pass the scan in
	// planregistry_gate_test.go and fail here.
	var supported []string
	for _, op := range accepted {
		if SupportedOperations[op] {
			supported = append(supported, op)
		}
	}

	for _, op := range supported {
		t.Run("supported/"+op, func(t *testing.T) {
			c, cand, planDoc := setupPlan(t)
			setOperation(t, planDoc, op)
			res := Apply(c, cand, nil, planDoc, freshLedger(t), &provider.Fake{}, pfAt, false)
			// Any other refusal is fine and expected — re-aiming a create at `delete`
			// produces a plan whose pins are wrong, and the executor is right to say
			// so. The one answer that must NOT come back is "I do not know this
			// operation", from an operation we publish as supported.
			if res.Code == perr.UnsupportedOperation {
				t.Errorf("%q is declared SUPPORTED and the executor answered "+
					"unsupported-operation. The refusal message is derived from that "+
					"same set, so a user is told the operation is supported and then "+
					"told it is not.", op)
			}
		})
	}
}
