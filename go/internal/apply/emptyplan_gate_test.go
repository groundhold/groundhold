package apply

import (
	"strings"
	"testing"

	"groundhold/internal/perr"
	"groundhold/internal/provider"
)

// D665. A plan with no actions is a plan with nothing to do. `apply` executed it
// anyway: it took the empty write set into `appendLease`, the ledger's validator
// refused ("event.capabilities must be a non-empty list of ids"), and the refusal
// was reported as a LEASE CONFLICT — exit 3, with the internal validator string in
// the reasons.
//
// Reached from the documented quickstart, on the fake provider, with no
// credentials: a candidate declaring an attribute the provider cannot witness
// converges once, and the second converge produces an empty plan (D249 isolates the
// unobservable attribute as unverifiable, correctly). Measured:
//
//	converge … --at T1   exit 0   APPLIED
//	converge … --at T2   exit 3   {"code":"lease-conflict",
//	                               "reasons":["STALE",
//	                                 "event.capabilities must be a non-empty list of ids"]}
//
// The published remediation for `lease-conflict` is "wait for expiry, or break the
// lease deliberately". There is no lease. The ledger is unusable for that contract
// from then on, because the same empty plan is produced every time.
func TestAnEmptyPlanIsNothingToChangeNotALeaseConflict(t *testing.T) {
	c, cand, plan := setupPlan(t)
	// The shape D249 produces on a second converge: every declared attribute either
	// matched or was isolated as unverifiable, so the sealed plan carries no actions.
	inner, _ := plan["plan"].(map[string]any)
	if inner == nil {
		t.Fatal("the sealed plan has no plan block")
	}
	inner["actions"] = []any{}
	inner["writes"] = []any{} // no action, therefore no capability is written
	res := Apply(c, cand, nil, plan, freshLedger(t), &provider.Fake{}, pfAt, false)
	code, exit, reason := res.Code, res.Exit, strings.Join(res.Reasons, " ")
	if len(res.Events) != 0 {
		t.Errorf("an empty plan appended %v to the ledger — there was nothing to "+
			"do, so there is nothing to record", res.Events)
	}
	if code == perr.LeaseConflict {
		t.Errorf("an empty plan reports %q (exit %d): %s\nA caller routing on the "+
			"code waits for a lease that does not exist, and the reason is an "+
			"internal document-validator string", code, exit, reason)
	}
	if code != perr.NothingToChange {
		t.Errorf("code = %q, want %q — there are no actions, so there is nothing to "+
			"apply and nothing went wrong", code, perr.NothingToChange)
	}
	if exit != 2 {
		t.Errorf("exit = %d, want 2 (the nothing-to-change code)", exit)
	}
	if strings.Contains(reason, "non-empty list") {
		t.Errorf("the reason leaks the ledger's internal validator text: %q", reason)
	}
}
