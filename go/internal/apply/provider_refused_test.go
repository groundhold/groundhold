package apply

import (
	"strings"
	"testing"

	"groundhold/internal/perr"
	"groundhold/internal/provider"
)

// perr.ProviderRefused (exit 2) is emitted on two apply-time refuse-before-mutate
// paths that were untested: (1) the driver's Validate hook rejects an action it cannot
// honor (D43), and (2) the SEALED plan's action target service disagrees with the
// candidate's declared service (D76) — a tampered plan must not re-route a candidate
// into a different builder. Both must abort BEFORE any mutation, appending nothing to
// the ledger.

// (1) driver Validate refusal.
func TestApplyRefusesWhenDriverValidateRejects(t *testing.T) {
	c, cand, plan := setupPlan(t)
	// the candidate declares service "mock"; make the fake driver reject it, so the
	// refuse-before-mutate Validate hook fails.
	fake := &provider.Fake{RefuseServices: map[string]bool{"mock": true}}
	res := Apply(c, cand, nil, plan, freshLedger(t), fake, pfAt, false)
	if res.Code != perr.ProviderRefused || res.Exit != 2 {
		t.Fatalf("expected provider-refused/2, got %s/%d (reasons=%v)", res.Code, res.Exit, res.Reasons)
	}
	if len(res.Events) != 0 {
		t.Fatalf("a driver refusal must append nothing to the ledger, got %v", res.Events)
	}
}

// (2) tampered plan re-routes the candidate's service.
func TestApplyRefusesReRoutedPlanService(t *testing.T) {
	c, cand, plan := setupPlan(t)
	// hand-edit the sealed plan so a create action's target names a DIFFERENT service
	// than the candidate declares ("mock"). serviceOf reads the segment between '.'
	// and '/', so rewriting "<prov>.mock/<cap>" to "<prov>.other/<cap>" flips it.
	if !reRouteFirstCreateService(plan, "other") {
		t.Skip("no create action with a mock-service target to re-route")
	}
	res := Apply(c, cand, nil, plan, freshLedger(t), &provider.Fake{}, pfAt, false)
	if res.Code != perr.ProviderRefused || res.Exit != 2 {
		t.Fatalf("expected provider-refused/2 for a re-routed service, got %s/%d (reasons=%v)", res.Code, res.Exit, res.Reasons)
	}
	if len(res.Events) != 0 {
		t.Fatalf("a re-route refusal must append nothing to the ledger, got %v", res.Events)
	}
}

// reRouteFirstCreateService rewrites the service segment of the first create action's
// target to newSvc. Returns false if no such action exists.
func reRouteFirstCreateService(plan map[string]any, newSvc string) bool {
	body, _ := plan["plan"].(map[string]any) // the plan body Apply reads is nested here
	actions, _ := body["actions"].([]any)
	for _, it := range actions {
		a, _ := it.(map[string]any)
		if a["operation"] != "create" {
			continue
		}
		target, _ := a["target"].(string)
		dot := strings.IndexByte(target, '.')
		slash := strings.IndexByte(target, '/')
		if dot < 0 || slash < 0 || slash < dot {
			continue
		}
		a["target"] = target[:dot+1] + newSvc + target[slash:]
		return true
	}
	return false
}
