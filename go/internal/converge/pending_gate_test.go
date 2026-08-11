package converge

import (
	"bytes"
	"path/filepath"
	"testing"

	"groundhold/internal/ledger"
)

// writeReceipt drives a create receipt on capability `cap` to `final` (pending →
// final) into an ndjson ledger at path, the way apply would.
func writeReceipt(t *testing.T, path, cap, final string) {
	t.Helper()
	w := ledger.Writer{Path: path, Led: ledger.New(), Env: "dev", Clock: 100, Actor: "test"}
	if err := w.Append("operation.receipt", []string{cap}, map[string]any{
		"operationId": "op-1", "status": "pending", "operation": "create"}, 0); err != nil {
		t.Fatalf("append pending: %v", err)
	}
	body := map[string]any{"operationId": "op-1", "status": final, "operation": "create"}
	if final == "unknown" {
		body["targetProviderId"] = "pv-r-dev-abc123"
	}
	if err := w.Append("operation.receipt", []string{cap}, body, 0); err != nil {
		t.Fatalf("append %s: %v", final, err)
	}
}

// planNothingToChange mocks the child verbs so the plan phase reports
// nothing-to-change — the shape a retire takes when the create left no binding.
func planNothingToChange(args ...string) (int, string, string) {
	switch args[0] {
	case "verify":
		return 0, `{"verdicts":[]}`, ""
	case "plan":
		return 2, `{"code":"nothing-to-change"}`, ""
	}
	return 0, "", ""
}

// D935: a retire converge over a capability whose create stayed `unknown` produces
// an empty plan (no binding to diff against), so it never enters apply and apply's
// pending-receipt guard — which iterates only action-carrying capabilities — never
// runs. Converge would then declare "converged" while the resource the receipt
// names may be live. It must refuse (ReconcileRequired) instead.
func TestConvergeRefusesConvergedWhileAReceiptIsUnknown(t *testing.T) {
	lpath := filepath.Join(t.TempDir(), "l.ndjson")
	writeReceipt(t, lpath, "r", "unknown")

	var out bytes.Buffer
	o := Options{Contract: "c", Candidate: "k", At: "2026-01-01T00:00:00Z",
		Ledger: lpath, Caps: []string{"r"}, Out: &out, Yes: true}
	o.Run = planNothingToChange

	code := Converge(o)
	if code == 0 {
		t.Fatalf("converge claimed CONVERGED (exit 0) while an unknown create receipt "+
			"was outstanding — the resource may be live and billing:\n%s", out.String())
	}
	if code != 3 {
		t.Errorf("want ReconcileRequired (exit 3), got %d:\n%s", code, out.String())
	}
}

// The negative: once the receipt concludes (succeeded), the same nothing-to-change
// plan is honestly converged.
func TestConvergeStillConvergesWhenTheReceiptConcluded(t *testing.T) {
	lpath := filepath.Join(t.TempDir(), "l.ndjson")
	writeReceipt(t, lpath, "r", "succeeded")

	var out bytes.Buffer
	o := Options{Contract: "c", Candidate: "k", At: "2026-01-01T00:00:00Z",
		Ledger: lpath, Caps: []string{"r"}, Out: &out, Yes: true}
	o.Run = planNothingToChange

	if code := Converge(o); code != 0 {
		t.Errorf("a resolved receipt still blocked converged: exit %d\n%s", code, out.String())
	}
}

// The guard is scoped to the run's capabilities: a pending receipt on some OTHER
// capability, not in this converge's scope, does not block it.
func TestPendingBlockerIsScopedToTheRunsCapabilities(t *testing.T) {
	lpath := filepath.Join(t.TempDir(), "l.ndjson")
	writeReceipt(t, lpath, "other", "unknown")

	o := Options{Ledger: lpath, Caps: []string{"r"}}
	if cap, blocked := o.pendingBlocker(); blocked {
		t.Errorf("a pending receipt on %q (out of scope) blocked a converge over [r]", cap)
	}

	o2 := Options{Ledger: lpath, Caps: []string{"other"}}
	if _, blocked := o2.pendingBlocker(); !blocked {
		t.Error("a pending receipt on an in-scope capability was not detected")
	}
}

// D939: the D935 fail-open's fourth emitter — the POST-APPLY exit-0 "applied/
// verified" path. A MIXED plan reaches it while a receipt is still unknown: one
// capability (A) carries a real action, a second (B) is retired-unbound with a
// pending `unknown` receipt that the compiler drops from the plan, so apply's
// write-set-gated guard never sees it and the plan is non-empty (the three
// whole-empty-plan guards cannot fire). Converge must still refuse, not paint
// CONVERGED while B's resource may be live.
func TestConvergeRefusesConvergedWhenAMixedPlanLeavesAReceiptUnknown(t *testing.T) {
	lpath := filepath.Join(t.TempDir(), "l.ndjson")
	writeReceipt(t, lpath, "B", "unknown")

	planCalls := 0
	run := func(args ...string) (int, string, string) {
		switch args[0] {
		case "verify":
			return 0, `{"verdicts":[]}`, ""
		case "plan":
			planCalls++
			if planCalls == 1 {
				// first plan: A carries a real action → non-empty plan → enter apply
				return 0, `{"plan":{"actions":[{"id":"a-create-A","operation":"create",` +
					`"capability":"A","risk":{"reversibility":"R1","dataLoss":"none",` +
					`"downtime":"none","securityExposure":"none","identityReplacement":false}}]}}`, ""
			}
			// post-apply convergence-check plan: nothing to change → "verified"
			return 2, `{"code":"nothing-to-change"}`, ""
		case "forecast":
			return 0, `{"forecast":{"rollup":{}}}`, ""
		case "apply":
			return 0, `{"status":"applied","outcomes":[]}`, ""
		case "observe":
			return 0, `{}`, ""
		}
		return 0, "", ""
	}
	var out bytes.Buffer
	o := Options{Contract: "c", Candidate: "k", At: "2026-01-01T00:00:00Z",
		Ledger: lpath, Caps: []string{"A", "B"}, Out: &out, Yes: true}
	o.Run = run

	code := Converge(o)
	if code == 0 {
		t.Fatalf("converge reported exit 0 (CONVERGED) after a mixed plan while capability B's "+
			"unknown receipt was outstanding — B's resource may be live:\n%s", out.String())
	}
	if code != 3 {
		t.Errorf("want reconcile-required exit 3, got %d\n%s", code, out.String())
	}
}
