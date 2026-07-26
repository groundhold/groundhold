package converge

import (
	"bytes"
	"strings"
	"testing"
)

// Part C — a STALE/reconcile refusal must NAME the remedy. When a prior run was
// timed out or killed, the ledger holds an in-flight receipt and the next apply
// refuses reconcile-required (exit 3, STALE). converge must surface the exact
// `groundhold resume ... --at <clock>` pointer the apply child already computed
// (D230), instead of a dead end (Acme field report #4).
func TestConvergeSurfacesResumeHintOnStaleApply(t *testing.T) {
	t.Chdir(t.TempDir()) // converge writes .groundhold/converge-plan.yaml under cwd

	run := func(args ...string) (int, string, string) {
		switch args[0] {
		case "verify":
			return 0, `{"executable":true,"verdicts":[]}`, ""
		case "plan":
			return 0, `{"plan":{"actions":[{"id":"a-update-db","operation":"update",` +
				`"capability":"db","risk":{"dataLoss":"none"}}]}}`, ""
		case "forecast":
			return 0, `{"forecast":{"rollup":{}}}`, ""
		case "apply":
			// a prior timeout/kill left an in-flight receipt: apply refuses
			// reconcile-required (exit 3) and carries the resume `next` (D230).
			return 3, `{"status":"refused","code":"reconcile-required",` +
				`"reasons":["in-flight operations on db must be reconciled first (D29)"],` +
				`"next":{"kind":"command",` +
				`"command":"groundhold resume c --ledger l --at 2026-01-01T00:00:00Z",` +
				`"note":"resume asks the provider what actually happened, then re-run",` +
				`"runnable":true}}`, ""
		}
		return 0, "", ""
	}
	var out bytes.Buffer
	o := Options{Contract: "c", Candidate: "k", Ledger: "l",
		At: "2026-01-01T00:00:00Z", Run: run, Out: &out, Yes: true}

	exit := Converge(o)
	got := out.String()

	if exit != 3 {
		t.Fatalf("a reconcile-required apply must exit 3 (STALE), got %d\n%s", exit, got)
	}
	if !strings.Contains(got, "STALE") {
		t.Fatalf("exit 3 must render the STALE banner:\n%s", got)
	}
	if !strings.Contains(got, "groundhold resume c --ledger l --at 2026-01-01T00:00:00Z") {
		t.Fatalf("the STALE path must name the resume remedy WITH --at:\n%s", got)
	}
	if !strings.Contains(got, "resume asks the provider") {
		t.Fatalf("the remedy's note should travel too (D89 verbatim):\n%s", got)
	}
}

// Part B — converge surfaces a bound capability's converged no-op with its honest
// reason, so "converge did nothing" for that capability is never a mystery. The
// plan child reports it in plan.noop; converge prints one line per no-op.
func TestConvergeSurfacesNoOpReason(t *testing.T) {
	t.Chdir(t.TempDir())

	run := func(args ...string) (int, string, string) {
		switch args[0] {
		case "verify":
			return 0, `{"executable":true,"verdicts":[]}`, ""
		case "plan":
			// one capability updates, one is a converged no-op.
			return 0, `{"plan":{"actions":[{"id":"a-update-web","operation":"update",` +
				`"capability":"web","risk":{"dataLoss":"none"}}],` +
				`"noop":[{"capability":"api","reason":"bound, observed==declared"}]}}`, ""
		case "forecast":
			return 0, `{"forecast":{"rollup":{}}}`, ""
		case "apply":
			return 0, `{"status":"applied","events":[]}`, ""
		case "observe":
			return 0, `{}`, ""
		}
		return 0, "", ""
	}
	var out bytes.Buffer
	o := Options{Contract: "c", Candidate: "k", Ledger: "l",
		At: "2026-01-01T00:00:00Z", Run: run, Out: &out, Yes: true}

	Converge(o)
	got := out.String()
	if !strings.Contains(got, "api: no-op (bound, observed==declared)") {
		t.Fatalf("converge must name the converged no-op and its reason:\n%s", got)
	}
}
