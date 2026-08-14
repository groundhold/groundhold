package converge

import (
	"bytes"
	"strings"
	"testing"
)

// D1079: converge re-witnesses recorded reality with a read-only `audit` before it
// paints the world converged, so a HARD constraint the convergence check cannot see
// (a non-observable or intent-only attribute, or the D1071 security floor, both of
// which the plan-based check misses) blocks at exit 2 instead of exiting 0 green —
// the parity `audit` and `posture` (D965) already have with invariant #1.
//
// The conformance suite pins this end-to-end through the post-apply emitter; this
// pins the PRE-APPLY "nothing to change" emitter (a plan that is already converged
// on everything it can compare), which the conformance fixture does not reach, and
// guards against the gate being deleted from any single emitter (the D939 lesson).
func TestConvergedNothingToChangeIsGatedByAudit(t *testing.T) {
	// audit refuses: a hard constraint is unwitnessed -> converge must NOT report
	// converged at exit 0.
	auditBlocks := func(args ...string) (int, string, string) {
		switch args[0] {
		case "verify":
			return 0, `{"verdicts":[]}`, ""
		case "plan":
			return 2, `{"code":"nothing-to-change"}`, ""
		case "audit":
			return 2, `{"code":"observation-required","verdicts":[{"constraint":"c-mfa",` +
				`"path":"mfa.required","severity":"hard","verdict":"unknown",` +
				`"reason":"no observation witnesses this control"}]}`, ""
		}
		return 0, "", ""
	}
	var out bytes.Buffer
	exit := Converge(Options{
		Contract: "c.yaml", Candidate: "k.yaml", Ledger: "l.jsonl",
		Provider: "fake", At: "2026-01-01T00:00:00Z",
		Yes: true, Run: auditBlocks, Out: &out, JSON: true,
	})
	if exit != 2 {
		t.Fatalf("a hard constraint audit cannot witness must block converge at exit 2, got %d\nout: %s",
			exit, out.String())
	}
	if !strings.Contains(out.String(), "c-mfa") {
		t.Errorf("the blocked run must name the unwitnessed constraint; got: %s", out.String())
	}
	if strings.Contains(out.String(), `"convergence": "verified"`) {
		t.Errorf("a blocked run must never claim convergence verified; got: %s", out.String())
	}

	// audit passes: the same already-converged plan is a clean exit 0.
	auditClean := func(args ...string) (int, string, string) {
		switch args[0] {
		case "verify":
			return 0, `{"verdicts":[]}`, ""
		case "plan":
			return 2, `{"code":"nothing-to-change"}`, ""
		case "audit":
			return 0, `{"status":"clean","verdicts":[]}`, ""
		}
		return 0, "", ""
	}
	out.Reset()
	if exit := Converge(Options{
		Contract: "c.yaml", Candidate: "k.yaml", Ledger: "l.jsonl",
		Provider: "fake", At: "2026-01-01T00:00:00Z",
		Yes: true, Run: auditClean, Out: &out, JSON: true,
	}); exit != 0 {
		t.Fatalf("a clean audit over an already-converged plan must exit 0, got %d\nout: %s",
			exit, out.String())
	}
	if !strings.Contains(out.String(), `"status": "converged"`) {
		t.Errorf("a clean already-converged plan must report converged; got: %s", out.String())
	}
}
