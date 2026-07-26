package converge

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"groundhold/internal/render"
)

// TestDescribePlanFailsClosedOnUnparseablePlan pins D193: the destructive/
// data-loss consent gate keys on describePlan's verdict. If the plan body
// cannot be parsed for risk, converge cannot rule out data loss or identity
// replacement, so it must treat the plan as DESTRUCTIVE (fail-closed) and demand
// explicit consent — never default to non-destructive on an empty parse and skip
// the gate. Before the fix the unmarshal error was `_`-ignored, so a
// `converge --yes` on an unparseable plan would apply it without --allow-data-loss.
func TestDescribePlanFailsClosedOnUnparseablePlan(t *testing.T) {
	o := Options{Out: io.Discard}

	if !describePlan(o, "this is not a plan document", "") {
		t.Fatal("an unparseable plan must be treated as destructive (fail-closed) " +
			"so the consent gate fires")
	}

	// a valid, non-destructive plan is NOT flagged (no false positive)
	nonDestructive := `{"plan":{"actions":[{"id":"a-update-db","operation":"update",` +
		`"risk":{"dataLoss":"none","identityReplacement":false}}]}}`
	if describePlan(o, nonDestructive, "") {
		t.Fatal("a non-destructive plan must not be flagged destructive")
	}

	// a data-loss / identity-replacing plan IS destructive
	destructive := `{"plan":{"actions":[{"id":"a-delete-db","operation":"delete",` +
		`"risk":{"dataLoss":"certain","identityReplacement":true}}]}}`
	if !describePlan(o, destructive, "") {
		t.Fatal("a dataLoss=certain / identity-replacing plan must be destructive")
	}
}

// TestConvergeRendersBlockingVerdictNotRefused pins D194 F1: converge fed a
// verify that is not-executable BECAUSE a hard constraint is violated must
// render VIOLATED (the proven-false world), not a benign blue REFUSED. Before
// the fix converge passed an empty Rollup to Pick, collapsing the block into a
// policy refusal.
func TestConvergeRendersBlockingVerdictNotRefused(t *testing.T) {
	run := func(args ...string) (int, string, string) {
		if len(args) > 0 && args[0] == "verify" {
			return 2, `{"blockingReasons":["hard constraint violated: c-rto"],` +
				`"verdicts":[{"constraint":"c-rto","severity":"hard","verdict":"violated"}]}`, ""
		}
		return 0, "", ""
	}
	var out bytes.Buffer
	o := Options{Contract: "c", Candidate: "k", Vocab: "v",
		At: "2026-01-01T00:00:00Z", Run: run, Out: &out}
	exit := Converge(o)
	if exit != 2 {
		t.Fatalf("a not-executable verify must exit 2, got %d", exit)
	}
	got := out.String()
	if !strings.Contains(got, "VIOLATED") {
		t.Fatalf("converge must render VIOLATED for a violated hard constraint, got:\n%s", got)
	}
	if strings.Contains(got, "REFUSED") {
		t.Fatalf("a violated world must not render as a benign REFUSED, got:\n%s", got)
	}
}

// TestPlanCreateSummary pins the D251 lost-ledger signal: an all-creates plan is
// detected (creates == total) so converge can advise adopt-first.
func TestPlanCreateSummary(t *testing.T) {
	allCreate := `{"plan":{"actions":[{"operation":"create"},{"operation":"create"},{"operation":"create"}]}}`
	if c, tot := planCreateSummary(allCreate); c != 3 || tot != 3 {
		t.Fatalf("all-creates: got creates=%d total=%d, want 3/3", c, tot)
	}
	mixed := `{"plan":{"actions":[{"operation":"create"},{"operation":"update"}]}}`
	if c, tot := planCreateSummary(mixed); c != 1 || tot != 2 {
		t.Fatalf("mixed: got creates=%d total=%d, want 1/2", c, tot)
	}
	if c, tot := planCreateSummary("not json"); c != 0 || tot != 0 {
		t.Fatalf("unparseable must be 0/0, got %d/%d", c, tot)
	}
}

// TestForecastFailureIsSaidNotSwallowed pins D291. The forecast phase existed
// to show a human what will happen immediately BEFORE they consent — and its
// exit code was the only one converge discarded. A failed preview therefore
// rendered exactly like a delivered one: the checklist row went done (Enter on
// the next phase completes the active row unconditionally) and nothing on the
// human channel said the preview was missing. Green where reality was absent,
// on the consent path.
func TestForecastFailureIsSaidNotSwallowed(t *testing.T) {
	run := func(args ...string) (int, string, string) {
		switch args[0] {
		case "verify":
			return 0, `{"executable":true,"verdicts":[]}`, ""
		case "plan":
			return 0, `{"plan":{"actions":[{"id":"a-create-db","operation":"create",` +
				`"capability":"db","risk":{"dataLoss":"none"}}]}}`, ""
		case "forecast":
			// the preview could not be produced (a mismatched candidate, a
			// corrupt ledger — apply re-checks all of it independently)
			return 1, "", "forecast error: candidate does not match the plan\n"
		}
		return 0, "", ""
	}
	var out bytes.Buffer
	o := Options{Contract: "c", Candidate: "k", Vocab: "v", Ledger: "l",
		At: "2026-01-01T00:00:00Z", Run: run, Out: &out, Yes: true}
	Converge(o)
	got := out.String()

	if !strings.Contains(got, "forecast did not produce a preview") {
		t.Fatalf("a failed forecast must be SAID on the human channel:\n%s", got)
	}
	if !strings.Contains(got, "candidate does not match the plan") {
		t.Fatalf("the child's own reason must travel (D89 verbatim):\n%s", got)
	}
}

// The advisory boundary: a failed PREVIEW must not block a correct deploy —
// apply re-validates the read-set, the clock and the ledger itself, so
// refusing here would stop a valid run on a cosmetic failure. It must lose
// certainty loudly (above), not lose the ability to proceed.
func TestForecastFailureDoesNotBlockTheLoop(t *testing.T) {
	applied := false
	run := func(args ...string) (int, string, string) {
		switch args[0] {
		case "verify":
			return 0, `{"executable":true,"verdicts":[]}`, ""
		case "plan":
			return 0, `{"plan":{"actions":[{"id":"a-create-db","operation":"create",` +
				`"capability":"db","risk":{"dataLoss":"none"}}]}}`, ""
		case "forecast":
			return 1, "", "boom"
		case "apply":
			applied = true
			return 0, `{"status":"applied","events":[]}`, ""
		}
		return 0, "", ""
	}
	var out bytes.Buffer
	o := Options{Contract: "c", Candidate: "k", Vocab: "v", Ledger: "l",
		At: "2026-01-01T00:00:00Z", Run: run, Out: &out, Yes: true}
	Converge(o)
	if !applied {
		t.Fatalf("an advisory preview failure must not stop apply:\n%s", out.String())
	}
}

// TestChecklistFailedRowIsNotDone pins the row-state half: the resolved row
// must read failed WITH a why, never done. A resolved row that does not say
// why is indistinguishable from one that succeeded.
func TestChecklistFailedRowIsNotDone(t *testing.T) {
	var buf bytes.Buffer
	c := NewChecklist(&buf, render.Mode{ASCII: true}, false)
	c.Enter("verify")
	c.Enter("forecast")
	c.Fail("forecast", "no preview produced")
	c.Enter("confirm") // must NOT resurrect the failed row into done
	for _, r := range c.rows {
		if r.id == "forecast" {
			if r.state != "failed" {
				t.Fatalf("forecast row state = %q, want failed", r.state)
			}
			if r.why == "" {
				t.Fatal("a failed row must carry its why")
			}
		}
	}
}
