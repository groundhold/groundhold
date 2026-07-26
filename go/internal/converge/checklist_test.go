package converge

import (
	"bytes"
	"strings"
	"testing"

	"groundhold/internal/render"
)

// plainMode is deterministic (no color, ASCII glyphs) for golden assertions.
func plainMode() render.Mode { return render.Mode{Color: false, ASCII: true} }

// frozenFrame returns the final rendered frame by driving a sticky checklist and
// reading its last repaint (the frame content is what we assert, not the ANSI).
func frozenFrame(c *Checklist) []string {
	// re-render into a fresh buffer using the same row states, sticky off so the
	// output is the plain frame lines without cursor control.
	var b bytes.Buffer
	f := &Checklist{w: &b, m: c.m, rows: c.rows, byID: c.byID, sticky: true}
	f.prevLines = 0
	frame := strings.Join(f.frameLines(), "\n")
	return strings.Split(frame, "\n")
}

func TestChecklistPreListsAllPhasesPending(t *testing.T) {
	c := NewChecklist(nil, plainMode(), false)
	if len(c.rows) != 8 {
		t.Fatalf("expected 8 canonical phases, got %d", len(c.rows))
	}
	for _, r := range c.rows {
		if r.state != "pending" {
			t.Fatalf("phase %s should start pending, got %s", r.id, r.state)
		}
	}
	// the two observes are distinct rows, named by role
	if c.byID["observe-refresh"] == nil || c.byID["observe-evidence"] == nil {
		t.Fatal("observe must be two rows (refresh + evidence)")
	}
}

func TestChecklistEnterMarksPreviousDone(t *testing.T) {
	c := NewChecklist(nil, plainMode(), false)
	c.Enter("verify")
	c.Enter("plan")
	if c.byID["verify"].state != "done" {
		t.Fatalf("verify should be done once plan starts, got %s", c.byID["verify"].state)
	}
	if c.byID["plan"].state != "active" {
		t.Fatalf("plan should be active, got %s", c.byID["plan"].state)
	}
	// downstream phases stay pending (claim: unknown — never "will run")
	if c.byID["apply"].state != "pending" {
		t.Fatalf("apply should still be pending, got %s", c.byID["apply"].state)
	}
}

func TestChecklistSkipConditionalWithWhy(t *testing.T) {
	c := NewChecklist(nil, plainMode(), false)
	c.Enter("verify")
	c.Skip("observe-refresh", "evidence fresh")
	r := c.byID["observe-refresh"]
	if r.state != "skipped" || r.why != "evidence fresh" {
		t.Fatalf("conditional skip must carry a why: state=%s why=%q", r.state, r.why)
	}
}

func TestChecklistEarlyExitResolvesPendingToSkipped(t *testing.T) {
	// verify refuses -> every downstream row resolves to skipped(loop ended),
	// NEVER left dangling pending, NEVER marked failed.
	c := NewChecklist(nil, plainMode(), false)
	c.Enter("verify")
	c.Freeze(true, "loop ended: verify refused")

	if c.byID["verify"].state != "refused" {
		t.Fatalf("the refusing phase must be `refused`, got %s", c.byID["verify"].state)
	}
	for _, id := range []string{"plan", "forecast", "apply", "convergence-check"} {
		r := c.byID[id]
		if r.state != "skipped" {
			t.Fatalf("%s must be skipped after early exit, got %s", id, r.state)
		}
		if r.why == "" {
			t.Fatalf("%s skip must carry a why", id)
		}
	}
	// the four-valued discipline: no downstream row is `failed`
	for _, r := range c.rows {
		if r.state == "failed" {
			t.Fatalf("early exit must not mark any phase failed: %s", r.id)
		}
	}
}

func TestChecklistRefusedDistinctFromFailed(t *testing.T) {
	m := plainMode()
	if m.PhaseGlyph("refused") == m.PhaseGlyph("failed") {
		t.Fatal("refused and failed must have distinct glyphs (refusal-is-not-failure)")
	}
	if m.PhaseGlyph("refused") != "REF" || m.PhaseGlyph("failed") != "X" {
		t.Fatalf("glyphs: refused=%q failed=%q", m.PhaseGlyph("refused"), m.PhaseGlyph("failed"))
	}
}

func TestChecklistFrozenFrameGolden(t *testing.T) {
	c := NewChecklist(nil, plainMode(), false)
	c.Enter("verify")
	c.Enter("plan")
	c.Skip("observe-refresh", "evidence fresh")
	c.Enter("forecast")
	c.Enter("confirm")
	c.Enter("apply")
	c.Enter("observe-evidence")
	c.Enter("convergence-check")
	c.Freeze(false, "loop ended")

	lines := frozenFrame(c)
	joined := strings.Join(lines, "\n")
	// verify..observe-evidence done, observe-refresh skipped, convergence-check done
	for _, want := range []string{
		"OK verify", "OK plan", "SKIP observe", "OK forecast", "OK confirm",
		"OK apply", "OK observe", "OK convergence-check",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("frozen frame missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "converged") || strings.Contains(joined, "CONVERGED") {
		t.Fatalf("checklist must NOT render a loop verdict (that is the banner's job):\n%s", joined)
	}
}
