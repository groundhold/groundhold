package posture

import "testing"

// TestStaleHardConstraintBlocksNotDecayed pins D965: a decayed proof that is the
// ONLY backing for a HARD constraint makes that constraint UNKNOWN, and audit
// exits 2 on the identical evidence — so posture must block it too (invariant #1),
// not mask it as a benign decayed refresh (exit 0). The accumulator now records
// the audit `unknown`, and capRow ranks it above decayed. A decayed proof backing
// NO hard constraint still lands in decayed (D958 preserved).
func TestStaleHardConstraintBlocksNotDecayed(t *testing.T) {
	scope := []Scope{{Provider: "fake", Scope: "acct", Complete: true}}

	t.Run("stale hard-constraint proof blocks (unknown, exit 2)", func(t *testing.T) {
		in := Input{
			At:       "2026-07-15T12:05:00Z",
			Scopes:   scope,
			Bindings: map[string]string{"db": "fake:db-1"},
			Decayed:  map[string]bool{"db": true},
			// audit returned unknown for the hard constraint (its only proof is stale)
			Verdict: map[string]string{"db": "unknown"},
		}
		doc := Classify(in)
		if cls := classOf(doc, "fake:db-1"); cls != "unknown" {
			t.Fatalf("a stale HARD-constraint proof must be unknown (blocking), got %q", cls)
		}
		if doc.Summary.ExitCode() != 2 {
			t.Fatalf("posture must exit 2 on a stale hard constraint (audit-parity, invariant #1), got %d",
				doc.Summary.ExitCode())
		}
	})

	t.Run("decayed proof backing no hard constraint stays decayed (exit 0, D958)", func(t *testing.T) {
		in := Input{
			At:       "2026-07-15T12:05:00Z",
			Scopes:   scope,
			Bindings: map[string]string{"db": "fake:db-1"},
			Decayed:  map[string]bool{"db": true},
			Verdict:  map[string]string{}, // no hard audit verdict for this cap
		}
		doc := Classify(in)
		if cls := classOf(doc, "fake:db-1"); cls != "decayed" {
			t.Fatalf("a decayed proof backing no hard constraint must stay decayed, got %q", cls)
		}
		if doc.Summary.ExitCode() != 0 {
			t.Fatalf("decayed alone must not fail the machine surface (D958), got exit %d",
				doc.Summary.ExitCode())
		}
	})
}
