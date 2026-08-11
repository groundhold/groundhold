package ledger

import (
	"path/filepath"
	"strings"
	"testing"
)

// D576. Measured on a real ledger: rewrite the body of the LAST event and `attest`
// exits 0 and reports a healthy chain. Rewrite any earlier one and it exits 5.
//
// That is not a defect. A hash chain protects an event by the link its SUCCESSOR
// holds, and the final event has no successor — its integrity lives in an external
// anchor, which is why `snapshot` prints one and says "store it off-host", and why
// THREAT_MODEL.md's first row pairs "per-capability hash chain" with "a
// positional/manifest tail **anchor** (external)". Confirmed both halves: with an
// anchor taken before the edit, `anchor --check` exits 5 on the same file `attest`
// called healthy.
//
// What was missing is at the point of use. `attest` already reports what it does NOT
// cover — `unsigned`, `archivedBase` — and said nothing about the tip. An operator
// running it in CI without an anchor concludes "ledger intact" for a ledger whose
// last decision was rewritten. The record stated it; the moment of use did not
// (D566's shape, and D568's: the report is the thing a person reads).
func TestAttestSaysItCannotCoverTheTip(t *testing.T) {
	r := &IntegrityReport{TotalEvents: 3, TailEvents: 3}
	r.stampCoverage()
	if r.Coverage == nil {
		t.Fatal("the report states no coverage at all")
	}
	if !strings.Contains(strings.ToLower(r.Coverage.Tip), "anchor") {
		t.Errorf("the coverage note does not point at the anchor, which is the only "+
			"thing that covers the tip: %+v", r.Coverage)
	}
	if !strings.Contains(strings.ToLower(r.Coverage.Tip), "last") {
		t.Errorf("the note does not say WHICH event is uncovered, so a reader cannot "+
			"tell whether it matters to them: %+v", r.Coverage)
	}
}

// An EMPTY tail has no tip to leave uncovered, and claiming otherwise would be the
// noise D537 warns about — a caveat printed when it cannot apply.
func TestAttestSaysNothingAboutTheTipOfAnEmptyTail(t *testing.T) {
	r := &IntegrityReport{TotalEvents: 5, TailEvents: 0, BaseEvents: 5}
	r.stampCoverage()
	if r.Coverage != nil && r.Coverage.Tip != "" {
		t.Errorf("a ledger with no tail events was warned about its last event: %+v",
			r.Coverage)
	}
}

// Through Attest() itself, not the helper: a test aimed at the function it fixed
// proves the function and says nothing about whether anything CALLS it (D564, and
// the reason this test exists at all — the first version here exercised
// stampCoverage directly and would have passed with the wiring absent).
func TestAttestReportCarriesTheCoverageNote(t *testing.T) {
	path := writeTinyLedger(t)
	rep, err := Attest(path, "2026-07-31T12:00:00Z")
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if rep.TailEvents == 0 {
		t.Fatalf("the fixture produced no tail events, so the note cannot be exercised")
	}
	if rep.Coverage == nil || rep.Coverage.Tip == "" {
		t.Errorf("Attest() built a report with no coverage note — stampCoverage is not "+
			"wired into the path an operator actually runs: %+v", rep)
	}
}

// writeTinyLedger writes a two-event ledger through the real Writer, so Attest reads
// a file produced the way production produces one.
func writeTinyLedger(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.ndjson")
	w := &Writer{Path: path, Led: New(), Env: "dev", Clock: 1752600000, Actor: "t"}
	if err := w.Append("contract.published", []string{"store"},
		map[string]any{"contract": "t", "version": 1}, 0); err != nil {
		t.Fatal(err)
	}
	led, err := ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w2 := &Writer{Path: path, Led: led, Env: "dev", Clock: 1752600001, Actor: "t"}
	if err := w2.Append("contract.published", []string{"store"},
		map[string]any{"contract": "t", "version": 2}, 0); err != nil {
		t.Fatal(err)
	}
	return path
}
