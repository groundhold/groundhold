package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D611. `spec/errors.md`: `ledger-corrupted | 5 | … nothing proceeds over corruption`.
// Twelve verbs obeyed it. Three did not: `runs`, `status` and `wait` reported derived
// run state — a handle, a phase, a duration — from a ledger that does not replay, at
// exit 0 and with an OK banner, while `export`, `attest`, `audit` and the rest refused
// the identical bytes with exit 5.
//
// The reason was one struct. `runstatus.ReadEvents` unmarshalled each line into a shape
// where every field is optional, so `{"this":"is not an event"}` parsed cleanly into an
// event with no type; `ledger.ParseTs`'s error was discarded (`clk, _ :=`), so its
// timestamp became the epoch. D323 named that exact pattern — PRESENT is not the same
// as PARSES — and here it was in the reader three reporting verbs share.
//
// These verbs are deliberately non-judging: a run that FAILED is still reported at exit
// 0, because reporting is not judging. That rule survives. A file that is not a ledger
// is not a run that failed.
func TestReportingVerbsRefuseACorruptLedger(t *testing.T) {
	dir := t.TempDir()

	healthy := `{"apiVersion":"state/v0","kind":"LedgerEvent","event":{"type":"converge.started","environment":"test","capabilities":["db"],"occurredAt":"2026-01-01T00:00:00Z","actor":{"id":"r","type":"runtime"},"body":{"handle":"abc123"}}}
`
	corrupt := healthy + "{\"this\":\"is not an event\"}\n"
	// A line with a PERFECTLY GOOD timestamp and no type. The two guards overlap on
	// the line above (it has neither), so only this fixture can tell whether the
	// type check is doing anything — the mutation meter caught that first, by
	// reporting a real mutant as SURVIVED.
	noType := healthy + `{"apiVersion":"state/v0","kind":"LedgerEvent","event":{"occurredAt":"2026-01-01T00:02:00Z","actor":{"id":"r","type":"runtime"}}}` + "\n"
	noTime := healthy + `{"apiVersion":"state/v0","kind":"LedgerEvent","event":{"type":"converge.finished","occurredAt":"not-a-timestamp","actor":{"id":"r","type":"runtime"}}}` + "\n"

	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// `wait` blocks until the run reaches a terminal state, so its healthy case needs
	// one — otherwise the control measures a timeout rather than a clean report.
	finished := healthy + `{"apiVersion":"state/v0","kind":"LedgerEvent","event":{"type":"converge.finished","environment":"test","capabilities":["db"],"occurredAt":"2026-01-01T00:01:00Z","actor":{"id":"r","type":"runtime"},"body":{"handle":"abc123"}}}` + "\n"
	okPath := write("ok.ndjson", healthy)
	donePath := write("done.ndjson", finished)
	badPath := write("bad.ndjson", corrupt)
	timePath := write("badtime.ndjson", noTime)
	noTypePath := write("notype.ndjson", noType)

	const at = "2026-02-01T00:00:00Z"
	for _, tc := range []struct {
		name    string
		argv    func(ledger string) []string
		healthy string
	}{
		{"runs", func(l string) []string {
			return []string{"runs", "--ledger", l, "--at", at}
		}, okPath},
		{"status", func(l string) []string {
			return []string{"status", "abc123", "--ledger", l, "--at", at}
		}, okPath},
		{"wait", func(l string) []string {
			return []string{"wait", "abc123", "--ledger", l, "--timeout", "1"}
		}, donePath},
	} {
		t.Run(tc.name+" refuses a line that is not an event", func(t *testing.T) {
			if got := run(tc.argv(badPath)); got != 5 {
				t.Errorf("exit %d over a corrupt ledger, want 5 (ledger-corrupted).\n"+
					"Twelve other verbs refuse these exact bytes; a caller cannot have "+
					"one verb call the file unusable and the next report state from it.",
					got)
			}
		})
		t.Run(tc.name+" refuses an event with no type", func(t *testing.T) {
			if got := run(tc.argv(noTypePath)); got != 5 {
				t.Errorf("exit %d over a line with a valid timestamp and no event.type, "+
					"want 5 — every field of the reader's struct is optional, so this "+
					"is the shape that decoded cleanly into a typeless event", got)
			}
		})
		t.Run(tc.name+" refuses an unreadable occurredAt", func(t *testing.T) {
			if got := run(tc.argv(timePath)); got != 5 {
				t.Errorf("exit %d over an unparseable timestamp, want 5 — discarding "+
					"the parse error dates the event to the epoch (D323)", got)
			}
		})
		t.Run(tc.name+" does not call a healthy ledger corrupt", func(t *testing.T) {
			// `runs` and `status` report at 0. `wait` is weaker on purpose: it blocks
			// for a terminal state and exits 3 on timeout, and building a synthetic
			// run the derivation calls terminal would be pinning my model of that
			// derivation rather than the property under test. What must hold for all
			// three is that a READABLE ledger is never called corrupt.
			got := run(tc.argv(tc.healthy))
			if got == 5 {
				t.Errorf("exit 5 over a healthy ledger — the refusal must be about " +
					"corruption, not about being stricter than before")
			}
			if tc.name != "wait" && got != 0 {
				t.Errorf("exit %d over a healthy ledger, want 0", got)
			}
		})
	}
}

// The refusal must name the line and say what is wrong with it, not merely fail.
func TestCorruptLedgerRefusalNamesTheLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "l.ndjson")
	body := `{"apiVersion":"state/v0","kind":"LedgerEvent","event":{"type":"converge.started","occurredAt":"2026-01-01T00:00:00Z","actor":{"id":"r","type":"runtime"}}}
{"this":"is not an event"}
`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	stderr := captureStderr(t, func() { run([]string{"runs", "--ledger", p, "--at", "2026-02-01T00:00:00Z"}) })
	for _, want := range []string{"line 2", "event.type"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not mention %q — an operator cannot find the "+
				"line:\n%s", want, stderr)
		}
	}
}
