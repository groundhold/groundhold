package export

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/ledger"
)

// D315 (adversarial audit of export): `export` is more permissive than replay
// about occurredAt, and a windowed export turns that into a SILENT drop.
//
// ValidateEvent requires occurredAt to be a quoted string but never parses it;
// ReplayFile does parse it and REFUSES the whole file when it will not. `export`
// verifies the chain and the signatures itself but never replays, so it accepts a
// file every other verb rejects — and then, under `--from/--to`, drops the
// unparseable event with a bare `continue` and a comment calling that "honestly
// outside any bounded window". The consumer receives a short stream with nothing
// saying anything was withheld, from a file the rest of the system considers
// corrupt.
//
// A silent drop is exactly what D53 forbids elsewhere ("unmapped types become
// diagnostics, never silent drops"), and this one is on the handover surface.
func TestExportRefusesWhatReplayRefuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	writeLedgerWithBadTime(t, path)

	// the rest of the system will not touch this file
	if _, err := ledger.ReplayFile(path); err == nil {
		t.Fatal("precondition: replay must refuse an unparseable occurredAt")
	}

	var out bytes.Buffer
	_, err := Run(Options{LedgerPath: path, Out: &out})
	if err == nil {
		t.Errorf("export accepted a ledger replay refuses — the handover surface "+
			"must be at least as strict as the fold.\nemitted:\n%s", out.String())
	}
}

// The windowed form is the dangerous one: the event is not merely accepted, it is
// dropped without a word, so the consumer cannot tell a quiet window from a
// withheld event.
func TestWindowedExportDoesNotSilentlyDropUnplaceableEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	writeLedgerWithBadTime(t, path)

	var out bytes.Buffer
	n, err := Run(Options{LedgerPath: path, Out: &out,
		From: "1970-01-01T00:00:00Z", To: "2100-01-01T00:00:00Z"})
	if err != nil {
		return // refusing is the correct outcome — the other test names it
	}
	if n != 2 {
		t.Errorf("a window spanning all of history emitted %d of 2 events — the "+
			"unplaceable one was dropped silently, and the stream says nothing "+
			"about it:\n%s", n, out.String())
	}
}

// writeLedgerWithBadTime hand-writes a two-event chain whose SECOND event carries
// an occurredAt that is a string but not a time. The chain linkage is intact, so
// only the timestamp rule separates it from a valid ledger.
func writeLedgerWithBadTime(t *testing.T, path string) {
	t.Helper()
	good := filepath.Join(t.TempDir(), "good.jsonl")
	led, err := ledger.ReplayFile(good)
	if err != nil {
		t.Fatal(err)
	}
	w := &ledger.Writer{Path: good, Led: led, Env: "test", Actor: "t", Clock: 1000}
	tok, err := w.AppendLease([]string{"orders-db"}, map[string]any{"ttlSeconds": 100000})
	if err != nil {
		t.Fatal(err)
	}
	w.Clock = 1001
	if err := w.Append("lease.released", []string{"orders-db"}, nil, tok); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 events, got %d", len(lines))
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &doc); err != nil {
		t.Fatal(err)
	}
	ev, _ := doc["event"].(map[string]any)
	ev["occurredAt"] = "whenever" // a string, as ValidateEvent demands — just not a time
	// the prev linkage still pins the first event's hash, so only the time is wrong
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(lines[0]+"\n"+string(b)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// D315: a blank line must not change an export. Two things keyed off the raw loop
// index: the identity pin (`if i == 0`, which a blank first line consumes, so
// ExpectLedger never ran — D134's cross-check skippable by whitespace) and, worse,
// the exported `index` itself (`base + i`), which is what a consumer correlates
// and dedupes on. One blank line renumbered every record in the stream.
func TestLeadingBlankLineDoesNotChangeTheExport(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.jsonl")
	led, err := ledger.ReplayFile(good)
	if err != nil {
		t.Fatal(err)
	}
	w := &ledger.Writer{Path: good, Led: led, Env: "test", Actor: "t", Clock: 1000}
	tok, err := w.AppendLease([]string{"orders-db"}, map[string]any{"ttlSeconds": 100000})
	if err != nil {
		t.Fatal(err)
	}
	w.Clock = 1001
	if err := w.Append("lease.released", []string{"orders-db"}, nil, tok); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	padded := filepath.Join(dir, "padded.jsonl")
	if err := os.WriteFile(padded, append([]byte("\n"), raw...), 0o600); err != nil {
		t.Fatal(err)
	}

	var a, b bytes.Buffer
	na, erra := Run(Options{LedgerPath: good, Out: &a})
	nb, errb := Run(Options{LedgerPath: padded, Out: &b})
	if erra != nil {
		t.Fatalf("baseline export failed: %v", erra)
	}
	if errb != nil {
		t.Fatalf("a leading blank line must not change the outcome: %v", errb)
	}
	if na != nb || a.String() != b.String() {
		t.Errorf("a blank first line changed the export (%d vs %d records):\n"+
			"without:\n%s\nwith:\n%s", na, nb, a.String(), b.String())
	}
}
