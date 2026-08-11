package ledger

import (
	"os"
	"path/filepath"
	"testing"
)

// D654. `repair` is the diagnose verb: an operator reaches for it when they
// suspect the history is damaged, and its numbers are what they compare against
// `attest`. It counted the LINES of the live file and called them events, which is
// two separate wrong answers on a compacted ledger:
//
//	repair --ledger l.jsonl   {"events":1, "status":"healthy", "validPrefixLines":1}
//	attest --ledger l.jsonl   totalEvents 19   baseEvents 18   tailEvents 1
//
// and on a ledger of blank lines:
//
//	printf '\n\n\n' > blank.jsonl
//	repair   {"events":1,"validPrefixLines":1}     <- three blank lines, one "event"
//
// An operator comparing the two verbs concludes one of them is lying about the
// same file. Both numbers are now `attest`'s: totalEvents, tailEvents, baseEvents.
func TestRepairCountsEventsTheWayAttestDoes(t *testing.T) {
	path := compacted(t) // 4 events compacted, 1 in the tail (see archivepin_gate_test)

	d, err := Diagnose(path)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Attest(path, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != "healthy" {
		t.Fatalf("the fixture is not healthy, so this measures nothing: %+v", d)
	}
	if d.TotalEvents != rep.TotalEvents {
		t.Errorf("repair says totalEvents=%d and attest says %d for the same file — "+
			"an operator comparing them concludes one is lying",
			d.TotalEvents, rep.TotalEvents)
	}
	if d.BaseEvents != rep.BaseEvents {
		t.Errorf("repair says baseEvents=%d and attest says %d — repair never looked "+
			"at the compaction at all", d.BaseEvents, rep.BaseEvents)
	}
	if d.TailEvents != rep.TailEvents {
		t.Errorf("repair says tailEvents=%d and attest says %d", d.TailEvents, rep.TailEvents)
	}
}

// A blank line is not an event. The count that gets PRINTED must say so, even
// though the truncation arithmetic underneath is quite reasonably in lines.
func TestBlankLinesAreNotEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blank.jsonl")
	if err := os.WriteFile(path, []byte("\n\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Diagnose(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.TotalEvents != 0 {
		t.Errorf("three blank lines were counted as %d events: %+v", d.TotalEvents, d)
	}
	// TailLines is the truncation view, not a physical line count: trailing
	// newlines are stripped before splitting, exactly as the quarantine's
	// prefix arithmetic does it. Three empty lines collapse to one empty entry.
	// Asserting 3 here would pin a definition the truncation does not use and
	// would put an off-by-one into a verb that CUTS files. What matters is that
	// the number of EVENTS is zero and the two units are separately named.
	if d.TailLines != 1 {
		t.Errorf("tailLines=%d, want 1 (the truncation view)", d.TailLines)
	}
	if d.ValidPrefixLines > d.TailLines {
		t.Errorf("validPrefixLines=%d exceeds tailLines=%d — DroppedLines would go "+
			"negative", d.ValidPrefixLines, d.TailLines)
	}
}

// The control: the truncation arithmetic must keep working in LINES, because that
// is what a quarantine cuts. A count of events cannot be used for it.
func TestQuarantineArithmeticStaysInLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	led := New()
	for i := 0; i < 3; i++ {
		w := &Writer{Path: path, Led: led, Env: "test",
			Clock: 1767225600 + i*60, Actor: "t"}
		if err := w.Append("contract.published", []string{"db"},
			map[string]any{"contractHash": "sha256:aaa", "version": i + 1}, 0); err != nil {
			t.Fatal(err)
		}
	}
	// Append a line that parses as JSON and is not an event: the file is corrupt
	// from there, and the valid prefix is the three real events.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{\"not\":\"an event\"}\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	d, err := Diagnose(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != "corrupt" {
		t.Fatalf("the fixture is not corrupt: %+v", d)
	}
	if d.ValidPrefixLines != 3 {
		t.Errorf("validPrefixLines=%d, want 3 — quarantine truncates to this, and "+
			"an off-by-one here throws away or keeps a real event", d.ValidPrefixLines)
	}
	if d.TailLines != 4 {
		t.Errorf("tailLines=%d, want 4", d.TailLines)
	}
}
