package export

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/ledger"
)

// buildCompacted writes a real hash-chained ledger with the product's own writer,
// compacts it, then appends more events — the shape every long-lived ledger reaches.
func buildCompacted(t *testing.T) (path string, beforeCount int) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "l.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	clock := 1767225600 // 2026-01-01T00:00:00Z
	for i := 0; i < 4; i++ {
		w := &ledger.Writer{Path: path, Led: led, Env: "test",
			Clock: clock + i*60, Actor: "t"}
		if err := w.Append("contract.published", []string{"db"},
			map[string]any{"contractHash": "sha256:aaa", "version": i + 1}, 0); err != nil {
			t.Fatal(err)
		}
	}
	beforeCount = 4
	if _, _, err := ledger.Rotate(path); err != nil {
		t.Fatalf("compact: %v", err)
	}
	led2, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := &ledger.Writer{Path: path, Led: led2, Env: "test",
		Clock: clock + 3600, Actor: "t"}
	if err := w.Append("contract.published", []string{"db"},
		map[string]any{"contractHash": "sha256:bbb", "version": 9}, 0); err != nil {
		t.Fatal(err)
	}
	return path, beforeCount
}

func exportRecords(t *testing.T, o Options) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	o.Out = &buf
	if _, err := Run(o); err != nil {
		t.Fatalf("export: %v", err)
	}
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

// D645. `export --from T1 --to T2` is the 4D disaster-recovery primitive, and the
// dr-forensics skill's first instruction is to run it. It read only the LIVE file.
// After a compaction the live file holds the tail, so a window over events that
// were compacted returned NOTHING — exit 0, empty stdout, nothing on stderr:
//
//	before compaction: export --from … --to …   18 events, exit 0
//	after  compaction: export --from … --to …    0 events, exit 0
//
// The skill's own rule is "any sentence without an event hash is speculation and
// comes out", so the honest conclusion an agent draws from that stream is "nothing
// happened in this window". The archives holding those events are sitting in the
// same directory. This is the shape D315 already names in its own comment — "a
// consumer got a short stream with nothing saying an event was withheld" — at the
// compaction boundary rather than at the timestamp parser.
func TestAWindowOverCompactedEventsIsNotEmpty(t *testing.T) {
	path, before := buildCompacted(t)

	all := exportRecords(t, Options{LedgerPath: path, Format: "ndjson"})
	if len(all) != before+1 {
		t.Errorf("exported %d events, want %d — the compacted history is missing "+
			"from the stream", len(all), before+1)
	}
	// Indices stay ABSOLUTE and contiguous from 0: a cursor consumer's meaning
	// does not change because the file was rotated underneath it.
	for i, r := range all {
		if idx, _ := r["index"].(float64); int(idx) != i {
			t.Errorf("record %d carries index %v — cursors are absolute (D137)", i, idx)
		}
	}

	// The 4D window over the compacted range specifically.
	win := exportRecords(t, Options{LedgerPath: path, Format: "ndjson",
		From: "2026-01-01T00:00:00Z", To: "2026-01-01T00:20:00Z"})
	if len(win) != before {
		t.Errorf("the window covering the compacted events returned %d of %d — a "+
			"forensic answer of \"nothing happened\" over a window in which %d "+
			"events occurred", len(win), before, before)
	}

	// A cursor BELOW the compaction boundary must resume from where it points.
	since := exportRecords(t, Options{LedgerPath: path, Format: "ndjson", Since: 1})
	if len(since) != before {
		t.Errorf("--since 1 returned %d records, want %d — an incremental consumer "+
			"loses everything between its cursor and the compaction", len(since), before)
	}
}

// If the archive a compaction wrote is gone, the compacted events cannot be read
// and the stream cannot be complete. That must be said, not silently skipped —
// the whole defect above is a short stream that looks like a full one.
func TestAMissingArchiveRefusesRatherThanShortensTheStream(t *testing.T) {
	path, _ := buildCompacted(t)
	snap, err := ledger.LoadSnapshotFile(ledger.SnapshotPath(path))
	if err != nil || snap == nil {
		t.Fatalf("no snapshot: %v", err)
	}
	if err := os.Remove(ledger.ArchivePath(path, snap.BaseEvents)); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	_, rerr := Run(Options{LedgerPath: path, Format: "ndjson", Out: &buf})
	if rerr == nil {
		t.Fatalf("exported %d bytes with the compacted history unreadable and said "+
			"nothing about it", buf.Len())
	}

	// The control: a consumer whose cursor is already PAST the compaction is not
	// asking for those events, and must not be blocked by their absence.
	if _, err := Run(Options{LedgerPath: path, Format: "ndjson",
		Since: snap.BaseEvents, Out: &bytes.Buffer{}}); err != nil {
		t.Errorf("a cursor past the compaction boundary asks for nothing that is "+
			"missing and must still stream: %v", err)
	}
}
