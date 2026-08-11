package ledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// compacted builds a real chained ledger with the product's writer and compacts it.
func compacted(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	led := New()
	for i := 0; i < 4; i++ {
		w := &Writer{Path: path, Led: led, Env: "test",
			Clock: 1767225600 + i*60, Actor: "t"}
		if err := w.Append("contract.published", []string{"db"},
			map[string]any{"contractHash": "sha256:aaa", "version": i + 1}, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := Rotate(path); err != nil {
		t.Fatal(err)
	}
	led2, err := ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := &Writer{Path: path, Led: led2, Env: "test", Clock: 1767229200, Actor: "t"}
	if err := w.Append("contract.published", []string{"db"},
		map[string]any{"contractHash": "sha256:bbb", "version": 9}, 0); err != nil {
		t.Fatal(err)
	}
	return path
}

// D646. `archive.sha256` and `previousSnapshotHash` had ZERO readers in the tree,
// while spec/state-model.md §9 told operators that "a swapped or truncated archive
// is detectable, not deniable". Measured: truncating an 18-event archive to 3 left
// `attest`, `anchor --check`, `repair` and `converge` all at exit 0.
func TestATruncatedArchiveIsNoticed(t *testing.T) {
	path := compacted(t)
	snap, err := LoadSnapshotFile(SnapshotPath(path))
	if err != nil || snap == nil {
		t.Fatalf("no snapshot: %v", err)
	}

	if ai := CheckArchive(path, snap); ai.Status != "matched" {
		t.Fatalf("an untouched archive must match: %+v", ai)
	}
	rep, err := Attest(path, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Snapshot == nil || rep.Snapshot.Archive.Status != "matched" {
		t.Fatalf("attest does not report the archive as checked: %+v", rep.Snapshot)
	}

	// Truncate it, the way a botched copy or a deliberate edit would.
	arch := ArchivePath(path, snap.BaseEvents)
	raw, err := os.ReadFile(arch)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(raw), "\n")
	if err := os.WriteFile(arch, []byte(lines[0]), 0o600); err != nil {
		t.Fatal(err)
	}

	ai := CheckArchive(path, snap)
	if ai.Status != "mismatched" {
		t.Errorf("a truncated archive reads as %q — the compacted history is the "+
			"only copy of those events, and after D645 it is what a forensic "+
			"window streams: %+v", ai.Status, ai)
	}
	rep2, err := Attest(path, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Snapshot.Archive.Status == "matched" {
		t.Errorf("attest still reports the archive as matched: %+v", rep2.Snapshot)
	}
	// repair is the verb that turns facts into a verdict.
	d, err := Diagnose(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status == "healthy" {
		t.Errorf("repair calls a ledger with a truncated archive healthy: %+v", d)
	}
}

// A sidecar must not get to nominate which file satisfies its own hash — that is
// the shape D312 closed for anchors and D643 for backup manifests.
func TestASnapshotCannotPointItsHashAtAnotherFile(t *testing.T) {
	path := compacted(t)
	snap, err := LoadSnapshotFile(SnapshotPath(path))
	if err != nil || snap == nil {
		t.Fatalf("no snapshot: %v", err)
	}
	decoy := filepath.Join(filepath.Dir(path), "decoy.jsonl")
	if err := os.WriteFile(decoy, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snap.Archive.File = decoy
	if ai := CheckArchive(path, snap); ai.Status != "misnamed" {
		t.Errorf("the snapshot redirected its own archive check to %s and got %q",
			decoy, ai.Status)
	}

	// The control: only the DIRECTORY may differ, so a backup that was copied
	// somewhere else still verifies rather than crying tamper.
	snap.Archive.File = filepath.Join("/somewhere/else",
		filepath.Base(ArchivePath(path, snap.BaseEvents)))
	if ai := CheckArchive(path, snap); ai.Status != "matched" {
		t.Errorf("a moved-but-intact ledger must still verify, got %+v", ai)
	}
}

// D647. Compaction computed an anchor and wrote it only if a file happened to
// already exist beside the ledger. The anchor is the one artefact that can be
// copied off-host, which is the only place authenticity can come from once the
// directory is writable (D646) — so the moment a fold replaces history is exactly
// the moment one must exist.
func TestCompactionAlwaysLeavesAnAnchor(t *testing.T) {
	path := compacted(t) // no anchor file was ever placed here
	raw, err := os.ReadFile(AnchorPath(path))
	if err != nil {
		t.Fatalf("compaction left no anchor: %v — nothing beside this ledger "+
			"witnesses the fold, and the operator has nothing to copy off-host", err)
	}
	a, err := LoadAnchorFile(AnchorPath(path))
	if err != nil || a == nil {
		t.Fatalf("the anchor compaction wrote is not loadable: %v (%d bytes)", err, len(raw))
	}
	if a.SnapshotHash == "" {
		t.Error("the anchor does not pin the snapshot hash, so a swapped sidecar " +
			"would still verify against it")
	}
	led, err := ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnforceAnchor(path, led); err != nil {
		t.Errorf("the anchor compaction just wrote does not verify against the "+
			"ledger it was written for: %v", err)
	}
}
