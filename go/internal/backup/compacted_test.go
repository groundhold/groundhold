package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/ledger"
	"groundhold/internal/restore"
)

// D313 (adversarial audit of backup): a backup taken AFTER compaction reports
// success but cannot be restored.
//
// `snapshot` (D137) rotates a ledger: the pre-snapshot events move to an archive
// and the live file keeps only the TAIL, with BaseEvents recording how many were
// compacted away. Two things then disagree:
//
//	BuildAnchor  writes Events = led.TotalEvents() — ABSOLUTE, base + tail
//	EmitCapsule  reads the FILE — the tail only
//
// and restore's full-mode totality check compares the deduped capsule events
// against anchor.Events, so it refuses every time. `backup` never notices: it
// replays the ledger (which succeeds), emits the capsules, writes the anchor and
// reports status "backed-up".
//
// That is the worst shape a backup bug can take — the artifact looks complete,
// the report says complete, and it is discovered to be unusable during the
// disaster it exists for.
func TestBackupRefusesACompactedLedgerUpFront(t *testing.T) {
	ledger.ResetSigning()
	dir := t.TempDir()
	src := writeTwoCapLedger(t, dir)

	// compact: the tail moves to an archive, the live file keeps a snapshot base
	if _, _, err := ledger.Rotate(src); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// append more history so the compacted ledger has a live tail too
	appendOneMore(t, src, "orders-db", 9000)

	out := filepath.Join(dir, "backup")
	rep, code := Run(Options{LedgerPath: src, Out: out})
	if code == ExitOK {
		t.Fatalf("a compacted ledger cannot be backed up as capsules; backup "+
			"must refuse rather than write a set that only fails at restore: %+v", rep)
	}
	if len(rep.Reasons) == 0 || !strings.Contains(rep.Reasons[0], "compacted") {
		t.Errorf("the refusal must name the real limitation (compaction), not fail "+
			"capsule-by-capsule with advice that does not work: %v", rep.Reasons)
	}
}

func writeTwoCapLedger(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "ledger.jsonl")
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := &ledger.Writer{Path: path, Led: led, Env: "test", Actor: "t"}
	bind := func(pid string) map[string]any {
		return map[string]any{"resources": []any{map[string]any{
			"id": "primary", "type": "fake.thing", "providerId": pid, "generation": 1}}}
	}
	clock := 1000
	for _, cap := range []string{"orders-db", "cache-net"} {
		w.Clock = clock
		tok, err := w.AppendLease([]string{cap}, map[string]any{"ttlSeconds": 100000})
		if err != nil {
			t.Fatal(err)
		}
		w.Clock = clock + 1
		if err := w.Append("binding.updated", []string{cap}, bind("fake:"+cap), tok); err != nil {
			t.Fatal(err)
		}
		w.Clock = clock + 2
		if err := w.Append("lease.released", []string{cap}, nil, tok); err != nil {
			t.Fatal(err)
		}
		clock += 100
	}
	return path
}

func appendOneMore(t *testing.T, path, cap string, clock int) {
	t.Helper()
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := &ledger.Writer{Path: path, Led: led, Env: "test", Actor: "t", Clock: clock}
	tok, err := w.AppendLease([]string{cap}, map[string]any{"ttlSeconds": 100000})
	if err != nil {
		t.Fatal(err)
	}
	w.Clock = clock + 1
	if err := w.Append("lease.released", []string{cap}, nil, tok); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(path, 0o600)
}

// D313: the archive workaround does NOT rescue a compacted ledger, and this test
// pins that so the misleading advice cannot come back. Capsules emitted from the
// archive end at the PRE-snapshot head while the live anchor pins the post-
// snapshot one, so restore calls them stale — correctly. (Combining archive and
// live capsules for one capability does not help either: the two event sets are
// disjoint, which merge adjudicates as a fork.)
func TestTheArchiveWorkaroundDoesNotSatisfyTheLiveAnchor(t *testing.T) {
	ledger.ResetSigning()
	dir := t.TempDir()
	src := writeTwoCapLedger(t, dir)
	snap, _, err := ledger.Rotate(src)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	appendOneMore(t, src, "orders-db", 9000)

	archive := ledger.ArchivePath(src, snap.BaseEvents)
	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("no archive at %s: %v", archive, err)
	}

	// the live (compacted) ledger's anchor — what an operator has off-host
	live, err := ledger.ReplayFile(src)
	if err != nil {
		t.Fatal(err)
	}
	anchorPath := filepath.Join(dir, "anchor.json")
	if err := writeJSON(anchorPath, ledger.BuildAnchor(live)); err != nil {
		t.Fatal(err)
	}

	// capsules emitted from the ARCHIVE, exactly as the refusal advises
	var capsules []string
	for _, cap := range []string{"orders-db", "cache-net"} {
		c, err := ledger.EmitCapsule(archive, cap)
		if err != nil {
			t.Fatalf("the advised workaround does not even emit for %q: %v", cap, err)
		}
		p := filepath.Join(dir, cap+".archive.capsule.json")
		if err := writeJSON(p, c); err != nil {
			t.Fatal(err)
		}
		capsules = append(capsules, p)
	}

	rrep, rcode := restore.Run(restore.Options{
		Out:          filepath.Join(dir, "restored.jsonl"),
		AnchorPath:   anchorPath,
		CapsulePaths: capsules,
	})
	if rcode == restore.ExitOK {
		t.Fatal("archive-emitted capsules satisfied the live anchor — if that is " +
			"now true, capsule DR after compaction works and both the backup " +
			"refusal and the D313 note must be revisited")
	}
	if len(rrep.Reasons) == 0 || !strings.Contains(rrep.Reasons[0], "anchor pins") {
		t.Errorf("expected a stale-capsule refusal naming the anchor head; got %v",
			rrep.Reasons)
	}
}

// A refused backup must not leave something that LOOKS like a backup. Restore
// already obeys this (it removes the ledger it wrote when the replay refuses);
// backup created the directory and wrote anchor.json before discovering it could
// not emit the capsules, leaving a plausible-looking artifact behind.
func TestRefusedBackupLeavesNoArtifact(t *testing.T) {
	ledger.ResetSigning()
	dir := t.TempDir()
	src := writeTwoCapLedger(t, dir)
	if _, _, err := ledger.Rotate(src); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	out := filepath.Join(dir, "backup")
	rep, code := Run(Options{LedgerPath: src, Out: out})
	if code == ExitOK {
		t.Fatalf("expected a refusal for a compacted ledger, got %+v", rep)
	}
	if _, err := os.Stat(out); err == nil {
		entries, _ := os.ReadDir(out)
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("a REFUSED backup left %s behind containing %v — an operator (or a "+
			"cron job) cannot tell it from a good backup, and restore would only "+
			"discover it during the disaster", out, names)
	}
}
