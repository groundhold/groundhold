package runstatus

import (
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/ledger"
)

// D672. After a `snapshot` every run vanished: `ReadEvents` read the live file
// alone. Measured against the binary — a converge that had printed CONVERGED read
// `done` before the compaction and `unknown` after it, `runs` returned
// `{"runs":[],"total":0}`, and `wait` blocked its full timeout and exited 3, the
// reconcile-required code whose published remediation is `groundhold resume`.
//
// `ListRuns`'s own doc-comment says a run whose start event was compacted "reads
// unknown and sorts last, never dropped". It was dropped, and compaction is the
// routine operation this design recommends.
func TestARunSurvivesACompaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	const handle = "abc123abc123"
	w := &ledger.Writer{Path: path, Led: led, Env: "test", Clock: 1767225600, Actor: "t"}
	tok, err := w.AppendLease([]string{"db"}, map[string]any{"ttlSeconds": 900})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []struct {
		typ  string
		body map[string]any
	}{
		{"apply.started", map[string]any{"applyRunId": handle, "plan": "sha256:p"}},
		{"apply.finished", map[string]any{"applyRunId": handle, "exitCode": 0}},
	} {
		if err := w.Append(ev.typ, []string{"db"}, ev.body, tok); err != nil {
			t.Fatal(err)
		}
	}

	before, _, err := ReadEventsFull(path)
	if err != nil {
		t.Fatal(err)
	}
	if s := DeriveRunStatus(before, handle, 1767225600+10000); s.State != StateDone {
		t.Fatalf("the fixture is wrong: state=%s before any compaction", s.State)
	}

	if _, _, err := ledger.Rotate(path); err != nil {
		t.Fatal(err)
	}

	after, note, err := ReadEventsFull(path)
	if err != nil {
		t.Fatalf("reading a compacted ledger: %v", err)
	}
	if note != "" {
		t.Errorf("an intact compaction reported a shortfall: %s", note)
	}
	s := DeriveRunStatus(after, handle, 1767225600+10000)
	if s.State != StateDone {
		t.Errorf("after a compaction the run reads %q — a successful deploy becomes "+
			"`unknown`, and `wait` on it blocks to its timeout and exits 3 telling "+
			"the operator to run `resume`", s.State)
	}
	if runs := ListRuns(after, 1767225600+10000, nil); len(runs) == 0 {
		t.Error("`runs` lists nothing after a compaction")
	}
}

// A pruned archive must not make a reporting verb unusable — spec §10 leaves
// pruning to the operator. The answer is "here is what I can see, and here is what
// I cannot", never a silent short list and never a permanent refusal.
func TestAPrunedArchiveIsReportedNotRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	w := &ledger.Writer{Path: path, Led: led, Env: "test", Clock: 1767225600, Actor: "t"}
	if err := w.Append("contract.published", []string{"db"},
		map[string]any{"contractHash": "sha256:a", "version": 1}, 0); err != nil {
		t.Fatal(err)
	}
	snap, _, err := ledger.Rotate(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ledger.ArchivePath(path, snap.BaseEvents)); err != nil {
		t.Fatal(err)
	}

	_, note, err := ReadEventsFull(path)
	if err != nil {
		t.Fatalf("a pruned archive must not make `runs` unusable: %v", err)
	}
	if note == "" {
		t.Error("the missing history was not reported — an incomplete answer that " +
			"does not say it is incomplete is the defect this fixes")
	}
}

// D676. Leases are PER-CAPABILITY. The fold ended the queried run's lease on ANY
// run's `lease.released`, with the comment "leases are serialized". Measured with
// the real binary: two converges over disjoint capabilities in one ledger, both
// exit 0, both leases live at once — and the moment `assets` released, the still
// running `db` run read `stalled`, remediation "the writer's lease lapsed with no
// outcome — run `groundhold resume`". A healthy in-flight run reported dead.
func TestAnotherRunsReleaseDoesNotEndThisRunsLease(t *testing.T) {
	const mine = "mine00000000"
	evs := []RunEvent{
		{Type: "apply.started", Clock: 100, Caps: []string{"db"},
			Body: map[string]any{"applyRunId": mine}},
		{Type: "lease.acquired", Clock: 100, Caps: []string{"db"},
			Body: map[string]any{"applyRunId": mine, "ttlSeconds": 900}},
		// A different run, over a different capability, finishing its own work.
		{Type: "lease.acquired", Clock: 110, Caps: []string{"assets"},
			Body: map[string]any{"applyRunId": "other0000000", "ttlSeconds": 900}},
		{Type: "lease.released", Clock: 120, Caps: []string{"assets"}},
	}
	s := DeriveRunStatus(evs, mine, 200) // 200 < 100+900: our lease is live
	if s.State != StateRunning || !s.Lease.Live {
		t.Errorf("state=%s leaseLive=%v — another run released ITS lease and this "+
			"one was reported dead, with the remediation %q",
			s.State, s.Lease.Live, s.Remediation)
	}

	// The control: our OWN release must still end it, or `stalled` and `done` stop
	// being reachable at all.
	evs = append(evs, RunEvent{Type: "lease.released", Clock: 130, Caps: []string{"db"}})
	if s := DeriveRunStatus(evs, mine, 200); s.Lease.Live {
		t.Error("this run's own lease release did not end its lease")
	}
}
