package detach

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// syncRunner is the hermetic seam: it records the launch args instead of forking
// a real process, so the launcher (registry, entry, log path) is tested without
// OS process management. The fork itself is a seam, not a subject — the child is
// the already-tested foreground path.
type syncRunner struct {
	argv    []string
	logPath string
}

func (s *syncRunner) Start(argv []string, logPath string) (int, error) {
	s.argv, s.logPath = argv, logPath
	return 4242, nil
}

func TestLaunchWritesWriteOncePointer(t *testing.T) {
	td := t.TempDir()
	lp := filepath.Join(td, "l.jsonl")
	r := &syncRunner{}
	e, err := Launch(r, Entry{Handle: "h1", Kind: "apply", LedgerPath: lp, LaunchedAt: "2026-07-11T19:00:00Z"},
		[]string{"apply", "c.yaml", "k.yaml", "p.json", "--ledger", lp})
	if err != nil {
		t.Fatal(err)
	}
	if e.PID != 4242 {
		t.Fatalf("pid = %d, want the runner's 4242", e.PID)
	}
	// the child got the argv verbatim + the resolved log path
	if r.logPath != filepath.Join(td, ".groundhold", "runs", "h1.log") {
		t.Fatalf("log path = %q", r.logPath)
	}
	if strings.Contains(strings.Join(r.argv, " "), "--detach") {
		t.Fatal("the child argv must not carry --detach (caller strips it)")
	}

	// registry pointer exists and is a POINTER ONLY — no derivable run state.
	regPath := filepath.Join(td, ".groundhold", "runs", "h1.json")
	raw, err := os.ReadFile(regPath)
	if err != nil {
		t.Fatalf("registry not written: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["handle"] != "h1" || m["kind"] != "apply" || m["ledgerPath"] != lp {
		t.Fatalf("registry entry wrong: %v", m)
	}
	// the invariant: nothing the ledger can answer may live here.
	for _, forbidden := range []string{"state", "outcome", "live", "converged", "exitCode"} {
		if _, present := m[forbidden]; present {
			t.Fatalf("registry leaked a ledger-derivable field %q — it must be a pointer only", forbidden)
		}
	}
	// 0600: the pointer names a ledger path, keep it operator-private.
	fi, _ := os.Stat(regPath)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("registry perms = %o, want 600", fi.Mode().Perm())
	}
}
