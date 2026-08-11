package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/detach"
)

// D679. "did not start" is a claim about a PROCESS, and nothing looked at the
// process. Measured: with the ledger lock held by another writer, the child was
// alive and blocked; the launcher printed "run did not start within 5s", exited 1 —
// and the run woke up later and created the infrastructure. The tool said it had
// not started; the run then acted. The registry has stored a `pid` all along and
// nothing ever read it.
//
// This gate reads the source, and says why: the failure needs a real fork blocked
// on a real lock for five seconds, which is not a test this suite should carry. The
// aliveness check itself is one syscall and is pinned as present, with the verdict
// text held to saying different things for the two cases.
func TestTheLauncherAsksWhetherTheProcessIsAlive(t *testing.T) {
	e := detach.Entry{Handle: "h", PID: 4242, LogPath: "/tmp/run.log"}

	code, msg := detachVerdict("h", "/tmp/l.jsonl", e, true)
	if code != 0 {
		t.Errorf("a live run that is merely slow to reach admission exits %d — "+
			"nothing has failed, and a caller routing on the code tears down a run "+
			"that is about to do its work", code)
	}
	if !strings.Contains(msg, "STILL") || !strings.Contains(msg, "4242") {
		t.Errorf("the live case does not say the process is running, or does not "+
			"name it: %q", msg)
	}

	deadCode, deadMsg := detachVerdict("h", "/tmp/l.jsonl", e, false)
	if deadCode == 0 {
		t.Error("a run whose process is gone must fail the command")
	}
	if deadMsg == msg {
		t.Error("a live run and a dead one get the same sentence — which is the " +
			"defect: the tool said `did not start` and the run then created the " +
			"infrastructure")
	}

	// And the wiring: the verdict must be handed the answer to the question it
	// asserts, from the pid the registry has stored all along.
	raw, err := os.ReadFile(filepath.Join(repoRootFromCmd(t), "go", "cmd",
		"groundhold", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "detachVerdict(handle, ledgerPath, e, processAlive(e.PID))") {
		t.Error("the launcher no longer asks whether the process exists")
	}
}
