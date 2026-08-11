package detach

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D678. The registry exists to surface a run the LEDGER cannot see — its own
// comment calls "launched but never admitted" the most attention-worthy condition
// here. A pointer it could not read was skipped with `continue`, so exactly the
// artefact whose unreadability is the news vanished. Measured: a truncated pointer
// and one at mode 000 both disappeared with no diagnostic, and two files naming one
// handle were listed twice, colliding for any caller keying by handle.
func TestAnUnreadableOrDuplicatePointerIsReported(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "l.jsonl")
	if err := os.WriteFile(ledger, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runs := runsDir(ledger)
	if err := os.MkdirAll(runs, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(runs, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("good00000001.json", `{"handle":"good00000001","kind":"apply",
	  "ledgerPath":"`+ledger+`","logPath":"/tmp/x.log","pid":1,"launchedAt":"2026-01-01T00:00:00Z"}`)
	write("torn00000002.json", `{"handle":"torn0000`) // truncated mid-write
	// A pointer that cannot be READ at all: a dangling symlink is the reliable
	// shape (chmod 000 is not, when the suite runs as root).
	if err := os.Symlink(filepath.Join(dir, "gone"),
		filepath.Join(runs, "dead00000004.json")); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}
	write("dupA00000003.json", `{"handle":"dup000000003","kind":"apply",
	  "ledgerPath":"`+ledger+`","logPath":"/tmp/a.log","pid":2,"launchedAt":"2026-01-01T00:00:00Z"}`)
	write("dupB00000003.json", `{"handle":"dup000000003","kind":"apply",
	  "ledgerPath":"`+ledger+`","logPath":"/tmp/b.log","pid":3,"launchedAt":"2026-01-01T00:00:00Z"}`)

	ents, err := ListRegistry(ledger)
	if err != nil {
		t.Fatal(err)
	}
	byHandle := map[string]Entry{}
	unreadable, dupes := 0, 0
	for _, e := range ents {
		if e.Unreadable != "" {
			unreadable++
			if strings.Contains(e.Unreadable, "second registry pointer") {
				dupes++
			}
		}
		byHandle[e.Handle] = e
	}
	if unreadable < 3 {
		t.Errorf("the unreadable pointer, the torn one and the duplicate were not "+
			"all three reported: %+v", ents)
	}
	var sawReadFailure bool
	for _, e := range ents {
		if strings.Contains(e.Unreadable, "no such file") ||
			strings.Contains(e.Unreadable, "cannot") {
			sawReadFailure = true
		}
	}
	if !sawReadFailure {
		t.Errorf("a pointer that could not be READ carries no reason: %+v", ents)
	}
	if dupes != 1 {
		t.Errorf("the duplicate handle was not named: %+v", ents)
	}
	if _, ok := byHandle["good00000001"]; !ok {
		t.Error("the healthy pointer was lost")
	}
	if len(ents) != 5 {
		t.Errorf("listed %d entries, want 5 — nothing may vanish silently", len(ents))
	}
}
