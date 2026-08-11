package ledger

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D708: no caller may fold "I could not read the snapshot" into "there is none".
//
// `LoadSnapshotFile` answers three ways — absent is (nil, nil), unreadable is
// (nil, err), present is (snap, nil). Three of its six callers wrote a two-valued
// test, `err == nil && snap != nil`, and each one lost the third answer somewhere
// that mattered: a backup that reported success and could not restore, an attestation
// that read as "no snapshot", and a run projection that answered "no such run" about
// runs it had simply stopped reading.
//
// The idiom is the defect, and the idiom is greppable. This gate bans it at the call
// site rather than hoping the next author remembers the three-valued shape.
func TestNoCallerFoldsAnUnreadableSnapshotIntoAnAbsentOne(t *testing.T) {
	root := repoRootFromLedger(t)
	goDir := filepath.Join(root, "go")

	// `err == nil &&` / `serr == nil &&` on the same line as the call, or on the
	// continuation line beneath it: the shape that discards the third answer.
	// `.*` rather than `[^)]*`: every real call nests a paren
	// (`LoadSnapshotFile(SnapshotPath(path))`), and the first draft of this pattern
	// stopped at that inner `)` and matched NOTHING. Its positive control passed
	// because the example it checked itself against — `LoadSnapshotFile(p)` — was
	// simpler than any line in the tree. A control that is easier than reality proves
	// the detector can match its own example and nothing else; the one below now uses
	// the shape the code actually has.
	failOpen := regexp.MustCompile(`LoadSnapshotFile\(.*\)\s*;\s*\w*err\s*==\s*nil\s*&&`)
	callers := 0
	var bad []string

	err := filepath.Walk(goDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return err
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		rel, _ := filepath.Rel(root, path)
		// join continuations so a call broken across two lines is still one subject
		joined := strings.ReplaceAll(string(raw), "&&\n\t\t", "&& ")
		joined = strings.ReplaceAll(joined, ";\n\t\t", "; ")
		for i, line := range strings.Split(joined, "\n") {
			if !strings.Contains(line, "LoadSnapshotFile(") ||
				strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			callers++
			if failOpen.MatchString(line) {
				bad = append(bad, rel+":"+itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if callers < 3 {
		t.Fatalf("found %d LoadSnapshotFile call sites — the scan broke and this gate "+
			"would pass over a reintroduced fold (D328)", callers)
	}
	if len(bad) > 0 {
		t.Errorf("call sites that treat an unreadable snapshot as an absent one:\n  %s\n"+
			"Use SnapshotStateOf: absent, present and unreadable are three answers, and "+
			"the third one is the one that costs a restore.", strings.Join(bad, "\n  "))
	}
	// Positive control: the detector must match the shape it bans.
	if !failOpen.MatchString(
		`if snap, err := LoadSnapshotFile(SnapshotPath(path)); err == nil && snap != nil {`) {
		t.Fatal("the detector cannot match its own example — it is not running")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func repoRootFromLedger(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "Makefile")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("no Makefile above this directory")
	return ""
}

// D710: an integrity pin is written or the operation refuses — never omitted quietly.
//
// `CheckAnchor` compares the snapshot pin only when it is NON-EMPTY, so an anchor
// written without one carries no swap detection at all: it still catches a rewritten
// tail, and says nothing about a fold replaced underneath it. Compaction used to write
// exactly that anchor whenever `HashSnapshot` failed —
//
//	if h, err := HashSnapshot(doc); err == nil { anchor.SnapshotHash = h }
//
// — two lines under a comment promising "pinning the fold hash so a swapped snapshot
// is detectable", and twenty lines under `previousSnapshotHash`, whose own comment
// says "never swallow: it must be honest". One file, one kind of pin, two readings.
//
// The gate holds the shape rather than the outcome: no `HashSnapshot` call may sit
// behind an `err == nil` test.
func TestNoIntegrityPinIsWrittenBestEffort(t *testing.T) {
	root := repoRootFromLedger(t)
	dir := filepath.Join(root, "go", "internal", "ledger")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	failOpen := regexp.MustCompile(`HashSnapshot\(.*\)\s*;\s*\w*err\s*==\s*nil`)
	calls := 0
	var bad []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatal(rerr)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if !strings.Contains(line, "HashSnapshot(") ||
				strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			calls++
			if failOpen.MatchString(line) {
				bad = append(bad, e.Name()+":"+itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
	}
	if calls < 2 {
		t.Fatalf("found %d HashSnapshot call sites — the scan broke (D328)", calls)
	}
	if len(bad) > 0 {
		t.Errorf("integrity pins written best-effort:\n  %s\n"+
			"A pin that omits itself on failure leaves a check that silently does not "+
			"run; refuse instead, the way previousSnapshotHash does.",
			strings.Join(bad, "\n  "))
	}
	if !failOpen.MatchString(`if h, err := HashSnapshot(doc); err == nil {`) {
		t.Fatal("the detector cannot match its own example — it is not running")
	}
}

// D711: the recovery verb must never leave the ledger path empty.
//
// Quarantine used to rename the history aside and then rename the prefix in, which
// leaves NO FILE at the ledger path between the two renames. A missing ledger replays
// as an EMPTY one — deliberately, so a first converge can create one — so a crash in
// that window hands the next converge an empty history for a full estate: every
// capability unbound, every action a create. D253 named that cost: "a second VPC, a
// second paid key, and neither one in the ledger". Produced by the verb whose whole
// job is to recover from corruption.
//
// The end state is checked below, and it is NOT enough on its own: with either
// ordering the files are all in place once the function returns, so the first draft of
// this test passed against the very rename it was written to forbid. The property
// lives in the WINDOW, which a test cannot observe without a fault hook — so the shape
// that creates the window is banned instead, in TestQuarantineMovesHistoryByLinking.
func TestQuarantineNeverLeavesTheLedgerPathEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l.jsonl")

	// two good lines and one that is not JSON at all
	good := `{"kind":"x"}` + "\n" + `{"kind":"y"}` + "\n"
	if err := os.WriteFile(path, []byte(good+"not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Diagnose(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != "corrupt" {
		t.Skipf("fixture did not produce a corrupt diagnosis (%s) — nothing to cut", d.Status)
	}
	res, _, err := Quarantine(path, d.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "repaired" {
		t.Fatalf("status %q, reasons %v", res.Status, res.Reasons)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the ledger path does not exist after a repair (%v) — the next "+
			"converge would replay an EMPTY history and plan a create for every "+
			"capability already standing", err)
	}
	kept, err := os.ReadFile(res.QuarantinedTo)
	if err != nil {
		t.Fatalf("the preserved history is unreadable: %v", err)
	}
	if !strings.Contains(string(kept), "not json") {
		t.Error("the quarantined copy does not hold the cut lines — the history was " +
			"not preserved, it was destroyed")
	}
}

// D711: the ledger path may never be the SOURCE of a rename in the repair path.
//
// That is the property the end-state test cannot see. `os.Rename(path, qpath)` empties
// the path for as long as it takes to rename the prefix in; `os.Link(path, qpath)`
// leaves the original where it is and the later rename swaps atomically over it. The
// difference is invisible after the fact and total during a crash.
func TestQuarantineMovesHistoryByLinking(t *testing.T) {
	root := repoRootFromLedger(t)
	raw, err := os.ReadFile(filepath.Join(root, "go", "internal", "ledger", "repair.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if !strings.Contains(src, "os.Link(path, qpath)") {
		t.Error("the history is not preserved by LINKING — if it is renamed aside, the " +
			"ledger path is empty until the prefix lands, and a crash there hands the " +
			"next converge an empty history for a full estate")
	}
	if strings.Contains(src, "os.Rename(path, qpath)") {
		t.Error("os.Rename(path, qpath) empties the ledger path — use os.Link so the " +
			"path always has a file")
	}
	// Positive control: the detector must be able to see the banned shape.
	if !strings.Contains(`if err := os.Rename(path, qpath); err != nil {`, "os.Rename(path, qpath)") {
		t.Fatal("the detector cannot match its own example — it is not running")
	}
}
