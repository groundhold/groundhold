package perr

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D764, the flag twin of D730's verb gate and of D763's operand gate. A message that
// names `--something` is teaching the reader a next step, and the binary either parses
// that flag or it does not. `RunRunning` said "`wait --handle` blocks until it concludes"
// — wait takes its handle POSITIONALLY, so the one remediation for a live run pointed at
// a flag that does not exist.
//
// Two citations are legitimate and are named here rather than smuggled past a looser
// pattern: one message says a verb HAS NO `--no-check` (citing a flag's absence is the
// opposite of routing at it), and one prints an AWS CLI command whose `--profile` belongs
// to a different binary entirely.
func TestNoMessageRoutesAtAFlagTheBinaryDoesNotParse(t *testing.T) {
	root := repoRoot(t)
	legitimate := map[string]bool{
		"--no-check": true, // cited to say restore has none
		"--profile":  true, // `aws configure export-credentials --profile` — not ours
	}

	// The flags main.go parses, however it spells the parsing.
	cliRaw, err := os.ReadFile(filepath.Join(root, "go", "cmd", "groundhold", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	flagRe := regexp.MustCompile(`"(--[a-z][a-z0-9-]*)"`)
	defined := map[string]bool{}
	for _, m := range flagRe.FindAllStringSubmatch(string(cliRaw), -1) {
		defined[m[1]] = true
	}
	if len(defined) < 40 {
		t.Fatalf("only %d flags found in main.go — the gate has lost its subject (D328)", len(defined))
	}

	strLit := regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
	var bad []string
	checked := 0
	err = filepath.Walk(filepath.Join(root, "go"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") ||
			strings.HasSuffix(p, "_test.go") {
			return nil
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		bare := regexp.MustCompile(`--[a-z][a-z0-9-]*`)
		for _, lit := range strLit.FindAllStringSubmatch(string(raw), -1) {
			for _, f := range bare.FindAllString(lit[1], -1) {
				checked++
				if defined[f] || legitimate[f] {
					continue
				}
				rel, _ := filepath.Rel(root, p)
				bad = append(bad, f+" ("+rel+")")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("%d message(s) name a flag this binary does not parse:\n  %s\n\n"+
			"Teaching the next action is the job; a flag that does not exist is worse "+
			"than no advice, because it reads as authoritative (D764).",
			len(bad), strings.Join(bad, "\n  "))
	}
	t.Logf("%d flag citations checked against %d parsed flags", checked, len(defined))
}
