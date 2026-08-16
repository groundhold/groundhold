package render

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D1113. spec/presentation.md publishes a table of green words, and the reasoning
// under it is why the table matters: "the green vocabulary stays smaller than the
// failure vocabulary, or success banners become a second API". Four words are
// distinguished — PROVEN, CONVERGED, APPLIED, SEALED — and each makes a specific claim
// about what was established. Everything else says OK.
//
// Nothing bound the table to the runtime. `greenWord` is a switch over four cases with
// `return "OK"` as its default, so a verb joins the OK set by existing, and a verb
// could join a DISTINGUISHED set by one line nobody compared against the spec. That
// second direction is the dangerous one: PROVEN and CONVERGED are epistemic claims —
// "hard constraints satisfied", "reconciliation reached its proven fixed point" — and a
// verb that starts making one without earning it says something false in one word.
//
// The gate reads the published table and requires the distinguished mapping to match
// exactly, in both directions.
func TestDistinguishedGreenWordsMatchTheSpec(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "spec", "presentation.md"))
	if err != nil {
		t.Skipf("no presentation spec here: %v", err)
	}

	// Rows of the green-word table: | `a`, `b` | `WORD` | claim |
	row := regexp.MustCompile("(?m)^\\|([^|]*)\\|\\s*`([A-Z]+)`\\s*\\|")
	published := map[string]string{}
	for _, m := range row.FindAllStringSubmatch(string(raw), -1) {
		word := m[2]
		if word == "OK" {
			// The OK row is a DEFAULT, not a membership list — asserting the names
			// in it would make this gate fail every time a verb is added, which is
			// the opposite of what it is for.
			continue
		}
		for _, v := range regexp.MustCompile("`([a-z][a-z-]*)`").FindAllStringSubmatch(m[1], -1) {
			published[v[1]] = word
		}
	}
	// Name the grant rather than count it. A count lets the spec DROP a row and the
	// gate narrow with it — verified: removing the `plan` row left four verbs, cleared
	// the floor, and stopped anyone noticing that SEALED had become ungranted. The
	// distinguished set is small and deliberate, so it is written here; changing it
	// means editing this line, which is the point.
	want := map[string]string{
		"verify": "PROVEN", "audit": "PROVEN",
		"converge": "CONVERGED", "apply": "APPLIED", "plan": "SEALED",
	}
	for verb, word := range want {
		if published[verb] != word {
			t.Errorf("the spec table no longer grants %s the word %q (it says %q) — "+
				"if that is deliberate, change this gate in the same commit",
				verb, word, published[verb])
		}
	}
	for verb, word := range published {
		if want[verb] != word {
			t.Errorf("the spec table grants %s the distinguished word %q, which this "+
				"gate does not know about — a new epistemic claim needs a deliberate "+
				"line here", verb, word)
		}
	}

	for verb, want := range published {
		if got := greenWord(verb); got != want {
			t.Errorf("spec says %s banners %q; the runtime says %q", verb, want, got)
		}
	}

	// The other direction. A verb that starts claiming PROVEN or CONVERGED without
	// being in the table is the failure this exists to catch, and it cannot be found
	// by walking the spec — only by walking the runtime's own answers.
	distinguished := map[string]bool{}
	for _, w := range published {
		distinguished[w] = true
	}
	var undeclared []string
	for _, verb := range allVerbsFromUsageish() {
		w := greenWord(verb)
		if distinguished[w] && published[verb] != w {
			undeclared = append(undeclared, verb+"→"+w)
		}
	}
	sort.Strings(undeclared)
	if len(undeclared) > 0 {
		t.Errorf("these verbs claim a distinguished green word the spec does not grant "+
			"them:\n  %s\n\nPROVEN and CONVERGED are epistemic claims. A verb that makes "+
			"one without earning it says something false in a single word, and the table "+
			"is where that grant is recorded.", strings.Join(undeclared, "\n  "))
	}
}

// allVerbsFromUsageish is a fixed list rather than a parse of the CLI's usage block:
// this package must not depend on cmd/. It is deliberately WIDER than the spec table —
// the point is to ask the runtime about verbs the table does not mention.
func allVerbsFromUsageish() []string {
	return []string{
		"adopt", "anchor", "apiver", "apply", "attest", "audit", "backup", "capsule",
		"compose", "connections", "converge", "cost", "crawl", "deposed", "diff",
		"discover", "example", "explain", "export", "forecast", "hash", "hints",
		"horizon", "keygen", "mcp", "observe", "pair", "parity", "plan", "posture",
		"preflight", "probe", "publish", "react", "refresh", "repair", "restore",
		"resume", "runs", "scenario", "snapshot", "status", "suggest", "survey",
		"unadopt", "unpair", "validate", "verify", "wait",
	}
}
