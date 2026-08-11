package perr

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D730, the wider half. Teaching the caller — a person or an agent — what to do next is
// a FOUNDING requirement of this CLI, not a courtesy: a probabilistic author is steered
// by deterministic refusals, and a refusal that routes at nothing steers it into a loop
// or into the wrong action. A pilot lost a quarter of an hour to one such sentence, and
// the sentence was not in the error table — it was inline in a driver.
//
// So the gate covers EVERY user-facing string in the tree, not the table alone: any
// backticked token shaped like a command must be a command this binary dispatches.
func TestNoUserFacingTextRoutesAtAVerbThatDoesNotExist(t *testing.T) {
	root := repoRoot(t)
	mainRaw, err := os.ReadFile(filepath.Join(root, "go", "cmd", "groundhold", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	verbs := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?:case|cmd ==) "([a-z][a-z-]+)"`).FindAllSubmatch(mainRaw, -1) {
		verbs[string(m[1])] = true
	}
	if len(verbs) < 20 {
		t.Fatalf("only %d verbs found — the gate lost its subject", len(verbs))
	}

	// The convention this gate enforces: routing advice names the action IN BACKTICKS.
	// Free prose cannot be checked — "retire or delete a created resource", the sentence
	// that cost a pilot a quarter of an hour, names a verb with no marker at all — so
	// the convention is what makes the class machine-visible, and the gate is what makes
	// the convention real.
	cited := regexp.MustCompile("`(?:groundhold )?([a-z][a-z-]+)[` ]")
	var files []string
	for _, dir := range []string{"go/internal", "go/cmd"} {
		_ = filepath.Walk(filepath.Join(root, dir), func(p string, fi os.FileInfo, e error) error {
			if e == nil && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				files = append(files, p)
			}
			return nil
		})
	}
	if len(files) < 100 {
		t.Fatalf("only %d source files walked — the gate lost its subject", len(files))
	}

	checked := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			// Only STRINGS reach a caller; a comment explaining the design does not.
			if !strings.Contains(line, `"`) {
				continue
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			for _, m := range cited.FindAllStringSubmatch(line, -1) {
				tok := m[1]
				if knownNonVerb[tok] || !looksLikeAVerb[tok] {
					continue // a backticked field, flag or value is not routing
				}
				checked++
				if !verbs[tok] {
					t.Errorf("%s: a message routes the caller at `%s`, which this binary "+
						"does not dispatch — teaching the next action is the job, and a "+
						"door that does not exist is worse than none (D730)",
						strings.TrimPrefix(f, root+"/"), tok)
				}
			}
		}
	}
	// D328: the sweep must have found something to judge, or a refactor that changes
	// how advice is written turns this into a gate over nothing.
	if checked < 5 {
		t.Fatalf("only %d routing citations examined across %d files — this project's "+
			"refusals are supposed to name the next action", checked, len(files))
	}
	t.Logf("checked %d routing citations across %d source files", checked, len(files))
}

// looksLikeAVerb is the closed set of words that would be READ as a groundhold command
// if they appeared backticked in advice — the real verbs plus the plausible ones this
// project has been asked for and does not have. A word outside it is not routing.
// Keeping it closed is what stops the gate from judging prose (D730).
var looksLikeAVerb = map[string]bool{
	"plan": true, "apply": true, "verify": true, "validate": true, "observe": true,
	"audit": true, "probe": true, "converge": true, "adopt": true, "unadopt": true,
	"discover": true, "hints": true, "resume": true, "repair": true, "refresh": true,
	"deposed": true, "attest": true, "capsule": true, "anchor": true, "export": true,
	"forecast": true, "explain": true, "status": true, "runs": true, "cost": true,
	"keygen": true, "hash": true, "scenario": true, "mcp": true, "survey": true,
	"suggest": true, "preflight": true, "posture": true, "retire": true, "delete": true,
	"destroy": true, "rollback": true, "import": true, "diff": true, "drift": true,
}
