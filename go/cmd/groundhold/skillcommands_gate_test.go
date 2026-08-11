package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D671. The skills are instructions given to an AGENT, so a step that cannot be
// executed literally is a defect in the same way a broken function is. Measured:
//
//	adopt … --map db=fake:existing-db --discovery discover.json
//	  → "adopt requires an explicit --at (RFC3339 timestamp)"   exit 1
//	converge <contract> <candidate> --ledger L --yes
//	  → "converge requires an explicit --at"                    exit 1   (and no --provider)
//
// Step 5 of `onboard-existing` is that skill's own "never skip" proof of takeover,
// and step 1 of the same file carries both flags — so the file disagreed with
// itself. This gate reads every command in every skill and holds it to the same
// rule the binary enforces, from `timeSensitiveVerbs` rather than from a second
// list that would drift.
func TestEverySkillCommandCarriesTheFlagsItsVerbRequires(t *testing.T) {
	root := repoRootFromCmd(t)
	files, err := filepath.Glob(filepath.Join(root, ".claude", "skills", "*", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 5 {
		t.Fatalf("found %d skills — this gate is measuring nothing (D328)", len(files))
	}
	if len(timeSensitiveVerbs) < 10 {
		t.Fatalf("timeSensitiveVerbs holds %d verbs — the subject collapsed",
			len(timeSensitiveVerbs))
	}

	invocation := regexp.MustCompile(`groundhold(?:-go)?\s+([a-z-]+)`)
	checked := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(filepath.Dir(f))
		// A command may wrap across lines inside one backtick span; join the file's
		// lines and let the span itself delimit the command.
		for _, span := range strings.Split(string(raw), "`") {
			m := invocation.FindStringSubmatch(span)
			if m == nil {
				continue
			}
			verb := m[1]
			if !timeSensitiveVerbs[verb] {
				continue
			}
			flat := strings.Join(strings.Fields(span), " ")
			// A bare `groundhold adopt` in prose is a NAME, not an instruction. A
			// span carrying any flag purports to be runnable, and is held to it.
			if !strings.Contains(flat, "--") {
				continue
			}
			checked++
			if !strings.Contains(flat, "--at") {
				t.Errorf("%s: `%s` — %s requires an explicit --at and the command "+
					"does not carry one, so an agent following this step literally "+
					"gets exit 1", name, flat, verb)
			}
		}
	}
	if checked == 0 {
		t.Error("no skill command named a time-sensitive verb — the extraction " +
			"broke, and a gate that found nothing is not a passing gate")
	}
	t.Logf("checked %d time-sensitive commands across %d skills", checked, len(files))
}
