package perr

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D730. Every machine error code carries a remediation, and a remediation that names a
// verb the binary does not have is worse than none: it sends the reader looking for
// something that was never there. Measured cost, from the field — a quarter of an hour
// spent searching a fifty-item verb list for `retire`, which is a CONTRACT state, not a
// verb, and which the advice never mentioned.
//
// The gate reads the CLI's own verb set out of main.go and requires every backticked or
// `groundhold X`-shaped token in a remediation to be one of them. It is over source
// because the remediation table and the verb list live in different packages, and the
// only thing that can drift is the relationship between them.
func TestRemediationsOnlyNameVerbsTheBinaryHas(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "go", "cmd", "groundhold", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	// The verb set as main.go spells it: `case "plan":` / `cmd == "plan"`.
	verbs := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?:case|cmd ==) "([a-z][a-z-]+)"`).FindAllSubmatch(raw, -1) {
		verbs[string(m[1])] = true
	}
	if len(verbs) < 20 {
		t.Fatalf("only %d verbs found in main.go — the gate lost its subject and would "+
			"pass over any advice at all", len(verbs))
	}

	// Tokens that look like an instruction to run something.
	cited := regexp.MustCompile("`groundhold ([a-z][a-z-]+)|`([a-z][a-z-]+)`")
	for code, r := range Explain {
		for _, m := range cited.FindAllStringSubmatch(r.Remediation, -1) {
			tok := m[1]
			if tok == "" {
				tok = m[2]
			}
			// Only judge tokens that LOOK like verbs; a backticked flag or field is not.
			if strings.Contains(tok, ":") || strings.HasPrefix(tok, "-") {
				continue
			}
			if !verbs[tok] && !knownNonVerb[tok] {
				t.Errorf("%s: the remediation names `%s`, which is not a verb this binary "+
					"has — advice that cannot be followed costs more than silence (D730)",
					code, tok)
			}
		}
	}
}

// knownNonVerb are backticked words in remediations that are deliberately not verbs
// (contract fields, states, file names). Listing them is what keeps the check above
// honest rather than approximate.
var knownNonVerb = map[string]bool{
	"state": true, "retired": true, "true": true, "false": true,
}
