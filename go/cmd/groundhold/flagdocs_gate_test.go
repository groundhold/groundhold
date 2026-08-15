package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// D1110. D1109 derived the per-verb allowed set from the usage block, which made the
// documentation load-bearing in a way it had never been: a flag the switch accepts but
// no usage line names is now refused by EVERY verb. `--allow-plaintext-secret` was
// exactly that. It has existed since D364 — the escape hatch for the plaintext-secret
// warning, on the reasoning that a warning nobody can turn off is one everybody learns
// to ignore — and the only place it was ever written down is a sentence in the design
// record. Not the usage block, not the README, not a spec page. So D1109 disabled it,
// and nothing failed: no test passes it, no example uses it, no CI job exercises it.
// An escape hatch nobody documents is one nobody uses, which is why breaking it was
// silent.
//
// This gate is the other direction from D1109's. That one asks whether a flag the
// operator typed is one the verb reads; this one asks whether a flag the parser accepts
// is one the operator could have known about. Together they close the loop: the switch
// and the usage block must name the same set, so a flag cannot be added to one without
// the other.
func TestEveryFlagTheParserAcceptsIsDocumented(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Every `case "--x":` in the global switch. Reading the AST rather than grepping,
	// so a flag inside a comment or a string cannot pad the set.
	parsed := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		cc, ok := n.(*ast.CaseClause)
		if !ok {
			return true
		}
		for _, e := range cc.List {
			lit, ok := e.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			v, err := strconv.Unquote(lit.Value)
			if err == nil && strings.HasPrefix(v, "--") && len(v) > 2 {
				parsed[v] = true
			}
		}
		return true
	})
	if len(parsed) < 40 {
		t.Fatalf("found %d flags in the parse switch — the AST walk broke, and this "+
			"gate would pass on anything (D328)", len(parsed))
	}

	documented := map[string]bool{}
	for _, f := range regexp.MustCompile(`--[a-z][a-z-]*`).FindAllString(usage, -1) {
		documented[f] = true
	}
	if len(documented) < 40 {
		t.Fatalf("found %d flags in the usage block — the same vacuity problem from "+
			"the other side", len(documented))
	}

	// Sub-parser flags are deliberately absent from the usage block and live in their
	// own registry (D602). Undocumented ON PURPOSE is a different thing from
	// undocumented by omission, and the registry is where that intent is recorded.
	private := map[string]bool{}
	for _, flags := range verbPrivateFlags {
		for _, f := range flags {
			private[f] = true
		}
	}

	var undocumented []string
	for f := range parsed {
		if !documented[f] && !private[f] {
			undocumented = append(undocumented, f)
		}
	}
	sort.Strings(undocumented)
	if len(undocumented) > 0 {
		t.Errorf("the parser accepts these flags and no usage line names them:\n  %s\n\n"+
			"Since D1109 the usage block decides which verb may be given which flag, so "+
			"an undocumented flag is not merely undiscoverable — it is REFUSED by every "+
			"verb. Add it to the lines of the verbs that read it, or register it as a "+
			"private sub-parser flag if it is deliberately internal.",
			strings.Join(undocumented, "\n  "))
	}
}
