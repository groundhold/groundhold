package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"testing"
)

// D631. `timeSensitiveVerbs` is the closed set that gets N1's presence gate (an
// explicit `--at`, never the epoch) and D323's parse gate (PRESENT is not PARSES).
// `discover` was outside it while consuming the clock:
//
//	groundhold discover --provider fake --project p1                 exit 0  at: 1970-01-01T00:00:00Z
//	groundhold discover --provider fake --project p1 --at not-a-time exit 0  at: "not-a-time"
//
// Both permanent: `at` is inside the canonical `discoveryHash`, and
// `adopt --discovery` writes that hash into the ledger as the adoption's provenance
// root — so an adoption cited an enumeration whose recorded time was the string
// "not-a-time". `pair`, the other ungated clock consumer, handles this itself and says
// why (D588: "a record saying 1970 is worse than a record saying nothing"), which is
// how we know the pattern was understood and this verb was simply missed.
//
// The gate is over the RULE: a verb whose dispatch block reads the evaluation clock
// must be in the set. It asks Go's own parser which blocks those are, so a verb added
// later is covered by the rule rather than by whoever remembers it.
func TestEveryVerbThatReadsTheClockIsGated(t *testing.T) {
	if len(timeSensitiveVerbs) < 10 {
		t.Fatalf("the gated set holds %d verbs — the probe broke and this gate would "+
			"pass on anything (D328)", len(timeSensitiveVerbs))
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	// `pair` reads the clock and handles a defaulted one itself, in writing (D588).
	// A deliberate, documented exception — not an omission.
	allowed := map[string]bool{"pair": true}

	seen := 0
	var ungated []string
	ast.Inspect(file, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		bin, ok := ifs.Cond.(*ast.BinaryExpr)
		if !ok || bin.Op != token.EQL {
			return true
		}
		id, ok := bin.X.(*ast.Ident)
		if !ok || id.Name != "cmd" {
			return true
		}
		lit, ok := bin.Y.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		verb, err := strconv.Unquote(lit.Value)
		if err != nil || verb == "" || verb[0] == '-' {
			return true
		}

		readsClock := false
		ast.Inspect(ifs.Body, func(m ast.Node) bool {
			if id, ok := m.(*ast.Ident); ok && id.Name == "evalTime" {
				readsClock = true
			}
			return true
		})
		if !readsClock {
			return true
		}
		seen++
		if !timeSensitiveVerbs[verb] && !allowed[verb] {
			ungated = append(ungated, verb)
		}
		return true
	})

	if seen == 0 {
		t.Fatal("no dispatch block was seen consuming evalTime — the parse broke and " +
			"this gate would pass over anything (D328)")
	}
	sort.Strings(ungated)
	if len(ungated) > 0 {
		t.Errorf("these verbs read the evaluation clock and are not in "+
			"timeSensitiveVerbs: %v\n"+
			"Outside the set they get neither the presence gate nor the parse gate, so "+
			"the clock silently becomes the epoch — or whatever string was typed — and "+
			"anything derived from it carries that forever.", ungated)
	}
}
