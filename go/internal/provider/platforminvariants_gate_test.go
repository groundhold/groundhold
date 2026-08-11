package provider_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// D799. `platform-invariant` is the strongest thing a driver can say. The other two
// derivations are about THIS resource — measured means we read it, config-intent means
// somebody asked for it. This one is about the SERVICE: it says the value cannot be
// otherwise, so nothing needs reading and nothing can drift.
//
// That makes it the only derivation that can be false while the code is working
// perfectly, and two of the forty-eight were:
//
//	dynamodb  availability.class "regional"   — until the table is a Global Table
//	firestore availability.class "regional"   — until the location is nam5 or eur3
//
// Both were claims about DATA PLACEMENT, which is what residency is, so both let an
// EU-only contract verify against an estate holding copies of its rows elsewhere.
//
// A claim like this cannot be checked by reading our code, because our code is not the
// authority on what the platform permits — the provider is. So the gate does the one
// thing it can: it pins the SET. Every platform-invariant claim in the drivers must
// appear in a checked-in list of claims that were confronted with the provider's own
// description. A new one fails here, and the failure is the review request.
func TestEveryPlatformInvariantClaimHasBeenAudited(t *testing.T) {
	root := repoRoot(t)

	found := map[string]string{} // "file|attr|value" -> file, for the message
	for _, pkg := range []string{"aws", "gcp", "azure", "k8s"} {
		dir := filepath.Join(root, "go", "internal", pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				var attr, value, derivation string
				for _, el := range lit.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok {
						continue
					}
					text := exprText(kv.Value)
					switch key.Name {
					case "Path":
						attr = unquoted(kv.Value)
					case "Value":
						value = text
					case "Derivation":
						derivation = unquoted(kv.Value)
					}
				}
				if derivation != "platform-invariant" || attr == "" {
					return true
				}
				found[pkg+"/"+name+"|"+attr+"|"+value] = pkg + "/" + name
				return true
			})
		}
	}

	audited := map[string]bool{}
	blob, err := os.ReadFile(filepath.Join("testdata", "platform_invariants.audited"))
	if err != nil {
		t.Fatalf("read audited list: %v", err)
	}
	for _, line := range strings.Split(string(blob), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		audited[line] = true
	}

	// A gate with no subject reports a clean sweep over nothing (D328).
	if len(found) < 30 || len(audited) < 30 {
		t.Fatalf("found %d claim(s) in the drivers and %d in the list — one of the two "+
			"sides stopped working", len(found), len(audited))
	}

	var unreviewed, stale []string
	for claim := range found {
		if !audited[claim] {
			unreviewed = append(unreviewed, claim)
		}
	}
	for claim := range audited {
		if _, ok := found[claim]; !ok {
			stale = append(stale, claim)
		}
	}
	sort.Strings(unreviewed)
	sort.Strings(stale)

	if len(unreviewed) > 0 {
		t.Errorf("%d platform-invariant claim(s) not in the audited list:\n  %s\n\n"+
			"This derivation says the platform CANNOT be otherwise — a statement about "+
			"the service, which only the provider's own description can settle. Check it "+
			"there, then add the line to testdata/platform_invariants.audited (D799).",
			len(unreviewed), strings.Join(unreviewed, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("%d audited claim(s) no longer made by any driver:\n  %s\n\nDrop them, so "+
			"the list stays a description of the code rather than a memory of it.",
			len(stale), strings.Join(stale, "\n  "))
	}
}

func unquoted(e ast.Expr) string {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return v
}

// exprText renders the value expression the way the audited list stores it: source text
// for a literal, the identifier chain otherwise.
func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Value
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprText(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		var args []string
		for _, a := range v.Args {
			args = append(args, exprText(a))
		}
		return exprText(v.Fun) + "(" + strings.Join(args, ", ") + ")"
	default:
		return "?"
	}
}
