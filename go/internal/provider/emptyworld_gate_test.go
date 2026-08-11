package provider_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// D802. An observer has exactly three honest endings: observations, an error, or the
// absence marker. There is a fourth ending that looks like the first and means nothing:
//
//	return nil, []string{"... not found — nothing to observe"}, nil
//
// No observations, no error. The ledger keeps observations latest-per-path, so the last
// good reading of a resource that has since been DELETED stays the freshest word about
// it: `service.managed: true`, every hard verdict `satisfied`, posture `managed-ok`,
// converge with nothing to do. The tool reports a compliant, managed resource that does
// not exist.
//
// That is why `resource.absent` exists (D513/D518/D522), and 135 of 143 observers already
// emitted it. The eight that did not were load balancers on all three clouds, two budgets,
// a backup policy and a workload-identity binding — every one of them the OWNER of a
// binding, which is exactly where the silence costs something.
//
// The gate needs no exception list, and that is worth stating: a facet observer (blob
// immutability, an egress road) returns observations or an error, never an empty success,
// because its subject's absence is its OWNER's to report. So the rule is flat — no
// observer may return "nothing, and nothing went wrong".
func TestNoObserverReturnsAnEmptyWorld(t *testing.T) {
	root := repoRoot(t)
	observers := 0
	var offenders []string

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
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || !strings.HasPrefix(fn.Name.Name, "observe") || fn.Body == nil {
					continue
				}
				observers++
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					ret, ok := n.(*ast.ReturnStmt)
					if !ok || len(ret.Results) != 3 {
						return true
					}
					// (nil | empty slice literal), anything, nil  —  an empty success.
					if !isNilOrEmptyObservations(ret.Results[0]) || !isNilIdent(ret.Results[2]) {
						return true
					}
					offenders = append(offenders, pkg+"/"+name+": "+fn.Name.Name)
					return false
				})
			}
		}
	}

	// A gate with no subject reports a clean sweep over nothing (D328).
	if observers < 100 {
		t.Fatalf("found %d observers — the drivers carry far more; the scan is broken", observers)
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("%d observer(s) return no observations and no error:\n  %s\n\nAn absence "+
			"that says nothing leaves the last good reading standing as the freshest word "+
			"about a resource that may be GONE — posture reads managed-ok and audit stays "+
			"satisfied. Emit provider.ResourceAbsentPath for an authoritative 404, or "+
			"return the error that explains why nothing could be read (D802).",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}

func isNilIdent(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "nil"
}

// isNilOrEmptyObservations reports whether the first return value carries no observation
// at all — `nil`, or a composite literal with no elements.
func isNilOrEmptyObservations(e ast.Expr) bool {
	if isNilIdent(e) {
		return true
	}
	lit, ok := e.(*ast.CompositeLit)
	return ok && len(lit.Elts) == 0
}
