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

// D805. Two drivers state an invariant in a comment and nothing checks it:
//
//	"every mutable path here is wired in updateConsumptionBudget
//	 (invariant: mutable-with-an-updater, never a false claim)"
//
// It matters because of what `mutable` MEANS to the compiler. A classifier answering
// "mutable" for an attribute promises the change can be honoured in place, so the plan
// carries an update action instead of a replacement. If the updater then has nothing to
// do with that attribute, the apply reports a change it did not make: the receipt says
// applied, the estate is untouched, and the next observe reads the old value — a drift
// the tool created by claiming to have removed one.
//
// An updater satisfies the promise in one of TWO ways, and both are legitimate:
//
//	rebuild   it calls its own Build* with the new attrs and sends the whole desired
//	          state, so every attribute lands without a per-path branch;
//	branch    it names the path and does something specific with it.
//
// A third shape — neither rebuilding nor naming the path — is the false claim. Today
// every one of the pairs is in the first two, so this gate has no exception list; it
// exists to keep the third from appearing quietly.
//
// A note on how this is measured, because measuring it wrongly is easy and I did it
// twice: a regex over case bodies read `"immutable"` as containing `"mutable"`, and a
// second regex assumed two tabs of indentation where the files use one, which merged
// every case into a single block and attributed every path to every verdict. Both
// produced confident lists of defects that were not there. Reading the AST is not
// fussiness here — it is the difference between measuring the code and measuring a
// guess about its formatting.
func TestEveryMutablePathHasAnUpdaterThatCouldApplyIt(t *testing.T) {
	root := repoRoot(t)

	type key struct{ pkg, service string }
	mutablePaths := map[key]map[string]bool{}
	updaterBody := map[key]string{}
	updaterRebuilds := map[key]bool{}

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
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				switch {
				case strings.HasPrefix(fn.Name.Name, "classify") && strings.HasSuffix(fn.Name.Name, "Change"):
					k := key{pkg, strings.TrimSuffix(strings.TrimPrefix(fn.Name.Name, "classify"), "Change")}
					for p := range mutableCases(fn) {
						if mutablePaths[k] == nil {
							mutablePaths[k] = map[string]bool{}
						}
						mutablePaths[k][p] = true
					}
				case strings.HasPrefix(fn.Name.Name, "update"):
					k := key{pkg, strings.TrimPrefix(fn.Name.Name, "update")}
					updaterBody[k] = string(src[fn.Pos()-1 : fn.End()-1])
					ast.Inspect(fn.Body, func(n ast.Node) bool {
						call, ok := n.(*ast.CallExpr)
						if !ok {
							return true
						}
						if id, ok := call.Fun.(*ast.Ident); ok && strings.HasPrefix(id.Name, "Build") {
							updaterRebuilds[k] = true
						}
						return true
					})
				}
			}
		}
	}

	pairs := 0
	var unwired []string
	for k, paths := range mutablePaths {
		body, ok := updaterBody[k]
		if !ok {
			continue // no updater of that name: a different gate's subject
		}
		pairs++
		if updaterRebuilds[k] {
			continue // sends the whole desired state; every attribute lands
		}
		for p := range paths {
			if !strings.Contains(body, `"`+p+`"`) {
				unwired = append(unwired, k.pkg+"/"+k.service+": "+p)
			}
		}
	}

	// A gate with no subject reports a clean sweep over nothing (D328).
	if pairs < 20 {
		t.Fatalf("only %d classify/update pairs found — the drivers carry far more; "+
			"the scan is broken", pairs)
	}
	sort.Strings(unwired)
	if len(unwired) > 0 {
		t.Errorf("%d path(s) classified MUTABLE whose updater neither rebuilds from "+
			"attrs nor mentions them:\n  %s\n\n`mutable` tells the compiler to plan an "+
			"update instead of a replacement. An updater that does nothing with the "+
			"attribute makes apply report a change it did not make (D805).",
			len(unwired), strings.Join(unwired, "\n  "))
	}
}

// mutableCases returns the attribute paths a classifier answers "mutable" for.
func mutableCases(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		cc, ok := n.(*ast.CaseClause)
		if !ok {
			return true
		}
		mutable := false
		ast.Inspect(cc, func(x ast.Node) bool {
			ret, ok := x.(*ast.ReturnStmt)
			if !ok || len(ret.Results) == 0 {
				return true
			}
			lit, ok := ret.Results[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if v, err := strconv.Unquote(lit.Value); err == nil && v == "mutable" {
				mutable = true
			}
			return true
		})
		if !mutable {
			return true
		}
		for _, e := range cc.List {
			if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if v, err := strconv.Unquote(lit.Value); err == nil {
					out[v] = true
				}
			}
		}
		return true
	})
	return out
}
