package provider_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// D1131. Twenty gates skip in the published copy, and each prints one sentence
// explaining why. That sentence said the tree was detected by having no `.git` —
// the mechanism D661 REMOVED, for the precise reason that the publication target
// is a clone and therefore HAS one. So the message named the wrong cause in the
// one situation where somebody reads it: a gate did not run, and they want to know
// whether that was deliberate.
//
// It is the shape this session keeps finding, at its smallest: prose describing a
// mechanism that was replaced, sitting beside the replacement. Here the two were
// fifteen lines apart in one file, and the comment on the replacement says in as
// many words that reading `.git` was wrong.
//
// The gate derives the marker from the predicate rather than repeating it, so the
// message cannot drift from the mechanism a second time.
func TestTheSkipReasonNamesWhatActuallyDetectsTheExport(t *testing.T) {
	path := filepath.Join(repoRoot(t), "go", "internal", "provider", "exportedtree_test.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("cannot parse the export-detection source: %v", err)
	}

	bodies := map[string]*ast.FuncDecl{}
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil {
			bodies[fn.Name.Name] = fn
		}
	}

	predicate, ok := bodies["exportedTreeAt"]
	if !ok {
		t.Fatal("exportedTreeAt is gone — the export predicate was renamed and this " +
			"gate is measuring nothing (D328)")
	}
	skipper, ok := bodies["skipIfExported"]
	if !ok {
		t.Fatal("skipIfExported is gone — this gate is measuring nothing (D328)")
	}

	// What the predicate actually looks at. Taking it from the code is the whole
	// point: a marker named twice can disagree with itself, which is what happened.
	markers := stringLiterals(predicate.Body)
	if len(markers) != 1 {
		t.Fatalf("expected the predicate to name exactly one marker, found %v — the "+
			"scan no longer understands it and would pass on anything", markers)
	}
	marker := markers[0]

	reasons := stringLiterals(skipper.Body)
	if len(reasons) == 0 {
		t.Fatal("skipIfExported prints no message at all — a skip with no reason is " +
			"indistinguishable from a gate somebody switched off")
	}
	reason := strings.Join(reasons, " ")

	if !strings.Contains(reason, marker) {
		t.Errorf("the skip message does not name %q, the marker that actually decides "+
			"it. A reader who wants to know whether a missing gate was deliberate is "+
			"told to look at the wrong thing.\nmessage: %s", marker, reason)
	}
	if strings.Contains(reason, ".git") {
		t.Errorf("the skip message still names `.git` as the cause. D661 removed that "+
			"mechanism because the publication target is a CLONE and has one — the "+
			"message would be false exactly where it is printed.\nmessage: %s", reason)
	}
}

// stringLiterals returns every string constant in a function body, in source order.
func stringLiterals(body *ast.BlockStmt) []string {
	var out []string
	ast.Inspect(body, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if s, err := strconv.Unquote(lit.Value); err == nil {
			out = append(out, s)
		}
		return true
	})
	return out
}
