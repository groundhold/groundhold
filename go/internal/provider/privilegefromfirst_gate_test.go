package provider_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// D797. A policy document and a role definition are both LISTS of grants, and both
// drivers read element zero:
//
//	d.Statement[0].Action            (AWS)
//	doc.Properties.Permissions[0]    (Azure)
//
// That is correct for the documents these drivers WRITE — they author one statement —
// and wrong for the documents they READ, because discover reverse-maps every
// customer-managed policy and role in the account. A grant placed in the second statement
// was invisible, so a policy granting `iam:*` reported access.privileged FALSE, as a
// measured observation. Under-reporting privilege is the worst direction available here:
// the operator reads a clean list and stops looking.
//
// The gate is deliberately narrow, so that it is decidable. It flags one shape:
//
//	a file that emits a PRIVILEGE attribute, taking [0] of a FIELD of a decoded
//	document (a selector expression, not a local slice)
//
// `parts[0]` from splitting a providerId is an Ident, not a field, and is not flagged —
// the distinction is exactly the one that matters, between chopping up a string we made
// and picking one grant out of somebody else's list.
func TestNoPrivilegeAttributeReadsOnlyTheFirstGrant(t *testing.T) {
	securityAttrs := map[string]bool{
		"access.privileged": true,
		"access.mutating":   true,
		"role.permissions":  true,
	}

	root := repoRoot(t)
	emitting := 0
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

			emits := false
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if v, err := strconv.Unquote(lit.Value); err == nil && securityAttrs[v] {
					emits = true
				}
				return true
			})
			if !emits {
				continue
			}
			emitting++

			ast.Inspect(f, func(n ast.Node) bool {
				idx, ok := n.(*ast.IndexExpr)
				if !ok {
					return true
				}
				zero, ok := idx.Index.(*ast.BasicLit)
				if !ok || zero.Kind != token.INT || zero.Value != "0" {
					return true
				}
				sel, ok := idx.X.(*ast.SelectorExpr)
				if !ok {
					return true // a local slice, not a field of a decoded document
				}
				t.Errorf("%s/%s emits a privilege attribute and reads %s[0] — a policy "+
					"or role is a LIST of grants, and the one that decides privilege is "+
					"not always first. Read them all, or say what could not be read "+
					"(D797).", pkg, name, sel.Sel.Name)
				return true
			})
		}
	}

	// A gate with no subject reports a clean sweep over nothing (D328).
	if emitting < 3 {
		t.Fatalf("only %d driver file(s) emit a privilege attribute — the drivers carry "+
			"more than that; the scan is broken", emitting)
	}
}
