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

// D796. Two durations sit next to each other in every backup API and mean opposite
// things:
//
//	retention  — how far BACK a restore can reach
//	RPO        — how much a failure LOSES
//
// They are both "days" and they are both about backups, so one reads as the other until
// someone asks which. The Azure driver wrote the requested RPO INTO the retention field:
// asking for a 15-minute data-loss window set backup retention to its floor of one day,
// so a tighter recovery requirement made the estate's recoverability worse. Observe then
// echoed those retention days back as the RPO, which closed the loop and made every
// round-trip test agree with itself.
//
// The other two clouds never wrote the value anywhere — both read an RPO as "automated
// backups must be on" — so this was one driver disagreeing with two, and with the world.
//
// This gate is NOT the curated list next door (D748). It asks one general question of
// every driver file: when a file emits an attribute that names a LOSS window, is that
// attribute's VALUE computed from something named for RETENTION? A guard is fine and
// common — AWS emits an RPO only when retention > 0, because retention > 0 is what turns
// PITR on — so the check reads the VALUE EXPRESSION, not the file.
func TestNoLossWindowIsComputedFromARetentionField(t *testing.T) {
	type rule struct {
		attr    string
		forbid  string // identifier substring that must not appear in the VALUE
		because string
	}
	rules := []rule{
		{"recovery.rpo", "Retention",
			"retention is how far BACK a restore reaches, not how much a failure loses"},
	}

	root := repoRoot(t)
	emissions := 0
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
				var pathLit string
				var value ast.Expr
				for _, el := range lit.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok {
						continue
					}
					switch key.Name {
					case "Path":
						if b, ok := kv.Value.(*ast.BasicLit); ok && b.Kind == token.STRING {
							if v, err := strconv.Unquote(b.Value); err == nil {
								pathLit = v
							}
						}
					case "Value":
						value = kv.Value
					}
				}
				if pathLit == "" || value == nil {
					return true
				}
				for _, r := range rules {
					if pathLit != r.attr {
						continue
					}
					emissions++
					ast.Inspect(value, func(vn ast.Node) bool {
						id, ok := vn.(*ast.Ident)
						if !ok || !strings.Contains(id.Name, r.forbid) {
							return true
						}
						t.Errorf("%s/%s emits %s with a value computed from %s — %s. "+
							"The two are adjacent in every backup API and opposite in "+
							"meaning; writing one as the other makes a TIGHTER recovery "+
							"requirement shorten the estate's history (D796).",
							pkg, name, r.attr, id.Name, r.because)
						return false
					})
				}
				return true
			})
		}
	}

	// A gate with no subject reports a clean sweep over nothing (D328). Drivers do emit
	// this attribute; a run that found none means the emission shape moved.
	if emissions < 2 {
		t.Fatalf("found %d emission(s) of a loss-window attribute across the drivers — "+
			"the scan no longer recognises how observations are built", emissions)
	}
}
