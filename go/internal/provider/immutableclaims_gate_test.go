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

// uncheckedImmutableCeiling is the number of IMMUTABLE claims not yet confronted with the
// provider that says whether they are true. It may only go DOWN.
//
// D807. A ceiling rather than a target, and a number rather than a wish, because the
// alternative shapes both fail: a list with no ceiling rots into permission (the
// fixture-coverage allowlist did exactly that, D803), and a demand that all 129 be
// audited at once turns an honest ratchet into a blocked branch.
const uncheckedImmutableCeiling = 9

// TestEveryImmutableClaimIsRegistered holds two things about the claims a driver makes
// when it says a change cannot be honoured in place.
//
// `immutable` is not an opinion about how fundamental an attribute feels. It tells the
// compiler an in-place change is impossible, so the plan carries a DESTROY AND RECREATE.
// It is a claim about the PROVIDER's API, and only the provider can settle it — D806
// found one that AWS's own documentation contradicts in a single sentence, and the price
// of that sentence was a budget deleted in order to change its period.
//
// So: every claim in the code must appear in the registry, and the number of unchecked
// ones may only fall. A new `immutable` cannot arrive unnoticed, and the debt cannot
// quietly grow while looking like progress.
func TestEveryImmutableClaimIsRegistered(t *testing.T) {
	root := repoRoot(t)

	inCode := map[string]bool{}
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
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "classify") {
					continue
				}
				svc := strings.TrimSuffix(strings.TrimPrefix(fn.Name.Name, "classify"), "Change")
				for attr := range caseAttributesReturning(fn, "immutable") {
					inCode[pkg+"/"+svc+"|"+attr] = true
				}
			}
		}
	}

	registered := map[string]string{} // claim -> state
	blob, err := os.ReadFile(filepath.Join("testdata", "immutable_claims.registry"))
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	for _, line := range strings.Split(string(blob), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			t.Errorf("registry line is not service|attribute|state: %q", line)
			continue
		}
		registered[parts[0]+"|"+parts[1]] = parts[2]
	}

	// A gate with no subject reports a clean sweep over nothing (D328).
	if len(inCode) < 50 || len(registered) < 50 {
		t.Fatalf("found %d claims in the code and %d in the registry — one of the two "+
			"sides stopped working", len(inCode), len(registered))
	}

	var unregistered, stale []string
	for c := range inCode {
		if _, ok := registered[c]; !ok {
			unregistered = append(unregistered, c)
		}
	}
	for c := range registered {
		if !inCode[c] {
			stale = append(stale, c)
		}
	}
	sort.Strings(unregistered)
	sort.Strings(stale)

	if len(unregistered) > 0 {
		t.Errorf("%d IMMUTABLE claim(s) not in the registry:\n  %s\n\nSaying a change "+
			"cannot be honoured in place makes the plan destroy and recreate the resource. "+
			"Confront the claim with the provider's own description and add the line as "+
			"`checked: <what said so>`, or add it as `unchecked` and raise nothing — the "+
			"ceiling only falls (D807).", len(unregistered), strings.Join(unregistered, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("%d registry line(s) name a claim no driver makes any more:\n  %s\n\n"+
			"Drop them, so the registry describes the code rather than remembering it.",
			len(stale), strings.Join(stale, "\n  "))
	}

	unchecked := 0
	for _, state := range registered {
		if state == "unchecked" {
			unchecked++
		}
	}
	if unchecked > uncheckedImmutableCeiling {
		t.Errorf("%d unchecked IMMUTABLE claims, ceiling %d — the debt grew. Every one of "+
			"these plans a destroy-and-recreate on a claim nobody has confronted with the "+
			"provider (D807).", unchecked, uncheckedImmutableCeiling)
	}
	if unchecked < uncheckedImmutableCeiling {
		t.Errorf("%d unchecked claims but the ceiling still says %d. Lower it: a ceiling "+
			"that trails the work stops being a ratchet.", unchecked, uncheckedImmutableCeiling)
	}
}

// caseAttributesReturning returns the attribute paths a classifier answers `verdict` for.
func caseAttributesReturning(fn *ast.FuncDecl, verdict string) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		cc, ok := n.(*ast.CaseClause)
		if !ok {
			return true
		}
		got := ""
		ast.Inspect(cc, func(x ast.Node) bool {
			ret, ok := x.(*ast.ReturnStmt)
			if !ok || len(ret.Results) == 0 || got != "" {
				return true
			}
			lit, ok := ret.Results[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if v, err := strconv.Unquote(lit.Value); err == nil {
				got = v
			}
			return true
		})
		if got != verdict {
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
