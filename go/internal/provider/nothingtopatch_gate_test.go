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

// TestNoImmutableVerdictSaysThereIsNothingToPatch holds one contradiction that cannot be
// anything but a defect (D823).
//
// `immutable` tells the compiler no in-place change exists, so it DESTROYS AND RECREATES
// the resource. "There is nothing to patch" says the attribute cannot differ at all — the
// service always has it that way. Put together, they instruct the tool to destroy a disk in
// order to reach a state the replacement will also not have. The request is not satisfied,
// and the data is gone.
//
// The codebase already had the honest idiom in the same shape elsewhere: App Runner answers
// `unsupported` for tls.enforced with "HTTPS-only by construction — nothing to patch
// (=false cannot be honored)", and the GCE classifier says in its own comment that
// "unsupported rather than immutable is the honest distinction". Two disk classifiers
// diverged from it, and a disk is where the divergence costs the most.
func TestNoImmutableVerdictSaysThereIsNothingToPatch(t *testing.T) {
	root := repoRoot(t)
	var bad []string
	checked := 0

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
				ret, ok := n.(*ast.ReturnStmt)
				if !ok || len(ret.Results) != 2 {
					return true
				}
				verdict, ok := stringLiteral(ret.Results[0])
				if !ok || verdict != "immutable" {
					return true
				}
				checked++
				reason := concatenatedString(ret.Results[1])
				if saysNothingToPatch(reason) {
					bad = append(bad, pkg+"/"+name+": "+truncate(reason, 110))
				}
				return true
			})
		}
	}

	// D328: assert the subject. If nothing returned "immutable" the sweep found nothing
	// and would report a clean run over an empty set.
	if checked < 40 {
		t.Fatalf("only %d immutable verdicts found across the drivers — the scan is broken", checked)
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("%d classifier(s) answer IMMUTABLE with a reason that says the attribute "+
			"cannot differ:\n  %s\n\nImmutable makes the plan destroy and recreate the "+
			"resource, and a replacement will have the same value — so the change is not "+
			"honoured and the data is gone anyway. Answer `unsupported` and say what cannot "+
			"be honoured (D823).", len(bad), strings.Join(bad, "\n  "))
	}
}

// TestTheContradictionGateReadsAReasonSplitAcrossLines pins the folding directly, for the
// D820 reason: a detector that reads less than it should passes a healthy tree unchanged,
// and only goes quiet on the day something is wrong. Every real reason in these drivers is
// long enough to be written as "a" + "b", so a gate that only reads the first literal would
// miss most of its subject while reporting a clean run.
func TestTheContradictionGateReadsAReasonSplitAcrossLines(t *testing.T) {
	expr, err := parser.ParseExpr(`"a managed disk is always encrypted at rest " +
		"and the setting cannot be turned off — there is nothing to patch"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := concatenatedString(expr); !saysNothingToPatch(got) {
		t.Fatalf("a reason split across two literals read as %q — the gate would miss every "+
			"contradiction written the way these drivers write them (D823)", got)
	}
	single, err := parser.ParseExpr(`"a region change is a new disk"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if saysNothingToPatch(concatenatedString(single)) {
		t.Fatal("an ordinary reason was read as a contradiction — the detector is too eager")
	}
}

func saysNothingToPatch(reason string) bool {
	r := strings.ToLower(reason)
	for _, phrase := range []string{
		"nothing to patch",
		"cannot be turned off",
		"cannot be disabled",
		"no way to disable",
	} {
		if strings.Contains(r, phrase) {
			return true
		}
	}
	return false
}

func stringLiteral(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	return v, err == nil
}

// concatenatedString folds a reason written as "a" + "b" + "c" into one string, because a
// reason long enough to be split is exactly the kind this gate must read.
func concatenatedString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		s, _ := stringLiteral(v)
		return s
	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			return concatenatedString(v.X) + concatenatedString(v.Y)
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
