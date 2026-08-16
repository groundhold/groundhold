package forecast

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// D1115. spec/forecast.md publishes two closed registries — the effect set ("closed
// set, D19 discipline") and the unknown-reason registry — and no test in the tree read
// that file. Both had drifted, in opposite directions, which is what makes the pair
// worth stating together.
//
// The reason registry names what is "emitted today" and separately what is "reserved
// for future providers/effects (defined, never yet emitted)". That is a claim about the
// runtime, not a list of words, and the runtime emitted FOUR reasons the document knew
// nothing about: invalid-observation, missing-binding, target-already-matches and
// deposed-target-validated-at-apply. A consumer reading the registry to decide what to
// branch on would meet all four in production.
//
// The effect set drifted the other way. It publishes nine effects; six are produced.
// `unforecastable` was marked reserved, which is precisely what made the omission
// misleading — a reader who sees ONE effect flagged as not-yet-emitted concludes the
// other eight are live, and `will-replace` and `will-adopt` are not.
//
// The expected sets are named HERE, not derived from either side (D1113: a gate that
// parses the document narrows itself when the document loses a line).
func TestForecastRegistriesMatchTheSpec(t *testing.T) {
	emittedEffects := map[string]bool{
		"will-create": true, "will-update": true, "will-delete": true,
		"no-effect": true, "unknown": true, "stale-plan": true,
	}
	reservedEffects := map[string]bool{
		"will-replace": true, "will-adopt": true, "unforecastable": true,
	}
	emittedReasons := map[string]bool{
		"missing-observation": true, "stale-observation": true,
		"unsupported-effect-model": true, "target-identity-mismatch": true,
		"invalid-observation": true, "missing-binding": true,
		"target-already-matches": true, "deposed-target-validated-at-apply": true,
	}
	reservedReasons := map[string]bool{
		"provider-computed": true, "provider-defaulted": true, "write-only": true,
		"cross-resource-effect": true, "eventual-consistency-window": true,
		"requires-provider-validation": true,
	}

	// --- what the runtime actually produces ---
	gotEffects, gotReasons := literalsAssignedTo(t, "forecast.go", "Effect", "Reason")
	if len(gotEffects) == 0 || len(gotReasons) == 0 {
		t.Fatalf("found %d effects and %d reasons in the source — the AST walk broke, "+
			"and this gate would pass on anything (D328)", len(gotEffects), len(gotReasons))
	}
	compareRegistry(t, "effects the runtime emits", gotEffects, emittedEffects, reservedEffects)
	compareRegistry(t, "unknown-reasons the runtime emits", gotReasons, emittedReasons, reservedReasons)

	// --- what the document publishes ---
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "spec", "forecast.md"))
	if err != nil {
		t.Skipf("no forecast spec here: %v", err)
	}
	spec := string(raw)

	block := regexp.MustCompile("(?s)## Effects \\(closed set.*?\n```\n(.*?)```").FindStringSubmatch(spec)
	if block == nil {
		t.Fatal("spec/forecast.md no longer publishes the closed effect set in the form " +
			"this gate reads — the published copy is unguarded again")
	}
	published := splitRegistry(block[1])
	want := map[string]bool{}
	for e := range emittedEffects {
		want[e] = true
	}
	for e := range reservedEffects {
		want[e] = true
	}
	diff(t, "the published effect set", published, want)

	// The reason registry's two halves, each read from its own sentence: the split IS
	// the claim, so checking their union would miss a reason moving between them.
	diff(t, "the spec's emitted-today reasons",
		wordsBetween(t, spec, `Emitted today: `, `\. Reserved for`), emittedReasons)
	diff(t, "the spec's reserved reasons",
		wordsBetween(t, spec, `never yet emitted\): `, `\. The effects`), reservedReasons)
}

func wordsBetween(t *testing.T, s, from, to string) map[string]bool {
	t.Helper()
	m := regexp.MustCompile(`(?s)` + from + `(.*?)` + to).FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("spec/forecast.md no longer carries the sentence between %q and %q", from, to)
	}
	// Only the backticked spans: the sentence around them is prose, and prose put
	// "stale-plan" into the reason set on the first attempt — the effect an
	// identity-mismatch reason is CARRIED ON, read as a reason itself.
	out := map[string]bool{}
	for _, span := range regexp.MustCompile("`([^`]*)`").FindAllStringSubmatch(m[1], -1) {
		for k := range splitRegistry(span[1]) {
			out[k] = true
		}
	}
	return out
}

// splitRegistry reads a `a | b | c` registry line into a set. Splitting on the
// published separator rather than matching a word shape: the shapes differ (`unknown`
// carries no hyphen, `deposed-target-validated-at-apply` carries four) and a pattern
// tuned to one of them silently drops the other.
func splitRegistry(s string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool {
		return r == '|' || r == '\n' || r == ' ' || r == '\t' || r == '`' || r == ','
	}) {
		if p := strings.Trim(part, ".`"); regexp.MustCompile(`^[a-z]+(-[a-z]+)*$`).MatchString(p) {
			out[p] = true
		}
	}
	return out
}

func compareRegistry(t *testing.T, what string, got, emitted, reserved map[string]bool) {
	t.Helper()
	diff(t, what, got, emitted)
	for v := range got {
		if reserved[v] {
			t.Errorf("%s: %q is published as RESERVED (\"defined, never yet emitted\") "+
				"and the runtime emits it — the document is telling a consumer not to "+
				"expect something they will meet", what, v)
		}
	}
}

func diff(t *testing.T, what string, got, want map[string]bool) {
	t.Helper()
	var missing, extra []string
	for v := range want {
		if !got[v] {
			missing = append(missing, v)
		}
	}
	for v := range got {
		if !want[v] {
			extra = append(extra, v)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("%s is missing: %s", what, strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		t.Errorf("%s carries unexpected: %s", what, strings.Join(extra, ", "))
	}
}

// literalsAssignedTo collects the string literals assigned to the named struct fields,
// read from the AST so a word in a comment or an error message cannot pad either set.
func literalsAssignedTo(t *testing.T, file, fieldA, fieldB string) (map[string]bool, map[string]bool) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b := map[string]bool{}, map[string]bool{}
	take := func(name string, lit *ast.BasicLit) {
		if lit == nil || lit.Kind != token.STRING {
			return
		}
		v, err := strconv.Unquote(lit.Value)
		if err != nil || v == "" {
			return
		}
		switch name {
		case fieldA:
			a[v] = true
		case fieldB:
			b[v] = true
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok || i >= len(x.Rhs) {
					continue
				}
				lit, _ := x.Rhs[i].(*ast.BasicLit)
				take(sel.Sel.Name, lit)
			}
		case *ast.KeyValueExpr:
			if k, ok := x.Key.(*ast.Ident); ok {
				lit, _ := x.Value.(*ast.BasicLit)
				take(k.Name, lit)
			}
		}
		return true
	})
	return a, b
}
