package apply

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

// D1117. The precondition registry is published TWICE — spec/sealed-plan.md lists
// `report-executable | no-assumed-basis | no-assumed-hard-basis | within-autonomy`,
// spec/executor.md calls it a "closed registry, D36" — and the two copies disagreed.
// executor.md named three, omitting `no-assumed-hard-basis`, which the runtime
// implements and the sibling document publishes. Neither test suite read either file.
//
// The omission points the wrong way round for once, and that is the interesting part.
// executor.md also says "anything the executor cannot evaluate REFUSES fail-closed", so
// a reader of that page alone would conclude a plan carrying `no-assumed-hard-basis`
// is REFUSED. It is evaluated — it is the D195 gate that stops a HARD constraint
// sealing on a guess. Believing that gate unreachable is a reason not to opt into it.
//
// The registry is named here, and all three artefacts are held against it: both
// documents and the executor's own switch, read from the AST so a name in a comment
// cannot pad the set.
func TestPreconditionRegistryMatchesBothSpecs(t *testing.T) {
	// Evaluated by the executor. `within-autonomy` is deliberately NOT here: it is in
	// the published registry and falls to the fail-closed arm, which is the promise
	// the last assertion checks.
	evaluated := map[string]bool{
		"report-executable": true, "no-assumed-basis": true, "no-assumed-hard-basis": true,
	}
	published := map[string]bool{
		"report-executable": true, "no-assumed-basis": true,
		"no-assumed-hard-basis": true, "within-autonomy": true,
	}

	got := preconditionCases(t, "apply.go")
	if len(got) == 0 {
		t.Fatal("no precondition cases found in apply.go — the AST walk broke, and " +
			"this gate would pass on anything (D328)")
	}
	diffSet(t, "the preconditions the executor evaluates", got, evaluated)
	for name := range got {
		if !published[name] {
			t.Errorf("the executor evaluates %q and neither spec publishes it — a "+
				"precondition nobody can read about is one nobody can opt into", name)
		}
	}

	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, doc := range []string{"sealed-plan.md", "executor.md"} {
		raw, err := os.ReadFile(filepath.Join(root, "spec", doc))
		if err != nil {
			t.Skipf("no %s here: %v", doc, err)
		}
		m := regexp.MustCompile("(?s)`report-executable \\|(.*?)`").FindStringSubmatch(string(raw))
		if m == nil {
			t.Fatalf("spec/%s no longer publishes the precondition registry as a "+
				"`a | b | c` list starting at report-executable — the published copy "+
				"is unguarded again", doc)
		}
		names := map[string]bool{"report-executable": true}
		for _, part := range strings.FieldsFunc(m[1], func(r rune) bool {
			return r == '|' || r == '\n' || r == ' ' || r == '\t' || r == '`'
		}) {
			if regexp.MustCompile(`^[a-z]+(-[a-z]+)*$`).MatchString(part) {
				names[part] = true
			}
		}
		diffSet(t, "spec/"+doc+"'s published registry", names, published)
	}
}

// The fail-closed promise itself: a precondition outside the registry must refuse, not
// be skipped. This is the direction that matters — a skipped precondition is a gate the
// operator believes is holding and which never ran.
func TestAnUnknownPreconditionRefuses(t *testing.T) {
	src, err := os.ReadFile("apply.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, `case "report-executable":`)
	if i < 0 {
		t.Fatal("the precondition switch moved — this gate cannot find it")
	}
	j := strings.Index(s[i:], "\n\t\tdefault:")
	if j < 0 {
		t.Fatal("the precondition switch has NO default arm: an unrecognised " +
			"precondition would fall through and be SKIPPED, which is the fail-open " +
			"the closed registry exists to prevent")
	}
	arm := s[i+j : i+j+400]
	if !strings.Contains(arm, "refused(") {
		t.Errorf("the default arm of the precondition switch does not refuse:\n%s\n\n"+
			"spec/executor.md promises anything the executor cannot evaluate REFUSES "+
			"fail-closed. A precondition that is silently skipped is a gate the "+
			"operator believes is holding.", arm)
	}
}

func diffSet(t *testing.T, what string, got, want map[string]bool) {
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

// preconditionCases reads the case labels of the switch over precondition types.
func preconditionCases(t *testing.T, file string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		sw, ok := n.(*ast.TypeSwitchStmt)
		_ = sw
		_ = ok
		s, ok := n.(*ast.SwitchStmt)
		if !ok || s.Tag == nil {
			return true
		}
		// The switch whose tag is the assignment of pc["type"].
		if !strings.Contains(exprText(fset, s.Tag), `pc["type"]`) &&
			!strings.Contains(exprText(fset, s.Init), `pc["type"]`) {
			return true
		}
		for _, stmt := range s.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, e := range cc.List {
				if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, err := strconv.Unquote(lit.Value); err == nil {
						out[v] = true
					}
				}
			}
		}
		return true
	})
	return out
}

func exprText(fset *token.FileSet, n ast.Node) string {
	if n == nil {
		return ""
	}
	start := fset.Position(n.Pos()).Offset
	end := fset.Position(n.End()).Offset
	raw, err := os.ReadFile("apply.go")
	if err != nil || end > len(raw) {
		return ""
	}
	return string(raw[start:end])
}
