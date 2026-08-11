package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// D602. D567 made an unrecognised flag a refusal instead of a silent positional. Three
// things were reading flags OUT of that positional list and were closed on without
// anyone noticing: `--version`/`-v` (D589), the POSIX `--` separator (D590), and this
// one — `apireq classify`, whose four flags are parsed by its own sub-parser.
//
// The third was the expensive one. `scripts/canary-aws.sh` and `canary-gcp.sh` call
// `apireq classify` on a daily schedule, read its exit code as 0/10/20, and treat
// anything else as `infra-flake`. With the verb refusing at exit 1 and its message on
// stderr, a REAL provider drift — the thing those canaries exist to catch — was being
// reported as a flake on two clouds, with "classify produced no message".
//
// The fix is a registry rather than four more cases in the global switch, because the
// global switch is shared: a flag added there is accepted (and ignored) by all 51
// verbs, which is the fail-open D567 removed. This gate keeps the registry exact —
// every private flag a sub-parser reads must be registered, or the next flag someone
// adds dies exactly the way these four did, silently and only in production.
func TestEveryPrivateFlagIsRegistered(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	registered := map[string]bool{}
	for _, flags := range verbPrivateFlags {
		for _, f := range flags {
			registered[f] = true
		}
	}
	if len(registered) == 0 {
		t.Fatal("verbPrivateFlags is empty — this gate would be vacuous (D328); if the " +
			"last sub-parser really is gone, delete the registry and this test together")
	}

	// `run` holds the global switch: the flags it cases on are the ones the global
	// parser consumes, and they are not private by definition.
	var missing []string
	seen := 0
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name == "run" {
			return true
		}
		ast.Inspect(fn, func(m ast.Node) bool {
			cc, ok := m.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, e := range cc.List {
				lit, ok := e.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil || !strings.HasPrefix(v, "--") {
					continue
				}
				seen++
				if !registered[v] {
					missing = append(missing, v+" (read by "+fn.Name.Name+")")
				}
			}
			return true
		})
		return true
	})

	if seen == 0 {
		t.Fatal("no sub-parser flag cases found in main.go — either the parse is wrong " +
			"or the registry now guards nothing; both must fail loudly (D565)")
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("these flags are parsed by a verb's own sub-parser but are NOT in "+
			"verbPrivateFlags: %v\n"+
			"The global parser refuses any flag it does not recognise (D567), so an "+
			"unregistered private flag makes its whole sub-verb unreachable — and the "+
			"only place that shows up is the script that calls it.", missing)
	}
}

// The other direction: a registered flag that no sub-parser reads would be swallowed
// silently for that verb, which is the exact failure D567 removed.
func TestNoRegisteredFlagIsUnread(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	read := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name == "run" {
			return true
		}
		ast.Inspect(fn, func(m ast.Node) bool {
			if cc, ok := m.(*ast.CaseClause); ok {
				for _, e := range cc.List {
					if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if v, err := strconv.Unquote(lit.Value); err == nil {
							read[v] = true
						}
					}
				}
			}
			return true
		})
		return true
	})

	for verb, flags := range verbPrivateFlags {
		if len(flags) == 0 {
			t.Errorf("verb %q is registered with no private flags", verb)
		}
		for _, f := range flags {
			if !read[f] {
				t.Errorf("%q is registered as a private flag of %q but no sub-parser "+
					"reads it — it would be accepted and dropped", f, verb)
			}
		}
	}
}

// The CLI FACE of the verb, which is what the canaries call and what nothing covered:
// `internal/edgecanary` is well tested, and the four flags that carry its inputs from
// the command line were unreachable for as long as it took someone to run them.
func TestAPIReqClassifyIsReachableFromTheCommandLine(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
		want int
	}{
		{"an anonymous 200 at the edge is green",
			[]string{"apireq", "classify", "--applied", "true", "--deployed", "true",
				"--http-status", "200", "--json"}, 0},
		{"a transport failure on a good edge is a flake, never a false green",
			[]string{"apireq", "classify", "--applied", "true", "--deployed", "true",
				"--transport", "--json"}, 30},
		{"a transport failure with nothing applied is a groundhold regression",
			[]string{"apireq", "classify", "--applied", "false", "--deployed", "false",
				"--transport", "--json"}, 20},
		// D620: the inputs the truth table turns on must be SUPPLIED. Absent, they
		// used to default to false — a claim about the edge derived from a missing
		// argument, and two daily canaries branch on the result.
		{"no inputs at all is a flake, never a verdict",
			[]string{"apireq", "classify", "--json"}, 30},
		{"a boolean that is not a boolean is a flake, never false",
			[]string{"apireq", "classify", "--applied", "yeees", "--deployed", "true",
				"--http-status", "200", "--json"}, 30},
		{"a non-integer status is refused, not guessed",
			[]string{"apireq", "classify", "--http-status", "abc", "--json"}, 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(tc.argv); got != tc.want {
				t.Errorf("run(%v) = %d, want %d\n"+
					"Exit 1 here means the global parser refused a private flag and the "+
					"sub-verb never ran — which reads to the canaries as an infra flake.",
					tc.argv, got, tc.want)
			}
		})
	}
}
