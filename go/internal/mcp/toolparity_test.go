package mcp

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// D1140. `tools/list` is a closed set published to a MACHINE. An agent does not read
// the source to find out what this server can do; it reads that reply and believes it.
//
// The set lived in two places in one file — the advertisement built by toolDefs, and
// the dispatcher's switch — and one test held one direction of one entry: that apply
// stays out while it is disabled. Nothing held the rest. A tool added to the dispatcher
// and not to the advertisement is undiscoverable, which is the quieter failure: it works
// perfectly for anyone who already knows its name and does not exist for anyone else.
// One added to the advertisement and not the dispatcher is louder but worse — the agent
// was told it could, tried, and got "unknown tool" back.
//
// Measured when this was written: the two agree, in both configurations. The point is
// that nothing was holding them there, and the drift is one line in either direction.
//
// The expectation is derived from the dispatcher via the AST rather than restated here,
// so adding a tool cannot satisfy this gate by being added to the gate.
func TestTheAdvertisedToolsAreExactlyTheDispatchableOnes(t *testing.T) {
	dispatch := dispatcherTools(t)
	if len(dispatch) < 5 {
		t.Fatalf("parsed %d tool cases from the dispatcher — the scan broke and this "+
			"gate would pass on anything (D328)", len(dispatch))
	}
	// The one tool that is deliberately conditional. Named, because a set derived from
	// both sides would agree with itself no matter what either side did.
	const gated = "groundhold_apply"
	if !contains(dispatch, gated) {
		t.Fatalf("the dispatcher no longer handles %s — this gate's premise is gone", gated)
	}

	for _, tc := range []struct {
		name       string
		allowApply bool
		want       []string
	}{
		{"apply disabled", false, without(dispatch, gated)},
		{"apply enabled", true, dispatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msgs := testServer(t,
				`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`+"\n"+
					`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`+"\n",
				tc.allowApply, nil)
			raw, _ := msgs[1]["result"].(map[string]any)["tools"].([]any)
			var got []string
			for _, item := range raw {
				name, _ := item.(map[string]any)["name"].(string)
				got = append(got, name)
			}
			sort.Strings(got)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("advertised %v, dispatchable %v.\nA name on one side and not the "+
					"other is a promise to a machine that reads this reply and nothing else: "+
					"missing from the advertisement it cannot be found, missing from the "+
					"dispatcher it answers \"unknown tool\" to an agent that trusted us.",
					got, tc.want)
			}
		})
	}
}

// dispatcherTools reads the tool names the switch actually handles, sorted.
func dispatcherTools(t *testing.T) []string {
	t.Helper()
	fset := gotoken.NewFileSet()
	file, err := parser.ParseFile(fset, "mcp.go", nil, 0)
	if err != nil {
		t.Fatalf("cannot parse the server: %v", err)
	}
	seen := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		clause, ok := n.(*ast.CaseClause)
		if !ok {
			return true
		}
		for _, expr := range clause.List {
			lit, ok := expr.(*ast.BasicLit)
			if !ok || lit.Kind != gotoken.STRING {
				continue
			}
			if s, err := strconv.Unquote(lit.Value); err == nil &&
				strings.HasPrefix(s, "groundhold_") {
				seen[s] = true
			}
		}
		return true
	})
	var out []string
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func without(xs []string, drop string) []string {
	var out []string
	for _, x := range xs {
		if x != drop {
			out = append(out, x)
		}
	}
	return out
}
