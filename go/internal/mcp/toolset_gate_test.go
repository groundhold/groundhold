package mcp

import (
	"sort"
	"strings"
	"testing"
)

// D593. The MCP tool list is the surface an AUTONOMOUS agent gets, and its membership
// is a safety boundary: read-mostly by default, with `apply` existing only under
// GROUNDHOLD_MCP_ALLOW_APPLY behind a hash-pinned two-step. The package comment states
// that boundary and is honest about its limit — the token pins a plan, it does not
// authenticate a human.
//
// One test guarded it, by name: "groundhold_apply must not exist without the env
// var". That covers one instance. A seventh tool — converge, adopt, retire — added
// later is not `groundhold_apply` and would slip in unremarked, which is the same
// shape as D586 (one flag guarded, the class open) with infrastructure mutation at
// the end of it.
//
// So the SET is pinned, the way providerVerbs is (D571): a change here has to be a
// deliberate edit that updates this list, and a reviewer sees the diff.
func TestDefaultToolSetIsExactlyTheReadMostlyOnes(t *testing.T) {
	want := []string{
		"groundhold_draft",    // writes only under .groundhold/drafts/, seals nothing
		"groundhold_forecast", // pure
		"groundhold_hash",     // pure
		"groundhold_observe",  // reads the world; records to the ledger on request
		"groundhold_plan",     // compiles; seals a plan, mutates no infrastructure
		"groundhold_verify",   // pure
	}
	got := toolNames(t, false)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the default MCP tool set changed WITHOUT updating this test.\n"+
			"  want: %v\n  got:  %v\n"+
			"If deliberate, update the list and state what the new tool mutates. This "+
			"is what an autonomous agent can reach without an env gate.", want, got)
	}
}

// And the escape hatch adds exactly one thing, not a door.
func TestApplyIsTheOnlyToolTheEnvGateAdds(t *testing.T) {
	base := toolNames(t, false)
	withApply := toolNames(t, true)
	added := diff(withApply, base)
	if strings.Join(added, ",") != "groundhold_apply" {
		t.Errorf("GROUNDHOLD_MCP_ALLOW_APPLY adds %v — the gate is documented as "+
			"admitting apply and its two-step, nothing else", added)
	}
	if len(diff(base, withApply)) != 0 {
		t.Errorf("the env gate REMOVED tools: %v", diff(base, withApply))
	}
}

func toolNames(t *testing.T, allowApply bool) []string {
	t.Helper()
	s := &Server{allowApply: allowApply}
	var names []string
	for _, m := range s.toolDefs() {
		n, _ := m["name"].(string)
		if n == "" {
			t.Fatal("a tool has no name")
		}
		names = append(names, n)
	}
	if len(names) < 3 {
		t.Fatalf("only %d tools listed — the probe broke and this gate would pass on "+
			"anything", len(names))
	}
	sort.Strings(names)
	return names
}

func diff(a, b []string) []string {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	var out []string
	for _, x := range a {
		if !in[x] {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
