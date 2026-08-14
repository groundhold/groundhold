package mcp

import (
	"os"
	"path/filepath"
	"regexp"
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

// D1086. D593 pins the SET the server serves, so a seventh tool cannot appear
// unremarked. Nothing pins what the DOCUMENTS say that set is.
//
// Two published surfaces name these tools — the MCP page and the README — and both
// also carry the safety claim that `groundhold_apply` is absent unless
// GROUNDHOLD_MCP_ALLOW_APPLY is set. An agent operator reads those pages to decide
// what an autonomous client can reach. Add a tool and the pages under-list it; remove
// one and they promise a tool that answers "unknown method"; flip the apply gating and
// the pages go on saying infrastructure mutation is off by default, which is the
// dangerous direction and the reason this is worth a gate rather than a note.
//
// The sibling gate above already binds one published sentence (the token claim) to the
// code. This binds the list and the gating claim the same way.
func TestPublishedToolListsMatchTheServedSet(t *testing.T) {
	root := repoRootFromMCP(t)
	deflt := toolNames(t, false)
	withApply := toolNames(t, true)

	served := map[string]bool{}
	for _, n := range withApply {
		served[n] = true
	}
	// The property under test is that apply is NOT in the default set. Assert it here
	// rather than trusting the sibling: this gate's message is about the documents, and
	// a reader must not have to guess which test failed.
	for _, n := range deflt {
		if n == "groundhold_apply" {
			t.Fatal("groundhold_apply is in the DEFAULT tool set — the published pages " +
				"say it appears only under GROUNDHOLD_MCP_ALLOW_APPLY, and that is now false")
		}
	}

	name := regexp.MustCompile(`groundhold_[a-z]+`)
	for _, rel := range []string{
		filepath.Join("website", "pages", "mcp.md"),
		"README.md",
	} {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue // a document this tree does not carry is not this gate's business
		}
		text := string(raw)

		mentioned := map[string]bool{}
		for _, m := range name.FindAllString(text, -1) {
			// The README's download line contains `groundhold_linux_amd64`; the regex
			// stops at the underscore-digit boundary, so filter to names the server
			// could plausibly have. Anything else is either a real tool or a phantom.
			if strings.HasPrefix(m, "groundhold_linux") || strings.HasPrefix(m, "groundhold_darwin") {
				continue
			}
			mentioned[m] = true
		}
		if len(mentioned) == 0 {
			t.Errorf("%s names no MCP tool at all — either the page stopped documenting "+
				"them (then this gate watches nothing) or the naming changed", rel)
			continue
		}

		for m := range mentioned {
			if !served[m] {
				t.Errorf("%s documents %q, which the server does not serve even with "+
					"apply enabled. A reader wiring an agent to it gets an unknown-method "+
					"error from a tool the docs promised.", rel, m)
			}
		}
		for _, n := range deflt {
			if !mentioned[n] {
				t.Errorf("%s does not mention %q, which every client gets by default. "+
					"An undocumented tool on the default surface is one nobody reviewed.",
					rel, n)
			}
		}
		// The gating claim itself, in whatever words each page uses for it.
		if mentioned["groundhold_apply"] && !strings.Contains(text, "GROUNDHOLD_MCP_ALLOW_APPLY") {
			t.Errorf("%s names groundhold_apply without naming the environment variable "+
				"that is the only thing keeping it off the default surface", rel)
		}
	}
}
