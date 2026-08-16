package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D1121. The code-to-contract skill's guards were all aimed one way. "Code mentions
// it is not production requires it"; classify before promoting; contradiction pass;
// never emit a capability whose only evidence is an import. Every one defends against
// INVENTING a dependency, and the evidence shape they ask for — "driver import + the
// config that wires it + the runtime entrypoint" — assumes an import exists to cite.
//
// A real codebase showed what that assumption costs: a system reaching several cloud
// services with no cloud SDK in any manifest — endpoints assembled from strings,
// requests signed by hand. A survey built the way the procedure describes would have
// come back empty and read as a clean estate. It is a tester's code, read with
// permission to survey it; the details are theirs and stay out of this file.
//
// The two failure directions are not symmetric, which is why only one of them was
// armoured. An invented dependency becomes a constraint somebody argues with. A
// missed one becomes a capability no contract carries and nothing ever verifies —
// and the report looks the same.
//
// This gate is deliberately WEAK and the entry says so: the skill is executed by an
// agent, not by CI, so nothing here proves an agent obeys it. What it does prevent is
// the guard being deleted or hollowed out — which is the failure mode that would
// otherwise happen quietly, since no test ever opened this file before.
func TestCodeToContractGuardsAgainstAnEmptySurvey(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".claude", "skills", "code-to-contract", "SKILL.md"))
	if err != nil {
		t.Skipf("no code-to-contract skill here: %v", err)
	}
	skill := string(raw)

	if !regexp.MustCompile(`(?i)empty survey is a finding`).MatchString(skill) {
		t.Fatal("the code-to-contract skill no longer carries the under-claiming guard. " +
			"Every other guard in it defends against inventing a dependency; this is the " +
			"only one defending against missing one, and a missed dependency is the " +
			"direction that leaves a capability unverified while the report reads clean.")
	}

	// Scope the search to the guard's OWN paragraph. The first version of this
	// assertion searched the whole file, so it passed on words living anywhere in it
	// — verified by hollowing the guard out to "look harder", which it happily
	// accepted. A check aimed at the document instead of the sentence is not a check
	// of the sentence.
	guard := regexp.MustCompile(`(?s)empty survey is a finding.*?\n\n`).FindString(skill)
	if guard == "" {
		t.Fatal("cannot isolate the guard's paragraph — this gate would fall back to " +
			"searching the whole file, which is how it silently stopped working once")
	}
	// The guard is only worth having if it says what to LOOK for. A sentence that
	// merely warns is advice; the substance is the shape that has no import.
	for _, must := range []string{
		"endpoint", // endpoints assembled from strings
		"sign",     // request signing
		"env var",  // resource-naming environment variables
	} {
		if !strings.Contains(strings.ToLower(guard), must) {
			t.Errorf("the guard no longer tells the agent to look for %q. Without the "+
				"concrete shape it is a warning, not a procedure — and the shape is the "+
				"whole finding: cloud access with no import to cite.", must)
		}
	}

	// The measurement is what makes the guard credible rather than hypothetical. If
	// someone removes the citation, the guard becomes an assertion about a risk
	// nobody has seen.
	if !strings.Contains(skill, "D1121") {
		t.Error("the guard no longer cites the run it came from. A guard against a " +
			"hypothetical risk gets argued away; one citing a measured codebase does not.")
	}
}
