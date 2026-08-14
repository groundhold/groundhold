package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D1063. `example candidate` scaffolds a candidate for a contract, and a candidate
// ANSWERS a contract: declaring an attribute ASSERTS the implementation has that
// property. The scaffold used to write every attribute in the vocabulary as a live
// line with a kind-default value, which manufactured assertions nobody chose — and
// one of them was actively unbuildable. For a bool the kind default is `false`, so a
// database scaffold declared `service.managed: false` one line under the
// `provider: aws` the scaffold itself recommends, and the RDS driver refuses that
// exact value ("service.managed=false cannot be honored by RDS"). Walked from the
// published README with nothing but a downloaded binary: `converge` APPLIED once and
// then REFUSED every later pass, so the documented loop could not converge. Deleting
// that single line made it APPLIED → CONVERGED.
//
// The rule this pins is the one the curated example already demonstrates (its
// contract constrains one path, its candidate declares exactly that one): a
// scaffolded candidate declares what the contract ASKS ABOUT and nothing else. The
// rest of the vocabulary is still shown, commented out, because seeing the palette is
// the scaffold's teaching value — but an offer is not an assertion.
//
// The gate is over the OUTPUT rather than the generator, so it stays true however the
// generator is rewritten, and it names the landmine that motivated it.
func TestScaffoldDeclaresOnlyWhatTheContractAsksAbout(t *testing.T) {
	root := repoRootFromCmd(t)
	dir := t.TempDir()

	// A contract that constrains ONE path, so "asked about" and "in the vocabulary"
	// cannot be confused: a scaffold that dumps the vocabulary fails this, a scaffold
	// that answers the contract passes it.
	contract := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(contract, []byte(
		"apiVersion: contract/v0.1\n"+
			"kind: InfrastructureContract\n"+
			"meta: { id: scaffold-t, environment: test, version: 1 }\n"+
			"capabilities:\n"+
			"  - id: db\n"+
			"    type: capability.database.relational\n"+
			"constraints:\n"+
			"  hard:\n"+
			"    - { id: eu, subject: db, path: location.region, op: equals,\n"+
			"        value: eu-central-1, verify: { method: static } }\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if code := run([]string{"example", "candidate", contract}); code != 0 {
			t.Fatalf("example candidate exited %d", code)
		}
	})

	var live []string
	inAttrs := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "attributes:"):
			inAttrs = true
			continue
		case trimmed == "" || strings.HasPrefix(trimmed, "#"):
			continue // an offer, not an assertion
		}
		if inAttrs && strings.Contains(trimmed, ":") &&
			!strings.HasPrefix(trimmed, "provider:") && !strings.HasPrefix(trimmed, "service:") {
			live = append(live, strings.TrimSpace(strings.SplitN(trimmed, ":", 2)[0]))
		}
	}

	// The positive half: the asked-about path must BE there. Without this the gate
	// passes on a scaffold that declares nothing at all, which would be the same
	// class of vacuity it exists to catch (D328).
	var sawAsked bool
	for _, p := range live {
		if p == "location.region" {
			sawAsked = true
		}
	}
	if !sawAsked {
		t.Errorf("the scaffold does not declare location.region, the one path the "+
			"contract constrains — a candidate that answers nothing is not a scaffold.\ngot: %v", live)
	}

	// The negative half: nothing else may be asserted.
	for _, p := range live {
		if p != "location.region" {
			t.Errorf("the scaffold declares %q, which the contract does not ask about — "+
				"a declared attribute is an ASSERTION about the implementation, and the "+
				"kind default for a bool (`false`) is how `service.managed: false` reached "+
				"a candidate under a `provider: aws` recommendation, which RDS refuses "+
				"outright. Offer it commented out instead.", p)
		}
	}

	// And the landmine by name, so a regression says what it broke rather than only
	// that a count moved.
	for _, p := range live {
		if p == "service.managed" {
			t.Fatal("service.managed is asserted again: with the bool default `false` " +
				"this is the exact document that made `converge` REFUSE every pass after " +
				"the first (D1063)")
		}
	}
	_ = root
}
