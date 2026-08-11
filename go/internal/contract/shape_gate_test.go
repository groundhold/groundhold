package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D627. Every one of these loader sites was `x, _ := doc["k"].(T)`. A wrong type
// yields the zero value, so the CONTENT DISAPPEARS and the loader carries on.
//
// Measured on the most natural YAML slip there is — keying constraints by id instead
// of listing them, which reads perfectly well to a human:
//
//	constraints:
//	  hard:
//	    encryption:              # a MAPPING where the schema says array
//	      subject: db
//	      path: encryption.atRest
//	      op: equals
//	      value: true
//
//	$ groundhold verify c.yaml k.yaml    # the candidate declares encryption.atRest: false
//	  0 satisfied, 0 violated, 0 unknown, 0 unverifiable
//	  PROVEN                              exit 0
//
// A contract that plainly requires encryption at rest PROVED a candidate that plainly
// refuses it, and `plan` and `apply` then created the resource — because the
// requirement was never loaded. `validate` reported "0 constraints (0 hard)" and
// exited 0. `spec/contract.schema.json` says `array`; nothing at runtime enforced it.
//
// Two siblings from the same seam: a candidate whose `attributes:` is a LIST loses
// every attribute, turning an `absent` constraint into a false `satisfied` on a HARD
// verdict; and `verify: {method: null}` fell back to the initialised "static", turning
// a constraint the contract says must be proven against the provider into one proven
// by reading the candidate's own claim.
//
// The rule: if a key is PRESENT, its shape is part of the document's meaning. A block
// of the wrong shape is not an empty block.
func TestAMisShapedBlockIsRefusedNotDropped(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	const capsOK = `capabilities: [{id: db, type: capability.database.relational}]`

	for _, tc := range []struct{ name, doc, want string }{
		{"constraints.hard as a mapping", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: {id: t, environment: test, version: 1}
` + capsOK + `
constraints:
  hard:
    encryption:
      subject: db
      path: encryption.atRest
      op: equals
      value: true
`, "constraints.hard must be a list"},

		{"constraints as a list", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: {id: t, environment: test, version: 1}
` + capsOK + `
constraints:
  - {id: c1, subject: db, path: service.managed, op: equals, value: true}
`, "constraints must be a mapping"},

		{"budget as a mapping", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: {id: t, environment: test, version: 1}
` + capsOK + `
budget:
  c-budget:
    subject: db
    path: cost.monthly
    op: lte
    value: {amount: 100, currency: EUR}
`, "budget must be a list"},

		{"capabilities as a mapping", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: {id: t, environment: test, version: 1}
capabilities:
  db: {type: capability.database.relational}
`, "capabilities must be a list"},

		{"verify.method of the wrong type", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: {id: t, environment: test, version: 1}
` + capsOK + `
constraints:
  hard:
    - {id: tls, subject: db, path: encryption.inTransit, op: equals, value: true,
       verify: {method: null}}
`, "verify.method must be a string"},

		{"verify block of the wrong type", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: {id: t, environment: test, version: 1}
` + capsOK + `
constraints:
  hard:
    - {id: tls, subject: db, path: encryption.inTransit, op: equals, value: true,
       verify: probe}
`, "verify must be a mapping"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := LoadContract(write(strings.ReplaceAll(tc.name, " ", "-")+".yaml", tc.doc))
			if err == nil {
				t.Fatalf("accepted a mis-shaped document and loaded %d constraints — "+
					"a block the loader cannot read must refuse, because reading it as "+
					"empty silently drops everything the author wrote", len(c.Constraints))
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not name the shape problem (want %q): %v",
					tc.want, err)
			}
		})
	}
}

// The candidate side, where the same slip produces a false SATISFIED rather than an
// empty report.
func TestAMisShapedCandidateBlockIsRefused(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct{ name, doc, want string }{
		{"attributes as a list", `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: t
capabilities:
  db:
    provider: fake
    service: fakedb
    attributes:
      - network.publicExposure: true
`, "attributes must be a mapping"},
		{"capabilities as a list", `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: t
capabilities:
  - db
`, "capabilities must be a mapping"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadCandidate(write(strings.ReplaceAll(tc.name, " ", "-")+".yaml", tc.doc), nil, nil)
			if err == nil {
				t.Fatal("accepted a mis-shaped candidate — the declared attributes " +
					"vanish, and an `absent` constraint then reports satisfied on a " +
					"resource the document says is exposed")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not name the shape problem (want %q): %v",
					tc.want, err)
			}
		})
	}
}

// D629. Codex reviewed D627 and found the claim "every load-bearing site" too strong:
// `capability.requirements`, `assumptions` (and each entry's `affects`), and the
// candidate's per-capability BODY still used unchecked assertions. Each is the same
// defect with a different blast radius — a requirements block that vanishes removes
// constraints the author wrote, and a capability body that vanishes declares nothing
// while still counting as an implemented capability.
//
// It also caught the rule contradicting itself: `wantList`/`wantMap` treated a present
// `null` as absent. The resolution is a distinction worth stating rather than a blanket
// rule: a null CONTAINER is an empty container (idiomatic YAML for "none here"); a null
// LEAF value is unreadable and refuses, which is why `verify: {method: null}` is an
// error while `constraints:` with nothing under it is not.
func TestTheRemainingLoaderSitesRefuseToo(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("requirements of the wrong shape", func(t *testing.T) {
		_, err := LoadContract(write("req.yaml", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: {id: t, environment: test, version: 1}
capabilities:
  - id: db
    type: capability.database.relational
    requirements:
      - service.managed
`))
		if err == nil || !strings.Contains(err.Error(), "requirements must be a mapping") {
			t.Errorf("a mis-shaped requirements block did not refuse: %v", err)
		}
	})

	t.Run("assumptions of the wrong shape", func(t *testing.T) {
		_, err := LoadContract(write("asm.yaml", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: {id: t, environment: test, version: 1}
capabilities: [{id: db, type: capability.database.relational}]
assumptions:
  a1:
    statement: the network exists
    status: declared
`))
		if err == nil || !strings.Contains(err.Error(), "assumptions must be a list") {
			t.Errorf("a mis-shaped assumptions block did not refuse: %v", err)
		}
	})

	t.Run("a capability body that is not a mapping", func(t *testing.T) {
		_, err := LoadCandidate(write("cap.yaml", `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: t
capabilities:
  db: oops
`), nil, nil)
		if err == nil || !strings.Contains(err.Error(), "capabilities.db must be a mapping") {
			t.Errorf("a scalar capability body did not refuse: %v", err)
		}
	})

	t.Run("an explicitly empty container is empty, not an error", func(t *testing.T) {
		c, err := LoadContract(write("empty.yaml", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: {id: t, environment: test, version: 1}
capabilities: [{id: db, type: capability.database.relational}]
constraints:
budget:
assumptions:
`))
		if err != nil {
			t.Fatalf("`constraints:` with nothing under it is idiomatic YAML for an "+
				"empty block and must load: %v", err)
		}
		if len(c.Constraints) != 0 {
			t.Errorf("expected no constraints, got %d", len(c.Constraints))
		}
	})
}

// The control: well-shaped documents still load, and an ABSENT optional block is still
// absent rather than an error.
func TestWellShapedDocumentsStillLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte(`apiVersion: contract/v0.1
kind: InfrastructureContract
meta: {id: t, environment: test, version: 1}
capabilities: [{id: db, type: capability.database.relational}]
constraints:
  hard:
    - {id: c1, subject: db, path: service.managed, op: equals, value: true,
       verify: {method: static}}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := LoadContract(p)
	if err != nil {
		t.Fatalf("a well-shaped contract must load: %v", err)
	}
	if len(c.Constraints) != 1 {
		t.Errorf("loaded %d constraints, want 1", len(c.Constraints))
	}
}
