package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D673. The package doc has said since D19 that "anything the loader does not
// recognize is refused, never silently non-gating". That was true of VALUES and
// false of KEYS: a misspelled top-level block was dropped without a word.
//
// Measured — a contract whose block is spelled `constraint:` (singular):
//
//	validate typo.yaml            OK  contract t v1: 1 capabilities, 0 constraints  exit 0
//	hash typo.yaml == hash nocons.yaml                                 (same sha256)
//	verify typo.yaml cbad.yaml    0 satisfied, 0 violated  PROVEN      exit 0
//
// The candidate that `cbad.yaml` declares refuses encryption at rest. The contract
// requiring it PROVED it, and the identity every sealed plan pins could not tell
// that contract from one with no constraints at all.
func TestAMisspelledTopLevelBlockIsRefused(t *testing.T) {
	base := `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: t, owner: o@e.test, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
`
	for _, tc := range []struct{ name, block, want string }{
		{"constraint (singular)", `constraint:
  hard:
    - { id: c1, subject: db, path: encryption.atRest, op: equals, value: true,
        verify: { method: static } }
`, "constraint"},
		{"capabilties (typo)", "capabilties: []\n", "capabilties"},
		{"autonmy (typo)", "autonmy: {}\n", "autonmy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "c.yaml")
			if err := os.WriteFile(p, []byte(base+tc.block), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadContract(p)
			if err == nil {
				t.Fatalf("accepted a contract with an unknown top-level key:\n%s", tc.block)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not name the key: %v", err)
			}
		})
	}
}

// The escape hatch, and the control: a document may carry deliberately
// non-runtime data under an `x-` prefix (a YAML anchor block, a tool's metadata),
// and every known block must still load.
func TestAnExtensionKeyIsAllowedAndTheKnownBlocksStillLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(`apiVersion: contract/v0.1
kind: InfrastructureContract
x-defaults: &d
  note: anchors live here
meta: { id: t, owner: o@e.test, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - { id: c1, subject: db, path: encryption.atRest, op: equals, value: true,
        verify: { method: static } }
assumptions:
  - { id: a1, statement: "the region is eu-central-1", status: assumed,
      confidence: 0.9, affects: [c1] }
autonomy:
  forbidden:
    - delete_stateful: true
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadContract(p)
	if err != nil {
		t.Fatalf("a document using every known block plus an x- extension was "+
			"refused: %v", err)
	}
	if len(c.Constraints) != 1 || len(c.Assumptions) != 1 || c.Autonomy == nil {
		t.Errorf("a known block was dropped: constraints=%d assumptions=%d autonomy=%v",
			len(c.Constraints), len(c.Assumptions), c.Autonomy)
	}
}

// The candidate side, where the audit measured a verdict FLIP: `attributs:` instead
// of `attributes:` made an `op: absent` constraint read as satisfied.
func TestAMisspelledCandidateKeyIsRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.yaml")
	if err := os.WriteFile(p, []byte(`apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: t
capabilities: {}
candidat: oops
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCandidate(p, nil, nil); err == nil {
		t.Fatal("accepted a candidate with an unknown top-level key")
	}
}

// D683. The sweep D681 said was worth doing on its own: every remaining typed read
// in the loader. Each was `x, _ := m["k"].(T)`, so a wrong-typed value became the
// zero value and the field vanished from the canonical model — the document then
// hashing identically to one that never declared it.
//
// `meta.environment` is the sharpest: D610 refused a non-integer `meta.version` and
// left its sibling, and `environment` reaches resource TAGS and NAMES, so the estate
// would be stamped with an empty one while `validate` said OK.
func TestEveryTypedFieldInTheLoaderRefusesAWrongType(t *testing.T) {
	base := `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: t, owner: o@e.test, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
`
	for _, tc := range []struct{ name, doc, want string }{
		{"meta.environment as a number", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: t, owner: o@e.test, environment: 7, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
`, "meta.environment"},
		{"outcomes as a mapping", base + "outcomes:\n  id: o1\n", "outcomes"},
		{"capability type as a number", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: t, owner: o@e.test, environment: test, version: 1 }
capabilities:
  - id: db
    type: 7
`, "type"},
		// The `severity:` read lives in the BUDGET block — inside `constraints.hard`
		// the severity comes from the block name, so a key there is simply unread.
		// Aim at the site that exists.
		{"budget severity as a list", base + `budget:
  - { id: b1, subject: db, path: cost.monthly, op: lte,
      value: { amount: 100, currency: EUR }, severity: [hard],
      verify: { method: static } }
`, "severity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "c.yaml")
			if err := os.WriteFile(p, []byte(tc.doc), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadContract(p)
			if err == nil {
				t.Fatalf("accepted a wrong-typed field — it is dropped, and the "+
					"document then hashes like one that never declared it:\n%s", tc.doc)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not name the field: %v", err)
			}
		})
	}

	// The control: the well-formed document still loads with every field intact.
	p := filepath.Join(t.TempDir(), "ok.yaml")
	if err := os.WriteFile(p, []byte(base+"outcomes:\n  - { id: o1, probe: tcp-connect }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadContract(p)
	if err != nil {
		t.Fatalf("a well-formed contract was refused: %v", err)
	}
	if c.Environment != "test" || len(c.Outcomes) != 1 {
		t.Errorf("a field was dropped: env=%q outcomes=%d", c.Environment, len(c.Outcomes))
	}
}
