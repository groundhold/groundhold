package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D658. D627 gated the SHAPE of `constraints`, `capabilities`, `budget`,
// `assumptions`, `requirements` and `verify`: a block of the wrong shape is not an
// empty block, and reading it as one silently drops everything in it. `autonomy`
// was not in that list, and it is the block that holds the consent gates.
//
// Measured: a contract writing `forbidden:` as a MAPPING instead of a list loses
// `delete_stateful`, and a bound, observed, stateful database is destroyed:
//
//	plan (list form)     plan refused: retiring db destroys a stateful capability
//	                     and the contract forbids delete_stateful       exit 2
//	plan (mapping form)  DELETE: 1 capability(ies) — db   SEALED        exit 0
//	apply                x delete db  R4, dataLoss certain              exit 0
//
// `validate` said OK for both. Worse, `autonomy:` written as a LIST is dropped
// whole and the contract then hashes IDENTICALLY to one with no autonomy block at
// all — so the identity that every sealed plan, capsule and signature pins cannot
// tell "I disarmed the consent gates" from "I never had any".
func TestAMisShapedAutonomyBlockIsRefused(t *testing.T) {
	base := `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: p, owner: o@e.test, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
`
	for _, tc := range []struct{ name, block, want string }{
		{"autonomy as a list", "autonomy:\n  - forbidden\n", "autonomy"},
		{"autonomy as a scalar", "autonomy: yes\n", "autonomy"},
		{"forbidden as a mapping", "autonomy:\n  forbidden:\n    delete_stateful: true\n",
			"forbidden"},
		{"forbidden as a scalar", "autonomy:\n  forbidden: delete_stateful\n", "forbidden"},
		// auto_execute is a MAPPING of thresholds, not a list — the shipped example
		// spec/examples/orders-production.contract.yaml says so, and it is the
		// authority over my reading of code that never touches the block.
		{"auto_execute as a list", "autonomy:\n  auto_execute:\n    - db\n", "auto_execute"},
		{"auto_execute thresholds", "autonomy:\n  auto_execute:\n    max_reversibility: R1\n  forbidden:\n    - delete_stateful: true\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "c.yaml")
			if err := os.WriteFile(p, []byte(base+tc.block), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadContract(p)
			if tc.want == "" {
				if err != nil {
					t.Errorf("a legitimate autonomy block was refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted: %s\nthe block was silently dropped, and every "+
					"consent gate it holds with it", tc.block)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not name the offending block: %v", err)
			}
		})
	}
}

// The control: a well-formed autonomy block must still load, with every knob
// readable. Refusing more than asked is the cheap way to pass the cases above.
func TestAWellFormedAutonomyBlockStillLoads(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(`apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: p, owner: o@e.test, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
autonomy:
  no_assumed_hard_basis: true
  auto_execute:
    max_reversibility: R1
    max_cost_delta: { amount: 100, currency: EUR }
  allow_replace_stateful:
    - db
  forbidden:
    - delete_stateful: true
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadContract(p)
	if err != nil {
		t.Fatalf("a well-formed autonomy block was refused: %v", err)
	}
	if c.Autonomy == nil {
		t.Fatal("the autonomy block was dropped")
	}
	forbidden, _ := c.Autonomy["forbidden"].([]any)
	if len(forbidden) != 1 {
		t.Errorf("forbidden did not survive the load: %+v", c.Autonomy)
	}
	if v, _ := c.Autonomy["no_assumed_hard_basis"].(bool); !v {
		t.Errorf("no_assumed_hard_basis did not survive the load: %+v", c.Autonomy)
	}
}
