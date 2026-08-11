package plan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D533, from the field: converged infrastructure produced `AKCJI: 0, NO-OP: 16`,
// the compiler sealed the plan, and apply refused it with
// `reads.heads must pin a head per capability` — exit 2, indistinguishable from a
// real refusal. "Is there anything to deploy" had to be decided outside the tool.
//
// The compiler seals a zero-action plan DELIBERATELY (compiler.go: a blocked or
// unverified capability is not "nothing to change"), so the validator was refusing
// an artefact its own compiler intends to produce. Two checks conflated "the key is
// missing or ill-typed" with "the key is present and legitimately empty":
// `plan.actions` and `reads.heads`. With no actions there are no heads to pin,
// because heads are pinned per capability WITH an action.
func TestZeroActionPlanValidates(t *testing.T) {
	doc := zeroActionPlan()
	if _, err := loadFrom(t, doc); err != nil {
		t.Fatalf("a sealed zero-action plan was refused: %v\n"+
			"converged infrastructure must exit 0 saying nothing to do, not refuse", err)
	}
}

// The invariant that DOES hold must survive: an action's capability needs a pinned
// head, so actions without heads is still a malformed plan.
func TestActionsWithoutHeadsStillRefused(t *testing.T) {
	doc := zeroActionPlan()
	p := doc["plan"].(map[string]any)
	p["actions"] = []any{map[string]any{
		"id": "a-create-db", "capability": "db", "operation": "create",
		"target": "aws.rds/db", "idempotencyKey": "k",
	}}
	_, err := loadFrom(t, doc)
	if err == nil {
		t.Fatal("a plan with an action and no pinned head was accepted")
	}
	if !strings.Contains(err.Error(), "heads") {
		t.Errorf("refusal does not name heads: %v", err)
	}
}

// The verify gate is NOT in this class: report-executable is mandatory on every
// plan the compiler emits, converged or not (D195, the thesis), so the fixture
// carries it and the validator keeps demanding it.

// A missing or ill-typed key is still malformed — the fix must not turn a
// structural error into silence.
func TestMissingKeysStillRefused(t *testing.T) {
	for _, drop := range []string{"actions", "heads"} {
		doc := zeroActionPlan()
		p := doc["plan"].(map[string]any)
		if drop == "actions" {
			delete(p, "actions")
		} else {
			delete(p["reads"].(map[string]any), "heads")
		}
		if _, err := loadFrom(t, doc); err == nil {
			t.Errorf("a plan with %q missing was accepted", drop)
		}
	}
}

func zeroActionPlan() map[string]any {
	const src = `{
      "apiVersion": "plan/v0",
      "kind": "SealedPlan",
      "plan": {
        "contract": "orders",
        "environment": "prod",
        "reads": {
          "contractHash": "sha256:` + hex64 + `",
          "candidateHash": "sha256:` + hex64 + `",
          "heads": {},
          "toolchain": {"compiler": "groundhold/0.1", "spec": "sealed-plan/v0.1"}
        },
        "actions": [],
        "writes": [],
        "preconditions": [{"type": "report-executable"}]
      }
    }`
	var doc map[string]any
	if err := json.Unmarshal([]byte(src), &doc); err != nil {
		panic(err)
	}
	return doc
}

const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// loadFrom writes the document and runs it through LoadPlan, which is where the
// validation lives.
func loadFrom(t *testing.T, doc map[string]any) (map[string]any, error) {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadPlan(path)
}
