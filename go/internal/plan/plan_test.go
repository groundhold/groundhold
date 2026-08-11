package plan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	validHash  = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	validHash2 = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// ---------------------------------------------------------------------------
// requireHash: the sha256:<64 lowercase hex> shape gate.
// ---------------------------------------------------------------------------

func TestRequireHash(t *testing.T) {
	hex64 := strings.Repeat("a", 64)
	mixed := "sha256:0123456789abcdef" + strings.Repeat("0", 48)
	cases := []struct {
		name string
		in   any
		ok   bool
	}{
		{"all-a", "sha256:" + hex64, true},
		{"mixed-hex-digits", mixed, true},
		{"uppercase-hex-rejected", "sha256:" + strings.Repeat("A", 64), false},
		{"too-short-63", "sha256:" + strings.Repeat("a", 63), false},
		{"too-long-65", "sha256:" + strings.Repeat("a", 65), false},
		{"missing-prefix", hex64, false},
		{"wrong-prefix", "sha1:" + hex64, false},
		{"empty-string", "", false},
		{"non-string-int", 42, false},
		{"non-string-nil", nil, false},
		{"trailing-space", "sha256:" + hex64 + " ", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := requireHash(c.in, "x")
			if c.ok && err != nil {
				t.Fatalf("requireHash(%v) = %v, want nil", c.in, err)
			}
			if !c.ok && err == nil {
				t.Fatalf("requireHash(%v) = nil, want error", c.in)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// checkRisk: the mandatory risk vector (D33).
// ---------------------------------------------------------------------------

func riskOK() map[string]any {
	return map[string]any{
		"reversibility":       "R2",
		"dataLoss":            "none",
		"downtime":            "none",
		"securityExposure":    "none",
		"identityReplacement": false,
		"costDelta":           map[string]any{"amount": 0, "currency": "USD"},
	}
}

func TestCheckRisk(t *testing.T) {
	// amount accepts int / int64 / float64.
	for _, amt := range []any{0, int64(7), 1.5, -3} {
		r := riskOK()
		r["costDelta"] = map[string]any{"amount": amt, "currency": "USD"}
		if err := checkRisk("a1", r); err != nil {
			t.Errorf("checkRisk amount %#v (%T) = %v, want nil", amt, amt, err)
		}
	}

	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"not-a-map", nil}, // handled specially below
		{"missing-reversibility", func(r map[string]any) { delete(r, "reversibility") }},
		{"bad-reversibility", func(r map[string]any) { r["reversibility"] = "R5" }},
		{"missing-dataLoss", func(r map[string]any) { delete(r, "dataLoss") }},
		{"bad-downtime", func(r map[string]any) { r["downtime"] = "maybe" }},
		{"bad-securityExposure", func(r map[string]any) { r["securityExposure"] = "" }},
		{"identityReplacement-not-bool", func(r map[string]any) { r["identityReplacement"] = "false" }},
		{"identityReplacement-missing", func(r map[string]any) { delete(r, "identityReplacement") }},
		{"costDelta-not-map", func(r map[string]any) { r["costDelta"] = 5 }},
		{"costDelta-amount-string", func(r map[string]any) {
			r["costDelta"] = map[string]any{"amount": "0", "currency": "USD"}
		}},
		{"costDelta-amount-missing", func(r map[string]any) {
			r["costDelta"] = map[string]any{"currency": "USD"}
		}},
		{"costDelta-currency-empty", func(r map[string]any) {
			r["costDelta"] = map[string]any{"amount": 0, "currency": ""}
		}},
		{"costDelta-currency-missing", func(r map[string]any) {
			r["costDelta"] = map[string]any{"amount": 0}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var risk any
			if c.mutate == nil {
				risk = "not-a-map"
			} else {
				r := riskOK()
				c.mutate(r)
				risk = r
			}
			if err := checkRisk("a1", risk); err == nil {
				t.Fatalf("checkRisk(%s) = nil, want error", c.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// LoadPlan: full structural validation over a round-tripped YAML document.
// ---------------------------------------------------------------------------

func basePlan() map[string]any {
	return map[string]any{
		"kind":       "SealedPlan",
		"apiVersion": "plan/v0",
		"plan": map[string]any{
			"contract": "c-demo",
			"reads": map[string]any{
				"contractHash":  validHash,
				"candidateHash": validHash2,
				"heads": map[string]any{
					"capA": "genesis",
					"capB": validHash,
				},
				"toolchain": map[string]any{
					"compiler": "groundhold/test",
					"spec":     "plan/v0",
				},
			},
			"writes": []any{"capA", "capB"},
			"actions": []any{
				map[string]any{
					"id": "a1", "capability": "capA", "operation": "create",
					"idempotencyKey": "k1", "risk": riskOK(),
				},
				map[string]any{
					"id": "a2", "capability": "capB", "operation": "create",
					"idempotencyKey": "k2", "dependsOn": []any{"a1"}, "risk": riskOK(),
				},
			},
			"preconditions": []any{
				map[string]any{"type": "report-executable"},
			},
		},
	}
}

func planBlock(m map[string]any) map[string]any  { return m["plan"].(map[string]any) }
func readsBlock(m map[string]any) map[string]any { return planBlock(m)["reads"].(map[string]any) }
func actionsOf(m map[string]any) []any           { return planBlock(m)["actions"].([]any) }
func actionN(m map[string]any, i int) map[string]any {
	return actionsOf(m)[i].(map[string]any)
}

func loadFromMap(t *testing.T, m map[string]any) (map[string]any, error) {
	t.Helper()
	b, err := yaml.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	p := filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return LoadPlan(p)
}

func TestLoadPlanValid(t *testing.T) {
	doc, err := loadFromMap(t, basePlan())
	if err != nil {
		t.Fatalf("valid plan refused: %v", err)
	}
	if doc["kind"] != "SealedPlan" {
		t.Fatalf("returned doc kind = %v", doc["kind"])
	}
}

// Validation is order-independent: an action may be listed before the action
// it depends on. This pins the "no hidden ordering assumption" invariant of
// the load path (the Kahn cycle check must not assume list order).
func TestLoadPlanActionOrderIndependent(t *testing.T) {
	m := basePlan()
	acts := actionsOf(m)
	acts[0], acts[1] = acts[1], acts[0] // a2 (depends on a1) now first
	if _, err := loadFromMap(t, m); err != nil {
		t.Fatalf("reordered-but-acyclic plan refused: %v", err)
	}
}

// A diamond DAG (a1 -> a2, a1 -> a3, a2/a3 -> a4) is acyclic and must load.
func TestLoadPlanDiamondDAG(t *testing.T) {
	m := basePlan()
	planBlock(m)["writes"] = []any{"capA", "capB"}
	readsBlock(m)["heads"] = map[string]any{"capA": "genesis", "capB": validHash}
	mk := func(id string, deps ...string) map[string]any {
		a := map[string]any{
			"id": id, "capability": "capA", "operation": "create",
			"idempotencyKey": "k-" + id, "risk": riskOK(),
		}
		if len(deps) > 0 {
			dl := make([]any, len(deps))
			for i, d := range deps {
				dl[i] = d
			}
			a["dependsOn"] = dl
		}
		return a
	}
	planBlock(m)["actions"] = []any{
		mk("a4", "a2", "a3"), mk("a2", "a1"), mk("a3", "a1"), mk("a1"),
	}
	if _, err := loadFromMap(t, m); err != nil {
		t.Fatalf("diamond DAG refused: %v", err)
	}
}

func TestLoadPlanValidDelete(t *testing.T) {
	m := basePlan()
	a := actionN(m, 0)
	a["operation"] = "delete"
	a["targetProviderId"] = "projects/p/instances/i"
	a["targetGeneration"] = 3
	if _, err := loadFromMap(t, m); err != nil {
		t.Fatalf("valid delete refused: %v", err)
	}
}

func TestLoadPlanValidUpdate(t *testing.T) {
	m := basePlan()
	a := actionN(m, 0)
	a["operation"] = "update"
	a["changes"] = []any{
		map[string]any{"path": "settings.tier", "to": "db-n1-standard-2"},
	}
	if _, err := loadFromMap(t, m); err != nil {
		t.Fatalf("valid update refused: %v", err)
	}
}

// An update whose only change sets a value to null still counts: the gate is
// presence of the "to" key, not truthiness.
func TestLoadPlanUpdateToNullPresent(t *testing.T) {
	m := basePlan()
	a := actionN(m, 0)
	a["operation"] = "update"
	a["changes"] = []any{map[string]any{"path": "x", "to": nil}}
	if _, err := loadFromMap(t, m); err != nil {
		t.Fatalf("update with explicit null 'to' refused: %v", err)
	}
}

func TestLoadPlanValidWitnessed(t *testing.T) {
	m := basePlan()
	readsBlock(m)["heads"] = map[string]any{
		"capA": "genesis", "capB": validHash, "capW": validHash2,
	}
	planBlock(m)["witnessed"] = []any{
		map[string]any{
			"capability": "capW", "provider": "gcp",
			"service": "cloudsql", "reason": "shared vpc",
		},
	}
	if _, err := loadFromMap(t, m); err != nil {
		t.Fatalf("valid witnessed refused: %v", err)
	}
}

func TestLoadPlanRejects(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(map[string]any)
		wantSub string
	}{
		{"wrong-kind", func(m map[string]any) { m["kind"] = "Nope" }, "kind must be SealedPlan"},
		{"wrong-apiVersion", func(m map[string]any) { m["apiVersion"] = "plan/v1" }, "apiVersion must be plan/v0"},
		{"missing-plan-block", func(m map[string]any) { delete(m, "plan") }, "plan block is required"},
		{"empty-contract", func(m map[string]any) { planBlock(m)["contract"] = "" }, "plan.contract is required"},
		{"missing-reads", func(m map[string]any) { delete(planBlock(m), "reads") }, "plan.reads is required"},
		{"bad-contractHash", func(m map[string]any) { readsBlock(m)["contractHash"] = "nope" }, "reads.contractHash"},
		{"bad-candidateHash", func(m map[string]any) { readsBlock(m)["candidateHash"] = "nope" }, "reads.candidateHash"},
		{"head-neither-genesis-nor-hash", func(m map[string]any) {
			readsBlock(m)["heads"] = map[string]any{"capA": "later", "capB": validHash}
		}, "reads.heads[capA]"},
		{"toolchain-missing-compiler", func(m map[string]any) {
			readsBlock(m)["toolchain"] = map[string]any{"spec": "plan/v0"}
		}, "toolchain must carry compiler and spec"},
		{"toolchain-missing-spec", func(m map[string]any) {
			readsBlock(m)["toolchain"] = map[string]any{"compiler": "x"}
		}, "toolchain must carry compiler and spec"},
		{"write-not-in-heads", func(m map[string]any) {
			planBlock(m)["writes"] = []any{"capA", "capB", "capX"}
		}, "cannot write what you did not read"},
		{"write-not-string", func(m map[string]any) {
			planBlock(m)["writes"] = []any{"capA", 7}
		}, "plan.writes must be a non-empty list"},
		{"action-missing-id", func(m map[string]any) {
			planBlock(m)["actions"] = []any{map[string]any{"capability": "capA"}}
		}, "action missing id"},
		{"duplicate-action-id", func(m map[string]any) {
			actionN(m, 1)["id"] = "a1"
		}, "duplicate action id"},
		{"capability-outside-writes", func(m map[string]any) {
			actionN(m, 0)["capability"] = "capZ"
		}, "capability outside plan.writes"},
		{"unknown-operation", func(m map[string]any) {
			actionN(m, 0)["operation"] = "destroy"
		}, "unknown operation"},
		{"missing-idempotencyKey", func(m map[string]any) {
			delete(actionN(m, 0), "idempotencyKey")
		}, "idempotencyKey is required"},
		{"missing-risk", func(m map[string]any) {
			delete(actionN(m, 0), "risk")
		}, "risk vector is required"},
		{"delete-missing-targetProviderId", func(m map[string]any) {
			a := actionN(m, 0)
			a["operation"] = "delete"
			a["targetGeneration"] = 1
		}, "delete requires targetProviderId"},
		{"delete-missing-generation", func(m map[string]any) {
			a := actionN(m, 0)
			a["operation"] = "delete"
			a["targetProviderId"] = "projects/p/instances/i"
		}, "delete requires targetGeneration"},
		{"delete-generation-zero", func(m map[string]any) {
			a := actionN(m, 0)
			a["operation"] = "delete"
			a["targetProviderId"] = "projects/p/instances/i"
			a["targetGeneration"] = 0
		}, "delete requires targetGeneration"},
		{"update-missing-changes", func(m map[string]any) {
			actionN(m, 0)["operation"] = "update"
		}, "update requires a non-empty changes"},
		{"update-empty-changes", func(m map[string]any) {
			a := actionN(m, 0)
			a["operation"] = "update"
			a["changes"] = []any{}
		}, "update requires a non-empty changes"},
		{"update-change-missing-path", func(m map[string]any) {
			a := actionN(m, 0)
			a["operation"] = "update"
			a["changes"] = []any{map[string]any{"to": "x"}}
		}, "each change needs path and to"},
		{"update-change-missing-to", func(m map[string]any) {
			a := actionN(m, 0)
			a["operation"] = "update"
			a["changes"] = []any{map[string]any{"path": "settings.tier"}}
		}, "each change needs path and to"},
		{"dependsOn-unknown", func(m map[string]any) {
			actionN(m, 1)["dependsOn"] = []any{"ghost"}
		}, "dependsOn unknown action"},
		{"cycle", func(m map[string]any) {
			actionN(m, 0)["dependsOn"] = []any{"a2"} // a1<->a2
		}, "cycle"},
		{"self-cycle", func(m map[string]any) {
			actionN(m, 0)["dependsOn"] = []any{"a1"}
		}, "cycle"},
		{"unknown-precondition-type", func(m map[string]any) {
			planBlock(m)["preconditions"] = []any{map[string]any{"type": "always-true"}}
		}, "unknown precondition type"},
		{"missing-report-executable", func(m map[string]any) {
			planBlock(m)["preconditions"] = []any{map[string]any{"type": "within-autonomy"}}
		}, "must include report-executable"},
		{"witnessed-not-a-list", func(m map[string]any) {
			planBlock(m)["witnessed"] = "capW"
		}, "plan.witnessed must be a list"},
		{"witnessed-missing-provider", func(m map[string]any) {
			readsBlock(m)["heads"] = map[string]any{"capA": "genesis", "capB": validHash, "capW": validHash2}
			planBlock(m)["witnessed"] = []any{
				map[string]any{"capability": "capW", "service": "s", "reason": "r"},
			}
		}, "provider is required"},
		{"witnessed-no-pinned-head", func(m map[string]any) {
			planBlock(m)["witnessed"] = []any{
				map[string]any{"capability": "capW", "provider": "gcp", "service": "s", "reason": "r"},
			}
		}, "witnessed capW has no pinned head"},
		{"witnessed-also-in-writes", func(m map[string]any) {
			planBlock(m)["witnessed"] = []any{
				map[string]any{"capability": "capA", "provider": "gcp", "service": "s", "reason": "r"},
			}
		}, "also in plan.writes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := basePlan()
			c.mutate(m)
			_, err := loadFromMap(t, m)
			if err == nil {
				t.Fatalf("%s: LoadPlan = nil, want error containing %q", c.name, c.wantSub)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("%s: err = %q, want substring %q", c.name, err.Error(), c.wantSub)
			}
		})
	}
}

func TestLoadPlanMissingFile(t *testing.T) {
	if _, err := LoadPlan(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("LoadPlan on missing file = nil, want error")
	}
}

func TestLoadPlanEmptyDocument(t *testing.T) {
	p := filepath.Join(t.TempDir(), "empty.yaml")
	if err := os.WriteFile(p, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPlan(p); err == nil {
		t.Fatal("LoadPlan on empty document = nil, want error")
	}
}
