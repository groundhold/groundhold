package apply

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"groundhold/internal/compiler"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/observe"
	"groundhold/internal/verify"
)

// D283 end to end — the re-plan-after-partial story the fold branch exists
// for: run 1 creates the producer and fails the consumer; observe records the
// bound producer's outputs; run 2's compile FOLDS the reference to a literal
// and the consumer lands. Then the apply-side gates: a fold beyond its TTL,
// and a fold whose backing observation has moved, both refuse pre-lease.

const foldAt1 = "2026-07-24T10:00:00Z"
const foldAt2 = "2026-07-24T10:01:00Z"
const foldAt3 = "2026-07-24T10:05:00Z"
const foldAtLate = "2026-07-24T12:00:00Z" // far beyond the 900s TTL

func compileWith(t *testing.T, led *ledger.Ledger, at string) (
	map[string]any, *refSpyDeps) {
	t.Helper()
	deps := loadRefDocs(t)
	report, _ := verify.Verify(deps.c, deps.cand, nil)
	if !report.Executable {
		t.Fatalf("not executable: %v", report.BlockingReasons)
	}
	evalClock, err := ledger.ParseTs(at)
	if err != nil {
		t.Fatal(err)
	}
	in := compiler.Inputs{
		Heads:        map[string]string{},
		Bindings:     map[string]string{},
		Observations: map[string]map[string]ledger.ObsRecord{},
		EvalClock:    evalClock,
	}
	if led != nil {
		in.Heads = led.DecisionHeads
		in.Bindings = led.BoundProviderIDs()
		in.BindingProviders = led.BoundProviderNames()
		in.Observations = led.Observations
		in.Outputs = led.Outputs // D286: the wiring projection
	}
	doc, err := compiler.Compile(deps.c, deps.cand, nil, report, "proj-x", in)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	raw, _ := json.Marshal(doc)
	var planDoc map[string]any
	if err := json.Unmarshal(raw, &planDoc); err != nil {
		t.Fatal(err)
	}
	return planDoc, deps
}

type refSpyDeps struct {
	c    *contract.Contract
	cand *contract.Candidate
}

func TestFoldSelfHealsAfterPartialFailure(t *testing.T) {
	lp := freshLedger(t)

	// ---- run 1: producer lands, consumer fails (injected) ----
	plan1, _ := compileWith(t, nil, foldAt1)
	dbKey := idemKeyOf(t, plan1, "a-create-db")
	spy1 := newRefSpy()
	spy1.Fake.FailKeys = map[string]bool{dbKey: true}
	c, cand, _ := setupRefPlan(t) // reuse the shared fixtures for Apply's contract args
	res := Apply(c, cand, nil, plan1, lp, spy1, foldAt1, false)
	if res.Status != "failed" {
		t.Fatalf("run 1 must fail on the injected consumer, got %s (%v)", res.Status, res.Reasons)
	}

	// ---- observe: record the bound producer's outputs ----
	led := replay(t, lp)
	if led.BoundProviderIDs()["network"] == "" {
		t.Fatal("run 1 must have bound the producer")
	}
	spyObs := newRefSpy()
	if _, err := observe.Run(led.BoundProviderIDs(), spyObs, foldAt2, 0,
		led, lp, true); err != nil {
		t.Fatal(err)
	}
	led = replay(t, lp)
	rec, ok := led.Outputs["network"]["privateSubnetIds"]
	if !ok {
		t.Fatalf("observe must record the wiring output privateSubnetIds, got %v",
			led.Outputs["network"])
	}

	// ---- run 2: compile folds, apply lands the consumer on the literal ----
	plan2 := recompile(t, led, foldAt3)
	folds := foldsOf(t, plan2, "a-create-db")
	if len(folds) != 1 {
		t.Fatalf("run 2 must fold the reference, actions: %v", plan2)
	}
	spy2 := newRefSpy()
	res = Apply(c, cand, nil, plan2, lp, spy2, foldAt3, false)
	if res.Status != "applied" {
		t.Fatalf("run 2 = %s (%v)", res.Status, res.Reasons)
	}
	got, _ := spy2.createImpl["db"]["subnetIds"].([]any)
	want, _ := rec.Value.([]any)
	if len(got) != 2 || len(want) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("consumer got %v, observation said %v", got, want)
	}
	// the fold-only consumer validated UP FRONT (no deferral): validate:db
	// precedes create:db and no network call ever happened in run 2.
	if strings.Join(spy2.log, ",") != "validate:db,create:db" {
		t.Fatalf("run 2 driver calls = %v", spy2.log)
	}
}

func TestFoldRefusesBeyondTTLAtApply(t *testing.T) {
	lp := freshLedger(t)
	plan1, _ := compileWith(t, nil, foldAt1)
	dbKey := idemKeyOf(t, plan1, "a-create-db")
	spy1 := newRefSpy()
	spy1.Fake.FailKeys = map[string]bool{dbKey: true}
	c, cand, _ := setupRefPlan(t)
	Apply(c, cand, nil, plan1, lp, spy1, foldAt1, false)
	led := replay(t, lp)
	if _, err := observe.Run(led.BoundProviderIDs(), newRefSpy(), foldAt2, 0,
		led, lp, true); err != nil {
		t.Fatal(err)
	}
	led = replay(t, lp)
	plan2 := recompile(t, led, foldAt3)

	// sealed fresh, applied DECAYED: the pre-lease gate refuses, exit 3.
	res := Apply(c, cand, nil, plan2, lp, newRefSpy(), foldAtLate, false)
	if res.Exit != 3 || len(res.Reasons) == 0 ||
		!strings.Contains(res.Reasons[0], "beyond its TTL") {
		t.Fatalf("decayed fold must refuse stale (exit 3), got %+v", res)
	}
}

func TestFoldRefusesWhenObservationMoved(t *testing.T) {
	lp := freshLedger(t)
	plan1, _ := compileWith(t, nil, foldAt1)
	dbKey := idemKeyOf(t, plan1, "a-create-db")
	spy1 := newRefSpy()
	spy1.Fake.FailKeys = map[string]bool{dbKey: true}
	c, cand, _ := setupRefPlan(t)
	Apply(c, cand, nil, plan1, lp, spy1, foldAt1, false)
	led := replay(t, lp)
	if _, err := observe.Run(led.BoundProviderIDs(), newRefSpy(), foldAt2, 0,
		led, lp, true); err != nil {
		t.Fatal(err)
	}
	led = replay(t, lp)
	plan2 := recompile(t, led, foldAt3)

	// the world moves between seal and apply: a NEWER outputs observation
	// carries a different subnet set — the sealed literal is superseded.
	w := &ledger.Writer{Path: lp, Led: led, Env: "test",
		Clock: mustTs(t, foldAt3), Actor: "test"}
	if err := w.Append("observation.recorded", []string{"network"},
		map[string]any{
			"provider": map[string]any{"name": "fake"},
			"resource": map[string]any{"providerId": led.BoundProviderIDs()["network"]},
			"observations": []any{map[string]any{
				"kind": "Observation", "capability": "network",
				"path":   "outputs.privateSubnetIds",
				"value":  []any{"subnet-CHANGED-a", "subnet-CHANGED-b"},
				"source": "provider-api", "derivation": "measured",
				"observedAt": foldAt3, "ttlSeconds": 900,
			}},
		}, 0); err != nil {
		t.Fatal(err)
	}

	res := Apply(c, cand, nil, plan2, lp, newRefSpy(), foldAt3, false)
	if res.Exit != 3 || len(res.Reasons) == 0 ||
		!strings.Contains(res.Reasons[0], "has moved since sealing") {
		t.Fatalf("a superseded fold must refuse stale (exit 3), got %+v", res)
	}
}

// ---- small helpers ----------------------------------------------------------

func idemKeyOf(t *testing.T, plan map[string]any, actionID string) string {
	t.Helper()
	p, _ := plan["plan"].(map[string]any)
	actions, _ := p["actions"].([]any)
	for _, it := range actions {
		a, _ := it.(map[string]any)
		if a["id"] == actionID {
			k, _ := a["idempotencyKey"].(string)
			return k
		}
	}
	t.Fatalf("action %s not found", actionID)
	return ""
}

func foldsOf(t *testing.T, plan map[string]any, actionID string) []any {
	t.Helper()
	p, _ := plan["plan"].(map[string]any)
	actions, _ := p["actions"].([]any)
	for _, it := range actions {
		a, _ := it.(map[string]any)
		if a["id"] == actionID {
			f, _ := a["folds"].([]any)
			return f
		}
	}
	t.Fatalf("action %s not found", actionID)
	return nil
}

func replay(t *testing.T, lp string) *ledger.Ledger {
	t.Helper()
	led, err := ledger.ReplayFile(lp)
	if err != nil {
		t.Fatal(err)
	}
	return led
}

func mustTs(t *testing.T, at string) int {
	t.Helper()
	c, err := ledger.ParseTs(at)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func recompile(t *testing.T, led *ledger.Ledger, at string) map[string]any {
	t.Helper()
	plan, _ := compileWith(t, led, at)
	return plan
}

// loadRefDocs loads the shared ref fixtures once per call — the same files
// setupRefPlan writes, without compiling.
func loadRefDocs(t *testing.T) *refSpyDeps {
	t.Helper()
	td := t.TempDir()
	cp := td + "/c.yaml"
	kp := td + "/k.yaml"
	if err := os.WriteFile(cp, []byte(refContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(refCandidate), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cp)
	if err != nil {
		t.Fatal(err)
	}
	cand, err := contract.LoadCandidate(kp, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &refSpyDeps{c: c, cand: cand}
}
