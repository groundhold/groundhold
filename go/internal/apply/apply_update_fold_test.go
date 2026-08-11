package apply

import (
	"encoding/json"
	"fmt"
	"testing"

	"groundhold/internal/compiler"
	"groundhold/internal/ledger"
	"groundhold/internal/observe"
	"groundhold/internal/provider"
	"groundhold/internal/verify"
)

// D962: the apply-side half of the D961 fold. The compiler seals the resolved
// literal onto an UPDATE action's Folds, and apply re-judges its freshness
// pre-lease (foldStaleReason) — but the impl handed to prov.Update must be the
// FOLDED one, or a driver that re-pushes a full body from raw implementation
// (Lambda's UpdateFunctionConfiguration) drops the wired operand and STRIPS it as
// collateral of an unrelated change, reporting success. This exercises apply's
// update dispatch end to end and asserts the driver receives the resolved
// operand, not the raw $ref.
//
// updSpy is an OperandDrifter (so a bound resource's wired operand drifts and
// produces an update) that records the implementation map its Update call got.
type updSpy struct {
	*provider.Fake
	updateImpl map[string]map[string]any
}

func newUpdSpy() *updSpy {
	return &updSpy{Fake: &provider.Fake{}, updateImpl: map[string]map[string]any{}}
}

func (s *updSpy) OperandTargets(service string, attrs, impl map[string]any) ([]provider.OperandTarget, error) {
	if v, ok := impl["subnetIds"]; ok {
		return []provider.OperandTarget{{
			Path: provider.OperandPrefix + "subnetIds", Desired: fmt.Sprint(v)}}, nil
	}
	return nil, nil
}

func (s *updSpy) ClassifyChange(service, path string, current, desired any,
	impl map[string]any) (string, string) {
	if path == provider.OperandPrefix+"subnetIds" {
		return "mutable", "subnets patched in place"
	}
	return s.Fake.ClassifyChange(service, path, current, desired, impl)
}

func (s *updSpy) Update(service, capability, environment, providerID string,
	attrs, impl map[string]any, changes []string, key string) provider.CreateResult {
	cp := map[string]any{}
	for k, v := range impl {
		cp[k] = v
	}
	s.updateImpl[capability] = cp
	return s.Fake.Update(service, capability, environment, providerID, attrs, impl, changes, key)
}

func compileUpd(t *testing.T, deps *refSpyDeps, led *ledger.Ledger, spy provider.Provider, at string) map[string]any {
	t.Helper()
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
		Providers:    map[string]provider.Provider{"fake": spy, "": spy},
	}
	if led != nil {
		in.Heads = led.DecisionHeads
		in.Bindings = led.BoundProviderIDs()
		in.BindingProviders = led.BoundProviderNames()
		in.Observations = led.Observations
		in.Outputs = led.Outputs
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
	return planDoc
}

func TestApplyUpdateFeedsTheFoldedImplToTheDriver(t *testing.T) {
	deps := loadRefDocs(t)
	c, cand := deps.c, deps.cand
	lp := freshLedger(t)

	// ---- run 1: create network + db (both bind); db's subnetIds resolves from
	// network's create receipt in-run (D275) ----
	spy1 := newUpdSpy()
	plan1 := compileUpd(t, deps, nil, spy1, foldAt1)
	if res := Apply(c, cand, nil, plan1, lp, spy1, foldAt1, false); res.Status != "applied" {
		t.Fatalf("run 1 create = %s (%v)", res.Status, res.Reasons)
	}

	// ---- observe: record network's outputs (so run 2 can fold subnetIds) ----
	led := replay(t, lp)
	if _, err := observe.Run(led.BoundProviderIDs(), newUpdSpy(), foldAt2, 0, led, lp, true); err != nil {
		t.Fatal(err)
	}
	led = replay(t, lp)
	out, ok := led.Outputs["network"]["privateSubnetIds"]
	if !ok {
		t.Fatalf("observe must record network's privateSubnetIds, got %v", led.Outputs["network"])
	}

	// ---- force an operand drift: db's live subnetIds moved out of band, so a
	// re-plan produces an UPDATE that carries the subnetIds fold ----
	w := &ledger.Writer{Path: lp, Led: led, Env: "test", Clock: mustTs(t, foldAt2), Actor: "test"}
	if err := w.Append("observation.recorded", []string{"db"},
		map[string]any{
			"provider": map[string]any{"name": ""},
			"resource": map[string]any{"providerId": led.BoundProviderIDs()["db"]},
			"observations": []any{map[string]any{
				"kind": "Observation", "capability": "db",
				"path":   provider.OperandPrefix + "subnetIds",
				"value":  "subnets=STALE-OUT-OF-BAND",
				"source": "provider-api", "derivation": "measured",
				"observedAt": foldAt2, "ttlSeconds": 900,
			}},
		}, 0); err != nil {
		t.Fatal(err)
	}
	led = replay(t, lp)

	// ---- run 2: the plan must carry an update for db with the subnetIds fold ----
	spy2 := newUpdSpy()
	plan2 := compileUpd(t, deps, led, spy2, foldAt3)
	folds := foldsOf(t, plan2, "a-update-db")
	if len(folds) != 1 {
		t.Fatalf("the db update must carry the subnetIds fold, actions: %v", plan2["plan"])
	}

	if res := Apply(c, cand, nil, plan2, lp, spy2, foldAt3, false); res.Status != "applied" {
		t.Fatalf("run 2 update = %s (%v)", res.Status, res.Reasons)
	}

	// THE ASSERTION: the driver's Update received the RESOLVED subnet list from the
	// fold, not the raw {$ref} map. Without apply feeding the folded impl, a
	// full-body re-push would drop the wired operand (the D961 strip, apply-side).
	got, ok := spy2.updateImpl["db"]["subnetIds"].([]any)
	if !ok {
		t.Fatalf("prov.Update got subnetIds = %#v (raw $ref, unfolded) — apply fed the driver "+
			"the unresolved operand; a full-body re-push would STRIP it", spy2.updateImpl["db"]["subnetIds"])
	}
	want, _ := out.Value.([]any)
	if len(got) != len(want) || len(got) == 0 {
		t.Fatalf("prov.Update subnetIds = %v, want the folded producer output %v", got, want)
	}
}
