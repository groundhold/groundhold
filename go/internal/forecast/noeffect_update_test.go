package forecast

import (
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
)

// runFC builds a one-action plan for capability "db" and forecasts it with the given
// declared values and recorded observations.
func runFC(t *testing.T, op string, declared map[string]string,
	observed map[string]any) *Body {
	t.Helper()
	const eval = "2026-07-24T00:00:00Z"
	caps := map[string]map[string]contract.Provenanced{"db": {}}
	for k, v := range declared {
		caps["db"][k] = prov(t, "declared", v)
	}
	cand := &contract.Candidate{ContractID: "c-1", Capabilities: caps}
	obs := map[string]map[string]ledger.ObsRecord{"db": {}}
	for k, v := range observed {
		obs["db"][k] = ledger.ObsRecord{Value: v, ObservedAt: eval,
			TTLSeconds: 86400, Derivation: "measured", Source: "provider-api"}
	}
	action := map[string]any{"id": "a1", "capability": "db", "operation": op}
	plan := makePlan(t, cand, map[string]any{}, []any{action})
	doc, err := Forecast(plan, cand, nil, map[string]string{"db": "p:1"},
		map[string]int{"db": 1}, obs, eval)
	if err != nil {
		t.Fatalf("Forecast: %v", err)
	}
	return &doc.Forecast
}

// D577. Measured end to end on a live cluster: seal a plan that changes
// `pods.max` from 9 to 11, patch the ResourceQuota to 11 outside groundhold,
// re-observe, and forecast the sealed plan. It reports
//
//	effect: will-update      rollup: willUpdate 1, noEffect 0
//	attributes: [{path: pods.max, desired: 11, current: 11, prediction: "match"}]
//
// The attribute level is right and the headline contradicts it. A script routes on
// the rollup and a human skims it, and both are told a change is coming for a plan
// that changes nothing — the shape the pilot reported twice (D529's "nothing was
// changed" while the world HAD changed, D531's summary omitting capabilities).
//
// The precedent is in this same switch: a create against a bound capability is
// called `no-effect` because "the executor would 409-continue and change NOTHING —
// no-effect is the honest forecast OF THE ACTION". An update whose every predicted
// attribute already matches is the same statement about the same world, and the
// predictions are already computed one line below the verdict that ignores them.
func TestUpdateThatChangesNothingForecastsNoEffect(t *testing.T) {
	doc := runFC(t, "update", map[string]string{"residency": "eu-west1"},
		map[string]any{"residency": "eu-west1"})
	a := doc.Actions[0]
	if a.Effect != "no-effect" {
		t.Errorf("every attribute of this update already matches reality and the "+
			"forecast says %q\nattributes: %+v\nA rollup that counts it as an update "+
			"tells a script a change is coming for a plan that changes nothing.",
			a.Effect, a.Attributes)
	}
	if doc.Rollup.NoEffect != 1 || doc.Rollup.WillUpdate != 0 {
		t.Errorf("rollup disagrees with the per-action verdict: willUpdate=%d noEffect=%d",
			doc.Rollup.WillUpdate, doc.Rollup.NoEffect)
	}
}

// A genuine difference must still read as an update — the point is to distinguish
// them, not to soften every verdict.
func TestUpdateThatChangesSomethingStillForecastsWillUpdate(t *testing.T) {
	doc := runFC(t, "update", map[string]string{"residency": "eu-west1"},
		map[string]any{"residency": "us-east1"})
	if a := doc.Actions[0]; a.Effect != "will-update" {
		t.Errorf("an update whose target differs from reality forecast %q: %+v",
			a.Effect, a.Attributes)
	}
}

// An update with NO predicted attributes must not claim no-effect: that would be a
// conclusion drawn from absence, which is the failure this project keeps finding
// (D513, D522). Unknown is the honest word.
func TestUpdateWithNoPredictionsDoesNotClaimNoEffect(t *testing.T) {
	doc := runFC(t, "update", map[string]string{}, map[string]any{"residency": "eu-west1"})
	if a := doc.Actions[0]; a.Effect == "no-effect" {
		t.Errorf("an update with nothing predicted was called no-effect — a claim from "+
			"absence: %+v", a)
	}
}
