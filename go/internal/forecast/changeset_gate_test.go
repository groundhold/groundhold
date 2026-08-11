package forecast

import (
	"testing"

	"groundhold/internal/canonical"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/scalars"
)

// D639. The forecast is shown to a human immediately before they consent. Its
// no-effect branch decided "this changes nothing" from the CANDIDATE's vocabulary
// attributes and never looked at the ACTION's own change set — which is the plan's
// authoritative statement of what apply will do, and which apply hands to the driver's
// Update unconditionally.
//
// Two measured cases, both in the dangerous direction — predicted nothing, got a
// mutation:
//
//   - a plan sealed while the world drifted, then a newer observation showing the
//     target already reached: forecast `no-effect / target-already-matches`, apply
//     performed the update and bumped the binding generation;
//   - a change set on an OPERAND path (`implementation.*`): the forecast never mentions
//     the changed path at all — operands are not vocabulary attributes — and still
//     reported `noEffect: 1`. That needs no staging: any Lambda whose only drift is an
//     environment variable compiles inside plain `converge`, which prints the rollup on
//     the line directly above the consent prompt.
//
// Driven through Forecast itself, not through the helper: the first version of this
// test called `hasChanges` directly and stayed green when the mutation meter deleted
// its CALL SITE (D564, and the fifth time in this record).
func TestForecastNeverCallsAChangeSetNoEffect(t *testing.T) {
	// The candidate declares one attribute and the ledger observes the SAME value, so
	// D577's branch has something to match on. An empty prediction set is deliberately
	// NOT evidence of no effect (that entry's own comment), so a candidate with no
	// attributes cannot exercise the control.
	sc, serr := scalars.Parse(true)
	if serr != nil {
		t.Fatal(serr)
	}
	cand := &contract.Candidate{ContractID: "t",
		Capabilities: map[string]map[string]contract.Provenanced{
			"db": {"service.managed": {Scalar: sc, Status: "declared"}}}}
	candHash, err := canonical.HashCandidate(cand)
	if err != nil {
		t.Fatal(err)
	}
	plan := func(changes []any) map[string]any {
		a := map[string]any{
			"id": "a-update-db", "capability": "db", "operation": "update",
			"target": "fake:db-1",
		}
		if changes != nil {
			a["changes"] = changes
		}
		return map[string]any{"plan": map[string]any{
			"contract": "t", "environment": "test",
			"reads": map[string]any{
				"heads":         map[string]any{"db": "genesis"},
				"candidateHash": candHash,
			},
			"writes":  []any{"db"},
			"actions": []any{a},
		}}
	}
	bindings := map[string]string{"db": "fake:db-1"}
	obs := map[string]map[string]ledger.ObsRecord{
		"db": {"service.managed": {Value: true,
			ObservedAt: "2026-01-01T00:00:00Z", TTLSeconds: 3600,
			Derivation: "measured"}},
	}
	const at = "2026-01-01T00:00:00Z"

	t.Run("an operand change set is not no-effect", func(t *testing.T) {
		doc, err := Forecast(plan([]any{map[string]any{
			"path": "implementation.environment", "from": "A", "to": "B"}}),
			cand, map[string]string{"db": "genesis"}, bindings, nil, obs, at)
		if err != nil {
			t.Fatal(err)
		}
		if len(doc.Forecast.Actions) != 1 {
			t.Fatalf("expected one forecast action, got %d", len(doc.Forecast.Actions))
		}
		if got := doc.Forecast.Actions[0].Effect; got == "no-effect" {
			t.Errorf("an action carrying a change set was forecast as %q — apply calls "+
				"Update with exactly those paths, and the human consenting reads this "+
				"line", got)
		}
		if doc.Forecast.Rollup.NoEffect != 0 {
			t.Errorf("rollup counts a no-effect for an action that mutates: %+v",
				doc.Forecast.Rollup)
		}
	})

	// The control: D577's actual case — an update with no change set whose predictions
	// all match — must still report no-effect, or the fix has simply made the forecast
	// louder rather than truer.
	t.Run("no change set may still be no-effect", func(t *testing.T) {
		doc, err := Forecast(plan(nil), cand,
			map[string]string{"db": "genesis"}, bindings, nil, obs, at)
		if err != nil {
			t.Fatal(err)
		}
		if len(doc.Forecast.Actions) != 1 {
			t.Fatalf("expected one forecast action, got %d", len(doc.Forecast.Actions))
		}
		if got := doc.Forecast.Actions[0].Effect; got != "no-effect" {
			t.Errorf("an update with no change set and matching predictions was "+
				"forecast as %q — D577's case must keep working", got)
		}
	})
}
