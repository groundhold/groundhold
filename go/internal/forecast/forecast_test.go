package forecast

import (
	"testing"

	"groundhold/internal/canonical"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/scalars"
)

// ---- helpers ---------------------------------------------------------------

// prov builds a Provenanced attribute. A nil raw yields a status-only
// attribute with no scalar (the Status == "unknown" shape).
func prov(t *testing.T, status string, raw any) contract.Provenanced {
	t.Helper()
	if raw == nil {
		return contract.Provenanced{Status: status}
	}
	sc, err := scalars.Parse(raw)
	if err != nil {
		t.Fatalf("prov: parse %v: %v", raw, err)
	}
	return contract.Provenanced{Scalar: sc, Status: status}
}

// scalarOf parses raw into a *scalars.Scalar for direct compare() tests.
func scalarOf(t *testing.T, raw any) *scalars.Scalar {
	t.Helper()
	sc, err := scalars.Parse(raw)
	if err != nil {
		t.Fatalf("scalarOf: parse %v: %v", raw, err)
	}
	return sc
}

// makePlan assembles a plan document whose reads pin the candidate by its
// real hash (the identity gate the engine enforces) plus the given heads.
func makePlan(t *testing.T, cand *contract.Candidate, heads map[string]any,
	actions []any) map[string]any {
	t.Helper()
	h, err := canonical.HashCandidate(cand)
	if err != nil {
		t.Fatalf("hash candidate: %v", err)
	}
	reads := map[string]any{"candidateHash": h}
	if heads != nil {
		reads["heads"] = heads
	}
	return map[string]any{
		"plan": map[string]any{
			"contract":    cand.ContractID,
			"environment": "test",
			"reads":       reads,
			"actions":     actions,
		},
	}
}

func attrByPath(attrs []Attribute, path string) (Attribute, bool) {
	for _, a := range attrs {
		if a.Path == path {
			return a, true
		}
	}
	return Attribute{}, false
}

// ---- compare(): the four-valued prediction core ----------------------------

// TestCompareFourValued pins the closed prediction set of compare():
// match | differ | unknown | unverifiable. A kind/currency mismatch is
// unverifiable, NEVER a false "differ" (D3/D6, invariant #2 no coercion);
// canonical equality means 5m == 300s (D25); a nil desired is unknown.
func TestCompareFourValued(t *testing.T) {
	cases := []struct {
		name           string
		desired        *scalars.Scalar
		observed       any
		wantPrediction string
		wantReason     string
	}{
		{"nil-desired", nil, "anything", "unknown", "desired-value-unknown"},
		{"duration-equal", scalarOf(t, "5m"), "5m", "match", ""},
		{"duration-canonical-equal", scalarOf(t, "5m"), "300s", "match", ""},
		{"duration-differ", scalarOf(t, "5m"), "10m", "differ", ""},
		{"string-match", scalarOf(t, "private"), "private", "match", ""},
		{"string-differ", scalarOf(t, "private"), "public", "differ", ""},
		{"kind-mismatch-duration-vs-number", scalarOf(t, "5m"), 300, "unverifiable", "kind-mismatch"},
		{"currency-mismatch", scalarOf(t, "10 USD"), "10 EUR", "unverifiable", "kind-mismatch"},
		{"unparseable-observation", scalarOf(t, "private"), nil, "unverifiable", "unparseable-observation"},
		{"money-equal", scalarOf(t, "10 USD"), "10 USD", "match", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotPred, gotReason := compare(c.desired, c.observed)
			if gotPred != c.wantPrediction || gotReason != c.wantReason {
				t.Errorf("compare()=(%q,%q) want (%q,%q)",
					gotPred, gotReason, c.wantPrediction, c.wantReason)
			}
		})
	}
}

// ---- desiredOnly(): provenance survives into a create forecast -------------

// TestDesiredOnlyProvenanceSurvives pins invariant #3: the candidate's
// provenance status (declared|inferred|assumed|unknown) propagates into the
// Basis of every predicted attribute, and attributes come out path-sorted.
func TestDesiredOnlyProvenanceSurvives(t *testing.T) {
	cand := &contract.Candidate{
		ContractID: "c-1",
		Capabilities: map[string]map[string]contract.Provenanced{
			"db": {
				"residency":     prov(t, "declared", "eu-west1"),
				"backup.rpo":    prov(t, "inferred", "5m"),
				"cost.monthly":  prov(t, "assumed", "10 USD"),
				"tier.internal": prov(t, "unknown", nil),
			},
		},
	}
	got := desiredOnly(cand, "db")

	// path-sorted order
	wantOrder := []string{"backup.rpo", "cost.monthly", "residency", "tier.internal"}
	if len(got) != len(wantOrder) {
		t.Fatalf("got %d attrs, want %d", len(got), len(wantOrder))
	}
	for i, p := range wantOrder {
		if got[i].Path != p {
			t.Errorf("attr[%d].Path=%q want %q (not path-sorted)", i, got[i].Path, p)
		}
	}

	wantBasis := map[string]string{
		"residency":     "declared",
		"backup.rpo":    "inferred",
		"cost.monthly":  "assumed",
		"tier.internal": "unknown",
	}
	for path, basis := range wantBasis {
		a, ok := attrByPath(got, path)
		if !ok {
			t.Fatalf("missing attr %q", path)
		}
		if a.Basis != basis {
			t.Errorf("attr %q Basis=%q want %q (provenance lost)", path, a.Basis, basis)
		}
		if a.Prediction != "" {
			t.Errorf("attr %q Prediction=%q, want empty (create is desired-only)", path, a.Prediction)
		}
	}
	// unknown-status attribute carries no desired value
	tier, _ := attrByPath(got, "tier.internal")
	if tier.Desired != nil {
		t.Errorf("unknown-status attr Desired=%v, want nil", tier.Desired)
	}
}

// ---- predict(): four-valued attribute predictions + freshness --------------

// TestPredictFourValuedAndFreshness pins predict()'s per-attribute outcomes
// against a fresh evaluation clock: match/differ/unknown/unverifiable, the
// freshness degradation (stale -> unknown, D27), missing observation, and the
// invalid (negative-age / future) observation. Basis survives throughout.
func TestPredictFourValuedAndFreshness(t *testing.T) {
	const eval = 1_000_000 // evaluation clock (unix seconds)
	// observedAt strings resolve via ledger.ParseTs (RFC3339 -> unix).
	// 1970-01-12T13:46:40Z == 1_000_000; earlier == older.
	const atEval = "1970-01-12T13:46:40Z"   // age 0
	const atFresh = "1970-01-12T13:46:30Z"  // age 10
	const atStale = "1970-01-01T00:00:00Z"  // age ~1e6, way past ttl
	const atFuture = "1970-01-12T13:47:40Z" // age -60 (future)

	cand := &contract.Candidate{
		ContractID: "c-1",
		Capabilities: map[string]map[string]contract.Provenanced{
			"db": {
				"residency":  prov(t, "declared", "eu-west1"), // match
				"backup.rpo": prov(t, "inferred", "5m"),       // differ
				"exposure":   prov(t, "assumed", "private"),   // stale -> unknown
				"cost":       prov(t, "declared", "10 USD"),   // future -> unverifiable
				"note":       prov(t, "declared", "hello"),    // no observation
				"kindclash":  prov(t, "declared", "5m"),       // kind mismatch -> unverifiable
			},
		},
	}
	obs := map[string]ledger.ObsRecord{
		"residency":  {Value: "eu-west1", ObservedAt: atEval, TTLSeconds: 3600, Derivation: "measured"},
		"backup.rpo": {Value: "10m", ObservedAt: atFresh, TTLSeconds: 3600, Derivation: "inferred"},
		"exposure":   {Value: "private", ObservedAt: atStale, TTLSeconds: 3600, Derivation: "measured"},
		"cost":       {Value: "10 USD", ObservedAt: atFuture, TTLSeconds: 3600, Derivation: "measured"},
		"kindclash":  {Value: 300, ObservedAt: atEval, TTLSeconds: 3600, Derivation: "measured"},
	}

	var rollup Rollup
	got := predict(cand, "db", obs, eval, &rollup)

	type want struct{ pred, reason, basis string }
	wants := map[string]want{
		"residency":  {"match", "", "declared"},
		"backup.rpo": {"differ", "", "inferred"},
		"exposure":   {"unknown", "stale-observation", "assumed"},
		"cost":       {"unverifiable", "invalid-observation", "declared"},
		"note":       {"unknown", "missing-observation", "declared"},
		"kindclash":  {"unverifiable", "kind-mismatch", "declared"},
	}
	for path, w := range wants {
		a, ok := attrByPath(got, path)
		if !ok {
			t.Fatalf("missing attr %q", path)
		}
		if a.Prediction != w.pred {
			t.Errorf("attr %q Prediction=%q want %q", path, a.Prediction, w.pred)
		}
		if a.Reason != w.reason {
			t.Errorf("attr %q Reason=%q want %q", path, a.Reason, w.reason)
		}
		if a.Basis != w.basis {
			t.Errorf("attr %q Basis=%q want %q (provenance lost)", path, a.Basis, w.basis)
		}
	}

	// rollup counters: differ=1, unknown=2 (stale+missing), unverifiable=2
	// (invalid + kind-mismatch). match is not counted.
	if rollup.DriftingAttributes != 1 {
		t.Errorf("DriftingAttributes=%d want 1", rollup.DriftingAttributes)
	}
	if rollup.UnknownAttributes != 2 {
		t.Errorf("UnknownAttributes=%d want 2", rollup.UnknownAttributes)
	}
	if rollup.UnverifiableAttributes != 2 {
		t.Errorf("UnverifiableAttributes=%d want 2", rollup.UnverifiableAttributes)
	}

	// Current/derivation/age carried through for an observed attribute.
	res, _ := attrByPath(got, "residency")
	if res.Current != "eu-west1" || res.CurrentDerivation != "measured" || res.ObservationAge != 0 {
		t.Errorf("residency carry-through: current=%v deriv=%q age=%d",
			res.Current, res.CurrentDerivation, res.ObservationAge)
	}
	// A missing observation carries no current value.
	note, _ := attrByPath(got, "note")
	if note.Current != nil {
		t.Errorf("missing-observation attr Current=%v want nil", note.Current)
	}
}

// TestPredictStaleBoundaryInclusive pins the freshness boundary: age == ttl
// is still fresh (the code degrades only when age > ttl).
func TestPredictStaleBoundaryInclusive(t *testing.T) {
	const eval = 1_000_000
	const at = "1970-01-12T13:46:30Z" // age 10
	cand := &contract.Candidate{
		ContractID: "c-1",
		Capabilities: map[string]map[string]contract.Provenanced{
			"db": {"residency": prov(t, "declared", "eu-west1")},
		},
	}
	obs := map[string]ledger.ObsRecord{
		"residency": {Value: "eu-west1", ObservedAt: at, TTLSeconds: 10, Derivation: "measured"},
	}
	var rollup Rollup
	got := predict(cand, "db", obs, eval, &rollup)
	a, _ := attrByPath(got, "residency")
	if a.Prediction != "match" {
		t.Errorf("age==ttl Prediction=%q (reason %q) want match", a.Prediction, a.Reason)
	}
}

// ---- Forecast(): the closed effect set -------------------------------------

func baseCandidate(t *testing.T) *contract.Candidate {
	t.Helper()
	return &contract.Candidate{
		ContractID: "c-1",
		Capabilities: map[string]map[string]contract.Provenanced{
			"db": {"residency": prov(t, "declared", "eu-west1")},
		},
	}
}

func TestForecastEffectSet(t *testing.T) {
	cand := baseCandidate(t)
	const eval = "2026-07-24T00:00:00Z"

	type tc struct {
		name        string
		action      map[string]any
		bindings    map[string]string
		generations map[string]int
		wantEffect  string
		wantReason  string
	}
	cases := []tc{
		{
			name:       "create-unbound-will-create",
			action:     map[string]any{"id": "a1", "capability": "db", "operation": "create"},
			bindings:   nil,
			wantEffect: "will-create",
		},
		{
			name:       "create-bound-no-effect",
			action:     map[string]any{"id": "a1", "capability": "db", "operation": "create"},
			bindings:   map[string]string{"db": "projects/p/instances/i"},
			wantEffect: "no-effect",
		},
		{
			name:        "create-bound-newer-generation-is-replacement",
			action:      map[string]any{"id": "a1", "capability": "db", "operation": "create", "targetGeneration": 2},
			bindings:    map[string]string{"db": "projects/p/instances/i"},
			generations: map[string]int{"db": 1},
			wantEffect:  "will-create",
		},
		{
			name:       "update-bound-will-update",
			action:     map[string]any{"id": "a1", "capability": "db", "operation": "update"},
			bindings:   map[string]string{"db": "projects/p/instances/i"},
			wantEffect: "will-update",
		},
		{
			name:       "update-unbound-unknown",
			action:     map[string]any{"id": "a1", "capability": "db", "operation": "update"},
			bindings:   nil,
			wantEffect: "unknown",
			wantReason: "missing-binding",
		},
		{
			name:       "delete-bound-match-will-delete",
			action:     map[string]any{"id": "a1", "capability": "db", "operation": "delete", "targetProviderId": "projects/p/instances/i"},
			bindings:   map[string]string{"db": "projects/p/instances/i"},
			wantEffect: "will-delete",
		},
		{
			name:       "delete-unbound-unknown",
			action:     map[string]any{"id": "a1", "capability": "db", "operation": "delete", "targetProviderId": "projects/p/instances/i"},
			bindings:   nil,
			wantEffect: "unknown",
			wantReason: "missing-binding",
		},
		{
			name:       "delete-identity-mismatch-stale",
			action:     map[string]any{"id": "a1", "capability": "db", "operation": "delete", "targetProviderId": "projects/p/instances/OTHER"},
			bindings:   map[string]string{"db": "projects/p/instances/i"},
			wantEffect: "stale-plan",
			wantReason: "target-identity-mismatch",
		},
		{
			name:       "delete-deposed-will-delete",
			action:     map[string]any{"id": "a1", "capability": "db", "operation": "delete", "targetProviderId": "projects/p/instances/orphan", "deposed": true},
			bindings:   map[string]string{"db": "projects/p/instances/i"},
			wantEffect: "will-delete",
			wantReason: "deposed-target-validated-at-apply",
		},
		{
			name:       "unsupported-operation-unknown",
			action:     map[string]any{"id": "a1", "capability": "db", "operation": "frobnicate"},
			bindings:   map[string]string{"db": "projects/p/instances/i"},
			wantEffect: "unknown",
			wantReason: "unsupported-effect-model",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan := makePlan(t, cand, map[string]any{}, []any{c.action})
			doc, err := Forecast(plan, cand, nil, c.bindings, c.generations, nil, eval)
			if err != nil {
				t.Fatalf("Forecast: %v", err)
			}
			if !doc.Forecast.FreshPlan {
				t.Fatalf("expected fresh plan")
			}
			if len(doc.Forecast.Actions) != 1 {
				t.Fatalf("got %d actions, want 1", len(doc.Forecast.Actions))
			}
			af := doc.Forecast.Actions[0]
			if af.Effect != c.wantEffect {
				t.Errorf("Effect=%q want %q", af.Effect, c.wantEffect)
			}
			if af.Reason != c.wantReason {
				t.Errorf("Reason=%q want %q", af.Reason, c.wantReason)
			}
		})
	}
}

// TestForecastStalePlanCAS pins D41: if a decision head moved since the plan
// was sealed, every action becomes stale-plan and FreshPlan is false —
// regardless of the action's own effect model.
func TestForecastStalePlanCAS(t *testing.T) {
	cand := baseCandidate(t)
	const eval = "2026-07-24T00:00:00Z"
	// Plan pinned head "h1" for db; live head has moved to "h2".
	plan := makePlan(t, cand, map[string]any{"db": "h1"},
		[]any{map[string]any{"id": "a1", "capability": "db", "operation": "create"}})
	doc, err := Forecast(plan, cand, map[string]string{"db": "h2"}, nil, nil, nil, eval)
	if err != nil {
		t.Fatalf("Forecast: %v", err)
	}
	if doc.Forecast.FreshPlan {
		t.Fatalf("expected stale plan")
	}
	af := doc.Forecast.Actions[0]
	if af.Effect != "stale-plan" {
		t.Errorf("Effect=%q want stale-plan", af.Effect)
	}
	if doc.Forecast.Rollup.StalePlan != 1 {
		t.Errorf("Rollup.StalePlan=%d want 1", doc.Forecast.Rollup.StalePlan)
	}
}

// TestForecastMissingHeadIsGenesis pins that a pinned head absent from the
// live heads map defaults to "genesis": pinning "genesis" stays fresh, pinning
// anything else goes stale.
func TestForecastMissingHeadIsGenesis(t *testing.T) {
	cand := baseCandidate(t)
	const eval = "2026-07-24T00:00:00Z"
	act := []any{map[string]any{"id": "a1", "capability": "db", "operation": "create"}}

	// pin genesis, no live head -> fresh
	plan := makePlan(t, cand, map[string]any{"db": "genesis"}, act)
	doc, err := Forecast(plan, cand, nil, nil, nil, nil, eval)
	if err != nil {
		t.Fatalf("Forecast: %v", err)
	}
	if !doc.Forecast.FreshPlan {
		t.Errorf("pinning genesis with no live head should be fresh")
	}

	// pin non-genesis, no live head -> stale
	plan = makePlan(t, cand, map[string]any{"db": "h1"}, act)
	doc, err = Forecast(plan, cand, nil, nil, nil, nil, eval)
	if err != nil {
		t.Fatalf("Forecast: %v", err)
	}
	if doc.Forecast.FreshPlan {
		t.Errorf("pinning h1 with no live head (genesis) should be stale")
	}
}

// TestForecastCandidateHashMismatch pins the identity gate: a candidate that
// does not match the plan's pinned hash is refused.
func TestForecastCandidateHashMismatch(t *testing.T) {
	cand := baseCandidate(t)
	const eval = "2026-07-24T00:00:00Z"
	plan := makePlan(t, cand, map[string]any{}, nil)
	// mutate reads to pin a different hash
	plan["plan"].(map[string]any)["reads"].(map[string]any)["candidateHash"] = "sha256:deadbeef"
	_, err := Forecast(plan, cand, nil, nil, nil, nil, eval)
	if err == nil {
		t.Fatalf("expected candidate-mismatch error, got nil")
	}
}

// TestForecastBadEvaluationTime pins that an unparseable --at clock is refused
// (the N1 fail-closed clock discipline surfaces here as a parse error).
func TestForecastBadEvaluationTime(t *testing.T) {
	cand := baseCandidate(t)
	plan := makePlan(t, cand, map[string]any{}, nil)
	_, err := Forecast(plan, cand, nil, nil, nil, nil, "not-a-timestamp")
	if err == nil {
		t.Fatalf("expected bad-evaluation-time error, got nil")
	}
}

// TestForecastRollupAndMetadata pins rollup aggregation across a mixed action
// set plus the self-describing document metadata.
func TestForecastRollupAndMetadata(t *testing.T) {
	cand := &contract.Candidate{
		ContractID: "c-1",
		Capabilities: map[string]map[string]contract.Provenanced{
			"db":    {"residency": prov(t, "declared", "eu-west1")},
			"queue": {"protocol": prov(t, "declared", "amqp/0")},
		},
	}
	const eval = "2026-07-24T00:00:00Z"
	actions := []any{
		map[string]any{"id": "a1", "capability": "db", "operation": "create"},    // will-create
		map[string]any{"id": "a2", "capability": "queue", "operation": "update"}, // unknown (unbound)
	}
	plan := makePlan(t, cand, map[string]any{}, actions)
	doc, err := Forecast(plan, cand, nil, nil, nil, nil, eval)
	if err != nil {
		t.Fatalf("Forecast: %v", err)
	}
	r := doc.Forecast.Rollup
	if r.WillCreate != 1 || r.Unknown != 1 {
		t.Errorf("rollup=%+v want WillCreate=1 Unknown=1", r)
	}
	if doc.APIVersion != "forecast/v0" || doc.Kind != "Forecast" ||
		doc.SpecVersion != "contract/v0.1" {
		t.Errorf("metadata: apiVersion=%q kind=%q spec=%q",
			doc.APIVersion, doc.Kind, doc.SpecVersion)
	}
	if doc.Environment != "test" {
		t.Errorf("Environment=%q want test", doc.Environment)
	}
	if doc.Forecast.Contract != "c-1" {
		t.Errorf("Contract=%q want c-1", doc.Forecast.Contract)
	}
	if doc.Forecast.EvaluationTime != eval {
		t.Errorf("EvaluationTime=%q want %q", doc.Forecast.EvaluationTime, eval)
	}
}

// TestForecastCreateBoundDriftAtAttributeLevel pins the D45 discipline that a
// bound create is no-effect AS AN ACTION, yet real drift still surfaces at the
// attribute level and in the rollup — the honest forecast never hides drift.
func TestForecastCreateBoundDriftAtAttributeLevel(t *testing.T) {
	cand := &contract.Candidate{
		ContractID: "c-1",
		Capabilities: map[string]map[string]contract.Provenanced{
			"db": {"residency": prov(t, "declared", "eu-west1")},
		},
	}
	const eval = "2026-07-24T00:00:00Z"
	// observation from just before eval, well within ttl, but VALUE differs.
	obs := map[string]map[string]ledger.ObsRecord{
		"db": {"residency": {Value: "us-east1", ObservedAt: "2026-07-23T23:59:00Z",
			TTLSeconds: 3600, Derivation: "measured"}},
	}
	plan := makePlan(t, cand, map[string]any{},
		[]any{map[string]any{"id": "a1", "capability": "db", "operation": "create"}})
	doc, err := Forecast(plan, cand, nil,
		map[string]string{"db": "projects/p/instances/i"}, nil, obs, eval)
	if err != nil {
		t.Fatalf("Forecast: %v", err)
	}
	af := doc.Forecast.Actions[0]
	if af.Effect != "no-effect" {
		t.Fatalf("Effect=%q want no-effect", af.Effect)
	}
	res, ok := attrByPath(af.Attributes, "residency")
	if !ok {
		t.Fatalf("missing residency attribute")
	}
	if res.Prediction != "differ" {
		t.Errorf("attr Prediction=%q want differ (drift must surface)", res.Prediction)
	}
	if doc.Forecast.Rollup.DriftingAttributes != 1 {
		t.Errorf("Rollup.DriftingAttributes=%d want 1", doc.Forecast.Rollup.DriftingAttributes)
	}
}
