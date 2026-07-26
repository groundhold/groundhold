// Package forecast implements the preview stage (D40, D45,
// spec/forecast.md): a deterministic forecast from declared inputs.
// Now fed by observations (D44): attribute-level predictions with the
// four-valued discipline reappearing at prediction level —
// match | differ | unknown | unverifiable. A kind mismatch between
// desired and observed is unverifiable, never a false "differ" (D3/D6);
// canonical scalar equality compares (5m == 300s, D25); freshness
// degrades stale observations to unknown (state-model §4).
package forecast

import (
	"fmt"
	"sort"

	"groundhold/internal/canonical"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/scalars"
)

type Attribute struct {
	Path              string `json:"path"`
	Desired           any    `json:"desired"`
	Basis             string `json:"basis"`
	Prediction        string `json:"prediction,omitempty"` // match|differ|unknown|unverifiable
	Reason            string `json:"reason,omitempty"`
	Current           any    `json:"current,omitempty"`
	CurrentDerivation string `json:"currentDerivation,omitempty"`
	ObservationAge    int    `json:"observationAgeSeconds,omitempty"`
}

type ActionForecast struct {
	ID         string      `json:"id"`
	Capability string      `json:"capability"`
	Operation  string      `json:"operation"`
	Effect     string      `json:"effect"`
	Reason     string      `json:"reason,omitempty"`
	Attributes []Attribute `json:"attributes,omitempty"`
}

type Rollup struct {
	WillCreate             int `json:"willCreate"`
	WillUpdate             int `json:"willUpdate"`
	WillDelete             int `json:"willDelete"`
	NoEffect               int `json:"noEffect"`
	Unknown                int `json:"unknown"`
	StalePlan              int `json:"stalePlan"`
	DriftingAttributes     int `json:"driftingAttributes"`
	UnknownAttributes      int `json:"unknownAttributes"`
	UnverifiableAttributes int `json:"unverifiableAttributes"`
}

type Body struct {
	Plan           string           `json:"plan"`
	Contract       string           `json:"contract"`
	EvaluationTime string           `json:"evaluationTime"`
	FreshPlan      bool             `json:"freshPlan"`
	Actions        []ActionForecast `json:"actions"`
	Rollup         Rollup           `json:"rollup"`
}

type Document struct {
	APIVersion string `json:"apiVersion"`
	// SpecVersion + Environment make the forecast self-describing so the console
	// can ingest and key it without re-deriving identity (mirrors `cost --json`).
	// Output metadata only — never hashed (forecast output is not part of any
	// hashed artifact).
	SpecVersion string `json:"specVersion"`
	Kind        string `json:"kind"`
	Environment string `json:"environment,omitempty"`
	Forecast    Body   `json:"forecast"`
}

// Forecast predicts the effects of a sealed plan. bindings and
// observations come from ledger projections or files; heads are the
// DECISION heads snapshot (D41). All inputs declared, nothing read from
// the world (D40).
func Forecast(planDoc map[string]any, cand *contract.Candidate,
	heads map[string]string, bindings map[string]string,
	generations map[string]int,
	observations map[string]map[string]ledger.ObsRecord,
	evaluationTime string) (*Document, error) {
	p, _ := planDoc["plan"].(map[string]any)
	reads, _ := p["reads"].(map[string]any)

	// the plan pins the candidate by identity — refuse a different one
	candidateHash, err := canonical.HashCandidate(cand)
	if err != nil {
		return nil, err
	}
	if pinned, _ := reads["candidateHash"].(string); pinned != candidateHash {
		return nil, fmt.Errorf(
			"candidate does not match the plan: pinned %s, got %s",
			reads["candidateHash"], candidateHash)
	}

	planHash, err := canonical.HashPlan(planDoc)
	if err != nil {
		return nil, err
	}
	evalClock, err := ledger.ParseTs(evaluationTime)
	if err != nil {
		return nil, fmt.Errorf("bad evaluation time: %v", err)
	}

	// D41: decision-heads CAS
	fresh := true
	pinnedHeads, _ := reads["heads"].(map[string]any)
	for cap, pinnedAny := range pinnedHeads {
		pinnedHead, _ := pinnedAny.(string)
		current, ok := heads[cap]
		if !ok {
			current = "genesis"
		}
		if current != pinnedHead {
			fresh = false
		}
	}

	var actions []ActionForecast
	var rollup Rollup
	actionsRaw, _ := p["actions"].([]any)
	for _, it := range actionsRaw {
		a, _ := it.(map[string]any)
		af := ActionForecast{
			ID:         str(a["id"]),
			Capability: str(a["capability"]),
			Operation:  str(a["operation"]),
		}
		bound := bindings[af.Capability] != ""
		boundGen := generations[af.Capability]
		if bound && boundGen < 1 {
			boundGen = 1
		}
		actionGen, _ := a["targetGeneration"].(int)
		switch {
		case !fresh:
			af.Effect = "stale-plan"
			rollup.StalePlan++
		case af.Operation == "create" && !bound:
			af.Effect = "will-create"
			af.Attributes = desiredOnly(cand, af.Capability)
			rollup.WillCreate++
		case af.Operation == "create" && bound && actionGen > boundGen:
			// D48: a generation-stamped create is a replacement — the
			// name differs, so the 409-continuation logic does not apply
			af.Effect = "will-create"
			af.Attributes = desiredOnly(cand, af.Capability)
			rollup.WillCreate++
		case af.Operation == "create" && bound:
			// the executor would 409-continue and change NOTHING —
			// no-effect is the honest forecast OF THE ACTION; drift
			// screams at attribute level and in the rollup (D45)
			af.Effect = "no-effect"
			af.Attributes = predict(cand, af.Capability,
				observations[af.Capability], evalClock, &rollup)
			rollup.NoEffect++
		case af.Operation == "update" && bound:
			af.Effect = "will-update"
			af.Attributes = predict(cand, af.Capability,
				observations[af.Capability], evalClock, &rollup)
			rollup.WillUpdate++
		case af.Operation == "update" && !bound:
			af.Effect = "unknown"
			af.Reason = "missing-binding"
			rollup.Unknown++
		case af.Operation == "delete":
			pinned := str(a["targetProviderId"])
			if dep, _ := a["deposed"].(bool); dep {
				// D71: a deposed delete pins an ORPHAN — the binding
				// points at its successor by definition, so the
				// binding-match logic below does not apply; the deposed
				// projection is re-validated at apply
				af.Effect = "will-delete"
				af.Reason = "deposed-target-validated-at-apply"
				rollup.WillDelete++
				break
			}
			switch {
			case !bound:
				af.Effect = "unknown"
				af.Reason = "missing-binding"
				rollup.Unknown++
			case bindings[af.Capability] != pinned:
				// D47: the plan pinned a different identity — the apply
				// would refuse, so say so
				af.Effect = "stale-plan"
				af.Reason = "target-identity-mismatch"
				rollup.StalePlan++
			default:
				af.Effect = "will-delete"
				rollup.WillDelete++
			}
		default:
			af.Effect = "unknown"
			af.Reason = "unsupported-effect-model"
			rollup.Unknown++
		}
		actions = append(actions, af)
	}

	return &Document{
		APIVersion:  "forecast/v0",
		SpecVersion: "contract/v0.1",
		Kind:        "Forecast",
		Environment: str(p["environment"]),
		Forecast: Body{
			Plan:           planHash,
			Contract:       str(p["contract"]),
			EvaluationTime: evaluationTime,
			FreshPlan:      fresh,
			Actions:        actions,
			Rollup:         rollup,
		},
	}, nil
}

func desiredOnly(cand *contract.Candidate, capID string) []Attribute {
	attrs := cand.Capabilities[capID]
	paths := sortedPaths(attrs)
	out := make([]Attribute, 0, len(paths))
	for _, p := range paths {
		pv := attrs[p]
		var desired any
		if pv.Scalar != nil {
			desired = pv.Scalar.Raw
		}
		out = append(out, Attribute{Path: p, Desired: desired,
			Basis: pv.Status})
	}
	return out
}

// predict compares desired vs observed per attribute with the
// four-valued prediction set (D45).
func predict(cand *contract.Candidate, capID string,
	obs map[string]ledger.ObsRecord, evalClock int,
	rollup *Rollup) []Attribute {
	attrs := cand.Capabilities[capID]
	paths := sortedPaths(attrs)
	out := make([]Attribute, 0, len(paths))
	for _, p := range paths {
		pv := attrs[p]
		var desired any
		if pv.Scalar != nil {
			desired = pv.Scalar.Raw
		}
		attr := Attribute{Path: p, Desired: desired, Basis: pv.Status}

		rec, has := obs[p]
		switch {
		case !has:
			attr.Prediction = "unknown"
			attr.Reason = "missing-observation"
			rollup.UnknownAttributes++
		default:
			obsClock, err := ledger.ParseTs(rec.ObservedAt)
			age := evalClock - obsClock
			attr.Current = rec.Value
			attr.CurrentDerivation = rec.Derivation
			attr.ObservationAge = age
			switch {
			case err != nil || age < 0:
				attr.Prediction = "unverifiable"
				attr.Reason = "invalid-observation"
				rollup.UnverifiableAttributes++
			case age > rec.TTLSeconds:
				// freshness is part of the type system (D27)
				attr.Prediction = "unknown"
				attr.Reason = "stale-observation"
				rollup.UnknownAttributes++
			default:
				attr.Prediction, attr.Reason =
					compare(pv.Scalar, rec.Value)
				switch attr.Prediction {
				case "differ":
					rollup.DriftingAttributes++
				case "unverifiable":
					rollup.UnverifiableAttributes++
				case "unknown":
					rollup.UnknownAttributes++
				}
			}
		}
		out = append(out, attr)
	}
	return out
}

// compare: canonical scalar equality (D25) — a kind mismatch between
// desired and observed is unverifiable, never a false differ (D3/D6).
func compare(desired *scalars.Scalar, observed any) (string, string) {
	if desired == nil {
		return "unknown", "desired-value-unknown"
	}
	obsScalar, err := scalars.Parse(observed)
	if err != nil {
		return "unverifiable", "unparseable-observation"
	}
	ok, err := scalars.Operators["equals"](obsScalar, desired)
	if err != nil {
		return "unverifiable", "kind-mismatch"
	}
	if ok {
		return "match", ""
	}
	return "differ", ""
}

func sortedPaths(attrs map[string]contract.Provenanced) []string {
	paths := make([]string, 0, len(attrs))
	for p := range attrs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
