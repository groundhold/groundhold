package reach

import (
	"groundhold/internal/ledger"
)

// ReachPath is the observation path a reachability measurement records. It is a
// SEMANTIC outcome (an edge either serves the public path or is denied), not a
// wiring identity, so it lands in the ordinary Observations projection where a
// Layer-2 guardrail-dependency will consume it as evidence. Deliberately NOT
// under the ledger's WiringPrefix.
const ReachPath = "network.reachable"

// Record folds the measured reachability observations into the SAME observation
// stream everything else consumes (D59): source "reachability", derivation
// "measured", one observation.recorded per capability at the explicit --at.
// Only reachable/denied produce observations (see Observations); unknown
// measured nothing conclusive and is never recorded. Returns the appended event
// hashes. A network GET therefore never enters a hashed apply receipt — it
// enters the ledger only here, as a measurement with observedAt, like a probe.
func Record(led *ledger.Ledger, ledgerPath, env, at, providerName string,
	providerIDs map[string]string, obs []Observation) ([]string, error) {
	if len(obs) == 0 {
		return nil, nil
	}
	clock, err := ledger.ParseTs(at)
	if err != nil {
		return nil, err
	}
	if clock > led.Clock {
		led.Clock = clock
	}
	var events []string
	w := &ledger.Writer{Path: ledgerPath, Led: led, Env: env, Clock: clock,
		Actor: "groundhold-reachability", Events: &events}
	for _, o := range obs {
		body := map[string]any{
			"kind": "Observation", "capability": o.Capability,
			"path": ReachPath, "value": o.Value,
			"source": "reachability", "derivation": "measured",
			"method": "https-get", "evidence": o.Evidence,
			"observedAt": at, "ttlSeconds": 900,
		}
		if err := w.Append("observation.recorded", []string{o.Capability},
			map[string]any{
				"provider":     map[string]any{"name": providerName},
				"resource":     map[string]any{"providerId": providerIDs[o.Capability]},
				"observations": []any{body},
			}, 0); err != nil {
			return events, err
		}
	}
	return events, nil
}
