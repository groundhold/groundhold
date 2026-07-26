package compiler

import (
	"groundhold/internal/vocab"
	"strings"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/scalars"
)

// D286: `outputs.<name>` is a WIRING fact (an identity a consumer references),
// not a capability SEMANTIC fact (what the contract constrains). The two must
// never be counted together — a capability known only by its wiring is a
// capability NOT semantically observed, and saying otherwise is a fail-open in
// the direction of "everything is fine".

func semanticCand(t *testing.T) *contract.Candidate {
	t.Helper()
	sc, err := scalars.Parse(true)
	if err != nil {
		t.Fatal(err)
	}
	return &contract.Candidate{
		Capabilities: map[string]map[string]contract.Provenanced{
			"net": {"service.managed": {Scalar: sc}},
		},
		Extras: map[string]map[string]any{"net": {}},
	}
}

// TestBoundCapabilityKnownOnlyByWiringDemandsReObserve is the regression: a
// bound capability whose ONLY ledger knowledge is outputs.* (its semantic
// Observe emitted nothing — a vanished resource, or a driver whose read yields
// no attributes while ReadOutputs derives from the pid) must still refuse
// observation-required. Before D286 the wiring records made `len(obs) == 0`
// false, so every declared attribute was silently reclassified as
// "structurally non-observable" and dropped from the change-set: the plan
// proceeded as if the capability had been checked.
func TestBoundCapabilityKnownOnlyByWiringDemandsReObserve(t *testing.T) {
	in := Inputs{
		EvalClock: 1_000_000,
		Bindings:  map[string]string{"net": "fake:net-1"},
		Observations: map[string]map[string]ledger.ObsRecord{
			"net": {}, // no SEMANTIC observation
		},
		Outputs: map[string]map[string]ledger.ObsRecord{
			"net": {"privateSubnetIds": {
				Value:      []any{"subnet-a", "subnet-b"},
				ObservedAt: ledger.FormatTs(999_700), TTLSeconds: 900}},
		},
	}
	_, _, _, _, err := classifyBound(semanticCand(t), "net", "fake", "mock", in, vocab.Vocabulary{})
	if err == nil || !strings.Contains(err.Error(), "re-observe first") {
		t.Fatalf("a capability known only by its wiring must demand a re-observe, got: %v", err)
	}
}

// TestWiringRecordsNeverSatisfyASemanticAttribute: even a wiring record whose
// NAME collides with a declared attribute cannot answer for it — the two live
// in different projections, so the collision is structurally impossible rather
// than a rule someone must remember.
func TestWiringRecordsNeverSatisfyASemanticAttribute(t *testing.T) {
	in := Inputs{
		EvalClock: 1_000_000,
		Bindings:  map[string]string{"net": "fake:net-1"},
		Observations: map[string]map[string]ledger.ObsRecord{
			"net": {},
		},
		Outputs: map[string]map[string]ledger.ObsRecord{
			"net": {"service.managed": {Value: true,
				ObservedAt: ledger.FormatTs(999_700), TTLSeconds: 900}},
		},
	}
	_, _, _, _, err := classifyBound(semanticCand(t), "net", "fake", "mock", in, vocab.Vocabulary{})
	if err == nil || !strings.Contains(err.Error(), "re-observe first") {
		t.Fatalf("a wiring record must not answer for a semantic attribute, got: %v", err)
	}
}
