package apply

import (
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/provider"
)

func operandCand() *contract.Candidate {
	return &contract.Candidate{
		Capabilities: map[string]map[string]contract.Provenanced{
			"db": {}, "cache": {}, "net": {},
		},
		Extras: map[string]map[string]any{
			"db":    {"service": "aurora"},
			"cache": {"service": "elasticache"},
			"net":   {"service": "vpc"},
		},
	}
}

// TestOperandPreflightCollectsAllRefusals: the whole point of the preflight is
// that it does NOT fail fast — every capability the driver cannot honor is
// reported in one pass, sorted, so an operator fixes them in a single round-trip.
func TestOperandPreflightCollectsAllRefusals(t *testing.T) {
	prov := &provider.Fake{RefuseServices: map[string]bool{"aurora": true, "elasticache": true}}
	rep := Preflight(&contract.Contract{Environment: "prod"}, operandCand(), nil, prov)

	if rep.Ready {
		t.Fatal("must not be ready when two services are refused")
	}
	if rep.Missing != 2 {
		t.Fatalf("missing = %d, want 2 (aurora + elasticache)", rep.Missing)
	}
	if len(rep.Capabilities) != 3 {
		t.Fatalf("want all 3 capabilities reported, got %d", len(rep.Capabilities))
	}
	// sorted by capability: cache, db, net
	got := map[string]PreflightCap{}
	for _, c := range rep.Capabilities {
		got[c.Capability] = c
	}
	if rep.Capabilities[0].Capability != "cache" || rep.Capabilities[1].Capability != "db" {
		t.Fatalf("capabilities not sorted: %+v", rep.Capabilities)
	}
	if got["db"].OK || got["cache"].OK {
		t.Fatal("refused services must be marked not-ok")
	}
	if !got["net"].OK {
		t.Fatal("an honored service must be marked ok")
	}
	if got["db"].Refusal == "" {
		t.Fatal("a refusal must carry the driver's message (the named operand)")
	}
}

// TestOperandPreflightReadyWhenAllHonored: no refusals -> ready, zero missing.
func TestOperandPreflightReadyWhenAllHonored(t *testing.T) {
	rep := Preflight(nil, operandCand(), nil, &provider.Fake{})
	if !rep.Ready || rep.Missing != 0 {
		t.Fatalf("all-honored must be ready with 0 missing, got ready=%v missing=%d",
			rep.Ready, rep.Missing)
	}
	if len(rep.Capabilities) != 3 {
		t.Fatalf("every capability is still listed (ok=true), got %d", len(rep.Capabilities))
	}
}
