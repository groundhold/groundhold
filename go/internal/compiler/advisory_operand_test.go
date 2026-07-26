package compiler

import (
	"testing"

	"groundhold/internal/aws"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/provider"
	"groundhold/internal/scalars"
	"groundhold/internal/vocab"
)

func functionVocab(t *testing.T) vocab.Vocabulary {
	t.Helper()
	all, err := vocab.Embedded()
	if err != nil {
		t.Fatalf("embedded vocabularies: %v", err)
	}
	v, ok := all["capability.function.serverless"]
	if !ok {
		t.Fatal("capability.function.serverless missing from the embedded vocabularies")
	}
	return v
}

// TestAdvisoryAttrDoesNotBlockOperandUpdate pins the Acme field regression
// (D311/D318 era): a BOUND Lambda declaring an ADVISORY attribute
// (cost.monthly, evidence: projection) alongside a real change must still plan
// the change — never collapse to an empty SEALED plan.
//
// The driver's operand builder REFUSES any attribute it cannot map ("has no
// Lambda mapping — refusing rather than silently dropping it"), and a projection
// maps to no provider setting BY DESIGN. Before the fix the compiler handed the
// UNFILTERED attribute map to OperandTargets, so BuildLambda refused on
// cost.monthly, the caller isolated it as a block, and a legal container-image
// update silently vanished. The fix filters projection attrs (keyed off the
// vocabulary's evidence class, not the name) before the driver ever sees them —
// exactly as the apply boundary already does.
func TestAdvisoryAttrDoesNotBlockOperandUpdate(t *testing.T) {
	region, _ := scalars.Parse("eu-central-1")
	cost, _ := scalars.Parse("2 USD") // ADVISORY: evidence: projection
	cand := &contract.Candidate{
		Capabilities: map[string]map[string]contract.Provenanced{
			"api": {
				"location.region": {Scalar: region},
				"cost.monthly":    {Scalar: cost},
			},
		},
		Extras: map[string]map[string]any{"api": {
			"service": "lambda",
			"implementation": map[string]any{
				"image_uri": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/api:v2",
				"role_arn":  "arn:aws:iam::123456789012:role/api",
			},
		}},
	}
	at := "2026-07-25T10:00:00Z"
	clock, _ := ledger.ParseTs(at)
	rec := func(v any) ledger.ObsRecord {
		return ledger.ObsRecord{Value: v, ObservedAt: at, TTLSeconds: 86400, Derivation: "measured"}
	}
	in := Inputs{
		Bindings:  map[string]string{"api": "lambda:eu-central-1:123456789012:api"},
		Observed:  map[string]bool{"api": true},
		EvalClock: clock,
		Observations: map[string]map[string]ledger.ObsRecord{
			"api": {
				"location.region":                      rec("eu-central-1"),
				provider.OperandPrefix + "vpcConfig":   rec(""),
				provider.OperandPrefix + "environment": rec(""),
				provider.OperandPrefix + "package":     rec("123456789012.dkr.ecr.eu-central-1.amazonaws.com/api:v1"),
			},
		},
		Providers: map[string]provider.Provider{"aws": aws.NewDriver("eu-central-1")},
	}

	changes, immutable, block, _, err := classifyBound(cand, "api", "aws", "lambda", in, functionVocab(t))
	if err != nil {
		t.Fatalf("an advisory attribute must not error the reconcile: %v", err)
	}
	if block != "" {
		t.Fatalf("cost.monthly (evidence: projection) must not block the update — "+
			"got block %q (the Acme empty-plan regression)", block)
	}
	found := false
	for _, ch := range changes {
		if ch.Path == provider.OperandPrefix+"package" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the real container-image update must survive, got changes=%+v immutable=%+v",
			changes, immutable)
	}
}
