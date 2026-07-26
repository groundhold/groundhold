package apply

import (
	"testing"

	"groundhold/internal/aws"

	"groundhold/internal/contract"
	"groundhold/internal/scalars"
	"groundhold/internal/vocab"
)

// D311: an attribute the vocabulary marks as NOT resource state never reaches a
// driver. The drivers used to carry ~130 no-op `case "cost.monthly":` arms for
// exactly this — the same fact re-encoded once per service, because a builder
// REFUSES any attribute it cannot map (silent drops are forbidden). Filtering
// here makes the vocabulary the single source.
func TestProjectionAttributesNeverReachADriver(t *testing.T) {
	region, _ := scalars.Parse("eu-central-1")
	cost, _ := scalars.Parse("50")
	rto, _ := scalars.Parse("PT1H")
	cand := &contract.Candidate{
		Capabilities: map[string]map[string]contract.Provenanced{
			"db": {
				"location.region": {Scalar: region},
				"cost.monthly":    {Scalar: cost}, // projection
				"recovery.rto":    {Scalar: rto},  // probe outcome
			},
		},
	}
	c := &contract.Contract{Capabilities: map[string]map[string]any{
		"db": {"type": "capability.database.relational"},
	}}
	vocabs, err := vocab.Embedded()
	if err != nil {
		t.Fatalf("embedded vocabularies: %v", err)
	}

	got := attributesRaw(c, cand, vocabs, "db")
	if _, ok := got["cost.monthly"]; ok {
		t.Error("cost.monthly (evidence: projection) must not be handed to a driver")
	}
	if _, ok := got["recovery.rto"]; ok {
		t.Error("recovery.rto (evidence: probe) must not be handed to a driver")
	}
	if _, ok := got["location.region"]; !ok {
		t.Fatal("ordinary resource state must still reach the driver — the filter " +
			"must be exact, not a blanket drop")
	}
}

// Without a vocabulary (an unknown capability type, or a caller that has none)
// every attribute is resource state — the pre-D311 behaviour, so the filter can
// never silently swallow an attribute a driver was relying on.
func TestNoVocabularyMeansNoFiltering(t *testing.T) {
	cost, _ := scalars.Parse("50")
	cand := &contract.Candidate{
		Capabilities: map[string]map[string]contract.Provenanced{
			"db": {"cost.monthly": {Scalar: cost}},
		},
	}
	if got := attributesRaw(nil, cand, nil, "db"); len(got) != 1 {
		t.Fatalf("with no vocabulary nothing may be filtered, got %v", got)
	}
}

// TestARealDriverAcceptsACandidateDeclaringAProjection is the end-to-end pin for
// the ~124 no-op `case "cost.monthly":` arms D311 deleted from the drivers.
//
// A builder REFUSES any attribute it cannot map ("refusing rather than silently
// dropping it"), so before D311 every driver needed that arm or a contract
// declaring cost.monthly failed at Validate. The arms are gone; what makes that
// safe is the boundary filter. Remove the filter and this test fails with the
// driver's own refusal — which is exactly the regression it exists to catch.
func TestARealDriverAcceptsACandidateDeclaringAProjection(t *testing.T) {
	region, _ := scalars.Parse("eu-central-1")
	cost, _ := scalars.Parse("50")
	cand := &contract.Candidate{
		Capabilities: map[string]map[string]contract.Provenanced{
			"events": {
				"location.region": {Scalar: region},
				"cost.monthly":    {Scalar: cost}, // the projection the drivers no longer name
			},
		},
		Extras: map[string]map[string]any{"events": {"service": "sns"}},
	}
	c := &contract.Contract{
		Environment:  "prod",
		Capabilities: map[string]map[string]any{"events": {"type": "capability.messaging.topic"}},
	}
	vocabs, err := vocab.Embedded()
	if err != nil {
		t.Fatalf("embedded vocabularies: %v", err)
	}
	rep := Preflight(c, cand, vocabs, aws.NewDriver("eu-central-1"))
	if !rep.Ready {
		for _, cp := range rep.Capabilities {
			if !cp.OK {
				t.Fatalf("a declared projection must not make a driver refuse: %s", cp.Refusal)
			}
		}
		t.Fatal("preflight not ready")
	}
}
