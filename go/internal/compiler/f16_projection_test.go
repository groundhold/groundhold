package compiler

import (
	"strings"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/scalars"
	"groundhold/internal/vocab"
)

// relationalVocab is the REAL capability.database.relational vocabulary. D311:
// the projection skip is derived from the attribute's declared `evidence:` class,
// so these tests must exercise the shipped type system — a hand-written stub
// would prove only that the stub agrees with itself.
func relationalVocab(t *testing.T) vocab.Vocabulary {
	t.Helper()
	all, err := vocab.Embedded()
	if err != nil {
		t.Fatalf("embedded vocabularies: %v", err)
	}
	v, ok := all["capability.database.relational"]
	if !ok {
		t.Fatal("capability.database.relational missing from the embedded vocabularies")
	}
	return v
}

// TestClassifyBoundSkipsProjection pins F16: a projection attribute (cost.monthly)
// declared on a BOUND capability but never observed must NOT block a reconcile.
// Before the fix, "cost.monthly: no observation — re-observe first" froze every
// apply after a mid-flight partial (the reconcile of already-bound resources).
func TestClassifyBoundSkipsProjection(t *testing.T) {
	region, _ := scalars.Parse("eu-central-1")
	cost, _ := scalars.Parse("50") // value irrelevant — cost.monthly is skipped by path
	cand := &contract.Candidate{
		Capabilities: map[string]map[string]contract.Provenanced{
			"db": {
				"location.region": {Scalar: region},
				"cost.monthly":    {Scalar: cost}, // declared projection, never observed
			},
		},
		Extras: map[string]map[string]any{"db": {"service": "aurora"}},
	}
	at := "2026-07-21T10:00:00Z"
	clock, _ := ledger.ParseTs(at)
	in := Inputs{
		Bindings: map[string]string{"db": "aurora:eu-central-1:x"},
		Observations: map[string]map[string]ledger.ObsRecord{
			"db": {"location.region": {Value: "eu-central-1", ObservedAt: at,
				TTLSeconds: 86400, Derivation: "measured"}},
			// deliberately NO cost.monthly observation — the F16 case
		},
		EvalClock: clock,
	}
	changes, immutable, block, _, err := classifyBound(cand, "db", "aws", "aurora", in, relationalVocab(t))
	if err != nil {
		t.Fatalf("cost.monthly (projection, no observation) must not block reconcile: %v", err)
	}
	if block != "" {
		t.Fatalf("cost.monthly (projection) must not block the capability: %s", block)
	}
	for _, ch := range append(changes, immutable...) {
		if ch.Path == "cost.monthly" {
			t.Fatal("cost.monthly must never be a reconcile change")
		}
	}
}

// TestClassifyBoundMissingAttrDistinction pins the D249 key signal: a missing
// observation makes the attribute UNVERIFIABLE (reconcile proceeds, taken as
// declared) when the capability HAS other observations (observe ran, this attribute
// is structurally non-observable), but is an ObservationRequired REFUSAL (err) when
// the capability has NONE (never observed — re-observe fixes it, so converge's
// auto-observe still works).
func TestClassifyBoundMissingAttrDistinction(t *testing.T) {
	region, _ := scalars.Parse("eu-central-1")
	nonObs, _ := scalars.Parse("true") // a declared attr the driver never emits
	at := "2026-07-21T10:00:00Z"
	clock, _ := ledger.ParseTs(at)
	cand := &contract.Candidate{
		Capabilities: map[string]map[string]contract.Provenanced{
			"db": {
				"location.region":      {Scalar: region},
				"encryption.inTransit": {Scalar: nonObs}, // declared, never observed
			},
		},
		Extras: map[string]map[string]any{"db": {"service": "aurora"}},
	}
	base := Inputs{Bindings: map[string]string{"db": "aurora:eu-central-1:x"}, EvalClock: clock}

	// (1) capability HAS an observation (region) but NOT encryption.inTransit ->
	// unverifiable (not a block, not an error): the cap reconciles, the attr is
	// taken as declared and reported inconclusive.
	in := base
	in.Observations = map[string]map[string]ledger.ObsRecord{
		"db": {"location.region": {Value: "eu-central-1", ObservedAt: at, TTLSeconds: 86400, Derivation: "measured"}},
	}
	_, _, block, unverif, err := classifyBound(cand, "db", "aws", "aurora", in, relationalVocab(t))
	if err != nil || block != "" {
		t.Fatalf("a non-observable attr of an observed capability must be unverifiable, not error/block: err=%v block=%q", err, block)
	}
	if len(unverif) != 1 || unverif[0] != "encryption.inTransit" {
		t.Fatalf("encryption.inTransit must be reported unverifiable, got %v", unverif)
	}

	// (2) capability has NO observations at all -> ObservationRequired refusal (err).
	in2 := base
	in2.Observations = map[string]map[string]ledger.ObsRecord{}
	_, _, block2, _, err2 := classifyBound(cand, "db", "aws", "aurora", in2, relationalVocab(t))
	if err2 == nil || !strings.Contains(err2.Error(), "re-observe first") {
		t.Fatalf("a never-observed capability must be an ObservationRequired refusal, got block=%q err=%v", block2, err2)
	}
}

// TestProjectionSkipIsDrivenByTheVocabulary pins D311: the skip is DERIVED from
// the attribute's declared `evidence:` class, not from a hardcoded pair in this
// package. The discriminating case is a capability with NO observations at all —
// there D249's "observed but blind" rescue does not apply (it needs at least one
// observation to prove observe ran), so only the projection skip keeps a declared
// cost.monthly from forcing an ObservationRequired refusal.
//
// Delete `evidence: projection` from the vocabulary and this test fails, which is
// the whole claim: the type system decides, the engine only reads.
func TestProjectionSkipIsDrivenByTheVocabulary(t *testing.T) {
	cost, _ := scalars.Parse("50")
	cand := &contract.Candidate{
		Capabilities: map[string]map[string]contract.Provenanced{
			"db": {"cost.monthly": {Scalar: cost}},
		},
		Extras: map[string]map[string]any{"db": {"service": "aurora"}},
	}
	clock, _ := ledger.ParseTs("2026-07-21T10:00:00Z")
	in := Inputs{
		Bindings:     map[string]string{"db": "aurora:eu-central-1:x"},
		Observations: map[string]map[string]ledger.ObsRecord{}, // never observed
		EvalClock:    clock,
	}
	_, _, block, _, err := classifyBound(cand, "db", "aws", "aurora", in, relationalVocab(t))
	if err != nil {
		t.Fatalf("a declared projection on a never-observed capability must not refuse: %v", err)
	}
	if block != "" {
		t.Fatalf("a declared projection must not block the capability: %s", block)
	}

	// ...and with the marker gone the SAME input must refuse, proving the
	// vocabulary — not this package — is what decides.
	bare := relationalVocab(t)
	stripped := map[string]map[string]any{}
	for p, a := range bare.Attributes {
		cp := map[string]any{}
		for k, v := range a {
			if k != "evidence" {
				cp[k] = v
			}
		}
		stripped[p] = cp
	}
	bare.Attributes = stripped
	if _, _, _, _, err := classifyBound(cand, "db", "aws", "aurora", in, bare); err == nil {
		t.Fatal("without the declared evidence class the same input must refuse " +
			"(ObservationRequired) — otherwise the derivation is inert and this " +
			"test would pass whatever the vocabulary says")
	}
}
