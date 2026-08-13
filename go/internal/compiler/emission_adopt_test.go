package compiler

import (
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/provider"
)

// emittingDriver certifies that its lambda service auto-emits a log group governed
// by monitoring.logs (D1032) — the provenance mintEmissionAdopt keys on.
type emittingDriver struct{ provider.Fake }

func (*emittingDriver) EmittedCompanions() map[string][]provider.EmittedCompanion {
	return map[string][]provider.EmittedCompanion{
		"lambda": {{GovernedBy: "capability.monitoring.logs", NameOutput: "logGroupName"}},
	}
}

func emAdoptFixture(consent bool, fold *OperandFold) (
	[]Action, *contract.Contract, *contract.Candidate, Inputs) {
	logs := Action{ID: "a-create-logs", Capability: "logs", Operation: "create"}
	if fold != nil {
		logs.Folds = []OperandFold{*fold}
	}
	c := &contract.Contract{
		ID: "x",
		Capabilities: map[string]map[string]any{
			"api":  {"type": "capability.function.serverless"},
			"logs": {"type": "capability.monitoring.logs"},
		},
	}
	if consent {
		c.Autonomy = map[string]any{"allow_emission_adopt": []any{"logs"}}
	}
	cand := &contract.Candidate{ContractID: "x", Extras: map[string]map[string]any{
		"api":  {"provider": "aws", "service": "lambda"},
		"logs": {"provider": "aws", "service": "cwlogs"},
	}}
	in := Inputs{Providers: map[string]provider.Provider{"aws": &emittingDriver{}}}
	return []Action{logs}, c, cand, in
}

func logGroupFold() *OperandFold {
	return &OperandFold{Slot: "log_group", Capability: "api", Output: "logGroupName",
		Value: "/aws/lambda/fn"}
}

// The grant is minted only when BOTH provenance and consent hold.
func TestEmissionAdoptMintedWithProvenanceAndConsent(t *testing.T) {
	actions, c, cand, in := emAdoptFixture(true, logGroupFold())
	mintEmissionAdopt(actions, c, cand, in)
	if !actions[0].EmissionAdopt {
		t.Fatal("a monitoring.logs $ref-bound to a certified emission WITH scoped " +
			"consent must be granted the adopt")
	}
}

// Provenance without consent: the group stays behind the ownership gate.
func TestEmissionAdoptRefusedWithoutConsent(t *testing.T) {
	actions, c, cand, in := emAdoptFixture(false, logGroupFold())
	mintEmissionAdopt(actions, c, cand, in)
	if actions[0].EmissionAdopt {
		t.Fatal("no scoped allow_emission_adopt -> no grant, even with provenance")
	}
}

// Consent without provenance: a literal log_group (no $ref to an emission) is an
// ordinary standalone group, never adopted.
func TestEmissionAdoptRefusedWithoutProvenance(t *testing.T) {
	actions, c, cand, in := emAdoptFixture(true, nil)
	mintEmissionAdopt(actions, c, cand, in)
	if actions[0].EmissionAdopt {
		t.Fatal("no $ref to a certified emission -> no grant, even with consent")
	}
}

// A $ref to an output that is NOT a certified emission must not mint the grant —
// the provenance is the emission registry, not "any output named on any producer".
func TestEmissionAdoptRefusedForNonEmissionRef(t *testing.T) {
	fold := &OperandFold{Slot: "log_group", Capability: "api", Output: "someOtherOutput",
		Value: "x"}
	actions, c, cand, in := emAdoptFixture(true, fold)
	mintEmissionAdopt(actions, c, cand, in)
	if actions[0].EmissionAdopt {
		t.Fatal("a $ref to a non-emission output must not mint the grant")
	}
}

// The grant is only for monitoring.logs — a different consumer capability $ref-ing
// the same output is not adopting a log group and must not be granted.
func TestEmissionAdoptOnlyForLogsCapability(t *testing.T) {
	actions, c, cand, in := emAdoptFixture(true, logGroupFold())
	c.Capabilities["logs"]["type"] = "capability.storage.object"
	mintEmissionAdopt(actions, c, cand, in)
	if actions[0].EmissionAdopt {
		t.Fatal("only a capability.monitoring.logs adopts a log group")
	}
}
