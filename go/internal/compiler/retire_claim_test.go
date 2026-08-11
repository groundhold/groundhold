package compiler

import (
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/provider"
	"groundhold/internal/verify"
)

// D570, found by walking posture's own advice on a live cluster. Its shadow note
// says: "to remove it, ADOPT it under a minimal contract, then declare state: retired
// and converge (the delete flows through every gate)."
//
// Done exactly that, the delete died:
//
//	action a-delete-prod-quota failed: labels do not match — refusing to delete a
//	ResourceQuota that ...
//
// Adoption BINDS; it does not stamp ownership. Ownership is stamped by a `claim`
// action, and the compiler emits one only in the create/update loop — the retirement
// loop builds its delete with no `DependsOn` at all. The replacement delete two
// hundred lines below DOES carry it (`withClaim(...)  // create BEFORE destroy; own
// BEFORE destroy`), so the same file states the rule and the retirement path is the
// one place that does not follow it.
//
// The measurement corrected itself once, which is worth recording: the first reading
// was "adopted resources can never be retired". False — any intervening converge,
// even a no-op one, emits the claim and unblocks it. The real gap is narrower and
// exactly matches the note: adopt → retire with nothing in between.
func TestRetiringAnAdoptedCapabilityClaimsFirst(t *testing.T) {
	c, cand, in := retireFixture(t)
	doc, err := Compile(c, cand, nil, mustVerifyRetire(t, c, cand), "proj", in)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var del, claim *Action
	for i := range doc.Plan.Actions {
		switch doc.Plan.Actions[i].Operation {
		case "delete":
			del = &doc.Plan.Actions[i]
		case "claim":
			claim = &doc.Plan.Actions[i]
		}
	}
	if del == nil {
		t.Fatalf("no delete action was planned for a retired, bound capability: %+v", doc.Plan.Actions)
	}
	if claim == nil {
		t.Fatalf("an ADOPTED capability was retired with no claim action — the driver "+
			"refuses to delete an object carrying no ownership label, so this plan "+
			"cannot apply: %+v", doc.Plan.Actions)
	}
	found := false
	for _, d := range del.DependsOn {
		if d == claim.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("the delete does not depend on the claim (%q), so ordering is not "+
			"guaranteed: dependsOn=%v\nThe replacement delete in this same file "+
			"carries it — own BEFORE destroy.", claim.ID, del.DependsOn)
	}
}

// A capability that was CREATED by groundhold is already owned: no claim, no noise.
func TestRetiringACreatedCapabilityNeedsNoClaim(t *testing.T) {
	c, cand, in := retireFixture(t)
	in.Adopted = map[string]bool{} // not adopted — we made it
	doc, err := Compile(c, cand, nil, mustVerifyRetire(t, c, cand), "proj", in)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, a := range doc.Plan.Actions {
		if a.Operation == "claim" {
			t.Errorf("a capability groundhold created was claimed before deletion — "+
				"a write with no reason to happen: %+v", a)
		}
	}
}

func mustVerifyRetire(t *testing.T, c *contract.Contract, cand *contract.Candidate) *verify.Report {
	t.Helper()
	r, _ := verify.Verify(c, cand, nil)
	return r
}

// retireFixture: one ADOPTED, bound capability the contract retires.
func retireFixture(t *testing.T) (*contract.Contract, *contract.Candidate, Inputs) {
	t.Helper()
	td := t.TempDir()
	cp, kp := filepath.Join(td, "c.yaml"), filepath.Join(td, "k.yaml")
	if err := os.WriteFile(cp, []byte(`apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: t, owner: o@e.test, environment: dev, version: 2 }
capabilities:
  - id: store
    type: capability.storage.object
    state: retired
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(`apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: t
capabilities: {}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cp)
	if err != nil {
		t.Fatal(err)
	}
	cand, err := contract.LoadCandidate(kp, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, cand, Inputs{
		Bindings:         map[string]string{"store": "fake:my-bucket"},
		BindingProviders: map[string]string{"store": "fake"},
		BindingServices:  map[string]string{"store": "sql"},
		Adopted:          map[string]bool{"store": true},
		Claimed:          map[string]bool{},
		Generations:      map[string]int{"store": 1},
		Observed:         map[string]bool{"store": true},
		Providers:        map[string]provider.Provider{"fake": claimingDouble{&provider.Fake{}}},
	}
}

// claimingDouble is a driver that can claim — the guard the compiler checks before
// planning one (a driver that cannot claim gets no claim action).
type claimingDouble struct{ *provider.Fake }

func (claimingDouble) Name() string { return "fake" }
func (claimingDouble) Claim(service, capability, environment, providerID string) provider.CreateResult {
	return provider.CreateResult{Status: "succeeded", ProviderID: providerID}
}
