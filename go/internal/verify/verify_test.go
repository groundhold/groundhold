package verify

import (
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/contract"
)

// TestVerifyRefusesUncanonicalizableCandidate pins the honest-report invariant
// (D179): the free-form implementation block (D26) is NOT validated at load, so
// it can carry a value with no canonical form — a sub-1e-17 float that
// canonicalizes losslessly to nothing. Verify computes the candidate hash for its
// report; swallowing that error and emitting an empty candidateHash would be a
// dishonest identity, so Verify must REFUSE (return an error) rather than produce
// a verdict. This is the behavior the reference impl has, and the two must agree
// (a silent swallow here was invisible until the canonicalizer stopped colliding
// tiny floats). The conformance library runner can only express LOAD-time
// expect.error, so this verify-time refusal is pinned here and by the differential.
func TestVerifyRefusesUncanonicalizableCandidate(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "c.yaml")
	kp := filepath.Join(dir, "k.yaml")
	if err := os.WriteFile(cp, []byte(`apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: u1, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c
      subject: db
      path: service.managed
      op: equals
      value: true
      verify: { method: static }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(`apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: u1
capabilities:
  db:
    provider: aws
    service: rds
    attributes: { service.managed: true }
    implementation: { tiny: 1.0e-20 }
`), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := contract.LoadContract(cp)
	if err != nil {
		t.Fatal(err)
	}
	// The candidate MUST load — the implementation block is free-form (D26); its
	// un-canonicalizable value is only discovered when a hash is computed.
	cand, err := contract.LoadCandidate(kp, c, nil)
	if err != nil {
		t.Fatalf("candidate should load (free-form impl block, D26): %v", err)
	}
	report, err := Verify(c, cand, nil)
	if err == nil {
		t.Fatalf("Verify must refuse an un-canonicalizable candidate, got: %+v", report)
	}
}
