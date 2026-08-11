package verify

import (
	"os"
	"path/filepath"
	"strings"
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

// D766, from the field. A budget constraint compared a number the AUTHOR wrote against a
// threshold the author wrote and reported it as `observed 6 EUR`; the bill was 14.6. The
// reporter's sentence is the finding: **"Ograniczenie oparte na liczbie, którą sam
// wpisałem, nie jest ograniczeniem. Jest powtórzeniem mojego założenia."**
//
// What is fixed here is the WORD, not the semantics: a declared value still satisfies a
// static-bar constraint, and whether it should is a decision about verify.method defaults
// that belongs to the owner (recorded, flagged, not taken here). What must not stand is
// the sentence claiming a measurement nobody made.
func TestTheVerdictVerbFollowsTheProvenance(t *testing.T) {
	for _, c := range []struct {
		status string
		want   string
		absent string
	}{
		{"declared", "declared 6", "observed"},
		{"inferred", "inferred 6", "observed"},
		{"assumed", "assumed 6", "observed"},
		{"", "observed 6", "declared"},
	} {
		t.Run(c.status, func(t *testing.T) {
			got := basisVerb(c.status)
			line := "cost.monthly lte 15: " + got + " 6"
			if !strings.Contains(line, c.want) {
				t.Fatalf("basis %q rendered %q, want it to say %q — the word in the sentence "+
					"a person acts on must match how the value was come by (D766)",
					c.status, line, c.want)
			}
			if c.absent != "" && strings.Contains(line, c.absent) {
				t.Fatalf("basis %q rendered %q, which still says %q", c.status, line, c.absent)
			}
		})
	}
}
