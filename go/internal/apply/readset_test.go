package apply

import (
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/perr"
	"groundhold/internal/provider"
)

// A sealed plan pins the hashes of the contract + candidate it was compiled for in its
// read-set. Apply MUST refuse to execute that plan against DIFFERENT inputs — the
// anti-swap guarantee: a plan reviewed and sealed for one contract/candidate cannot be
// silently re-pointed at another (perr.ReadSetMismatch, exit 2, and nothing appended to
// the ledger). This pins that refusal, which was emitted (apply.go) but untested.

// a valid, executable contract+candidate whose region differs from pfContract, so its
// hashes will NOT match a plan sealed for pfContract.
const rsContract = `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: pfa, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-region
      subject: db
      path: location.region
      op: equals
      value: us-east1
      verify: { method: static }
`

const rsCandidate = `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: pfa
capabilities:
  db:
    provider: fake
    service: mock
    attributes:
      location.region: us-east1
`

func loadVariant(t *testing.T) (*contract.Contract, *contract.Candidate) {
	t.Helper()
	td := t.TempDir()
	cp := filepath.Join(td, "c2.yaml")
	kp := filepath.Join(td, "k2.yaml")
	if err := os.WriteFile(cp, []byte(rsContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(rsCandidate), 0o600); err != nil {
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
	return c, cand
}

func TestApplyRefusesReadSetMismatch(t *testing.T) {
	// a plan sealed for pfContract/pfCandidate...
	_, _, plan := setupPlan(t)
	// ...applied against a DIFFERENT (but valid, executable) contract+candidate.
	c2, cand2 := loadVariant(t)
	res := Apply(c2, cand2, nil, plan, freshLedger(t), &provider.Fake{}, pfAt, false)
	if res.Code != perr.ReadSetMismatch || res.Exit != 2 {
		t.Fatalf("expected read-set-mismatch/2, got %s/%d (reasons=%v)", res.Code, res.Exit, res.Reasons)
	}
	// a refuse-before-mutate must touch neither the provider nor the ledger.
	if len(res.Events) != 0 {
		t.Fatalf("a read-set mismatch must append nothing to the ledger, got %v", res.Events)
	}
}

// The mirror: the SAME inputs the plan was sealed for pass the read-set gate (they do
// not trip ReadSetMismatch — a sanity anchor so the test above is meaningful, not a
// tautology that would fire for any input).
func TestApplyAcceptsMatchingReadSet(t *testing.T) {
	c, cand, plan := setupPlan(t)
	res := Apply(c, cand, nil, plan, freshLedger(t), &provider.Fake{}, pfAt, false)
	if res.Code == perr.ReadSetMismatch {
		t.Fatalf("matching contract/candidate must NOT trip read-set-mismatch, got %s (%v)", res.Code, res.Reasons)
	}
}
