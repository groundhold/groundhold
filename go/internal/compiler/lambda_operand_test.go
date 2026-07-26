package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/provider"
	"groundhold/internal/verify"
)

// opDrifter is a driver implementing provider.OperandDrifter (F-LC3): it reports
// one operand target and classifies its reserved path as a mutable in-place
// patch. It exercises the compiler's operand-drift wiring without a real cloud.
type opDrifter struct {
	*provider.Fake
	desired string
}

func (o opDrifter) OperandTargets(service string, attrs, impl map[string]any) ([]provider.OperandTarget, error) {
	return []provider.OperandTarget{{Path: provider.OperandPrefix + "vpcConfig", Desired: o.desired}}, nil
}

func (o opDrifter) ClassifyChange(service, path string, current, desired any,
	impl map[string]any) (string, string) {
	if path == provider.OperandPrefix+"vpcConfig" {
		return "mutable", "operand patched in place"
	}
	return o.Fake.ClassifyChange(service, path, current, desired, impl)
}

const fnContract = `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: fnc, environment: test, version: 1 }
capabilities:
  - id: fn
    type: capability.function.serverless
constraints:
  hard:
    - id: c-region
      subject: fn
      path: location.region
      op: equals
      value: eu-central-1
      verify: { method: static }
`

const fnCandidate = `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: fnc
capabilities:
  fn:
    provider: aws
    service: lambda
    attributes:
      location.region: eu-central-1
`

func fnFixture(t *testing.T) (*contract.Contract, *contract.Candidate, *verify.Report) {
	t.Helper()
	td := t.TempDir()
	cp := filepath.Join(td, "c.yaml")
	kp := filepath.Join(td, "k.yaml")
	if err := os.WriteFile(cp, []byte(fnContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(fnCandidate), 0o600); err != nil {
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
	report, _ := verify.Verify(c, cand, nil)
	if !report.Executable {
		t.Fatalf("not executable: %v", report.BlockingReasons)
	}
	return c, cand, report
}

// TestOperandDriftRoutesToUpdate pins F-LC3 part 1: a BOUND function whose
// declared operand (vpcConfig) differs from the observed operand must plan an
// UPDATE, not a no-op. Before the fix, operand drift went undetected (operands
// are not typed vocab attributes) and converge was a silent no-op (F16/F25).
func TestOperandDriftRoutesToUpdate(t *testing.T) {
	c, cand, report := fnFixture(t)
	at := "2026-07-25T10:00:00Z"
	clock, _ := ledger.ParseTs(at)
	in := Inputs{
		Bindings:    map[string]string{"fn": "lambda:eu-central-1:000000000000:fn"},
		Generations: map[string]int{"fn": 1},
		Observed:    map[string]bool{"fn": true},
		Observations: map[string]map[string]ledger.ObsRecord{
			"fn": {
				"location.region":                    {Value: "eu-central-1", ObservedAt: at, TTLSeconds: 86400, Derivation: "measured"},
				provider.OperandPrefix + "vpcConfig": {Value: "subnets=subnet-a;sgs=sg-1", ObservedAt: at, TTLSeconds: 900, Derivation: "measured"},
			},
		},
		EvalClock: clock,
		Providers: map[string]provider.Provider{
			"aws": opDrifter{Fake: &provider.Fake{}, desired: "subnets=subnet-b;sgs=sg-1"},
		},
	}
	doc, err := Compile(c, cand, nil, report, "proj", in)
	if err != nil {
		t.Fatalf("operand drift must plan an update, got: %v", err)
	}
	var up *Action
	for i := range doc.Plan.Actions {
		if doc.Plan.Actions[i].Operation == "update" {
			up = &doc.Plan.Actions[i]
		}
	}
	if up == nil {
		t.Fatalf("expected an update action, got %+v", doc.Plan.Actions)
	}
	if len(up.Changes) != 1 || up.Changes[0].Path != provider.OperandPrefix+"vpcConfig" {
		t.Fatalf("update must carry the operand change, got %+v", up.Changes)
	}
}

// TestOperandConvergedIsNoOp: the same operand, observed EQUAL to the declared
// desired, must be a no-op (ErrNothingToChange) — operand-drift never invents work.
func TestOperandConvergedIsNoOp(t *testing.T) {
	c, cand, report := fnFixture(t)
	at := "2026-07-25T10:00:00Z"
	clock, _ := ledger.ParseTs(at)
	in := Inputs{
		Bindings:    map[string]string{"fn": "lambda:eu-central-1:000000000000:fn"},
		Generations: map[string]int{"fn": 1},
		Observed:    map[string]bool{"fn": true},
		Observations: map[string]map[string]ledger.ObsRecord{
			"fn": {
				"location.region":                    {Value: "eu-central-1", ObservedAt: at, TTLSeconds: 86400, Derivation: "measured"},
				provider.OperandPrefix + "vpcConfig": {Value: "subnets=subnet-b;sgs=sg-1", ObservedAt: at, TTLSeconds: 900, Derivation: "measured"},
			},
		},
		EvalClock: clock,
		Providers: map[string]provider.Provider{
			"aws": opDrifter{Fake: &provider.Fake{}, desired: "subnets=subnet-b;sgs=sg-1"},
		},
	}
	_, err := Compile(c, cand, nil, report, "proj", in)
	if err == nil || !strings.Contains(err.Error(), "nothing to change") {
		t.Fatalf("an equal operand must be a no-op, got err=%v", err)
	}
}

// TestAbsenceRoutesToCreate pins F-LC3 part 2: a BOUND function whose observe
// found it authoritatively GONE (resource.absent=true) must plan a CREATE
// (re-create after an out-of-band delete), not a no-op.
func TestAbsenceRoutesToCreate(t *testing.T) {
	c, cand, report := fnFixture(t)
	at := "2026-07-25T10:00:00Z"
	clock, _ := ledger.ParseTs(at)
	in := Inputs{
		Bindings:    map[string]string{"fn": "lambda:eu-central-1:000000000000:fn"},
		Generations: map[string]int{"fn": 1},
		Observed:    map[string]bool{"fn": true},
		Observations: map[string]map[string]ledger.ObsRecord{
			"fn": {provider.ResourceAbsentPath: {Value: true, ObservedAt: at, TTLSeconds: 900, Derivation: "measured"}},
		},
		EvalClock: clock,
		Providers: map[string]provider.Provider{"aws": &provider.Fake{}},
	}
	doc, err := Compile(c, cand, nil, report, "proj", in)
	if err != nil {
		t.Fatalf("a gone bound resource must re-create, got: %v", err)
	}
	created := false
	for _, a := range doc.Plan.Actions {
		if a.Capability == "fn" && a.Operation == "create" {
			created = true
		}
	}
	if !created {
		t.Fatalf("expected a re-create action, got %+v", doc.Plan.Actions)
	}
}

// TestReadErrorDoesNotRecreate: a bound function with NO observations at all and
// no recorded observe (a read error left no evidence) must BLOCK re-observe-first
// (unknown), never a spurious recreate.
func TestReadErrorDoesNotRecreate(t *testing.T) {
	c, cand, report := fnFixture(t)
	at := "2026-07-25T10:00:00Z"
	clock, _ := ledger.ParseTs(at)
	in := Inputs{
		Bindings:     map[string]string{"fn": "lambda:eu-central-1:000000000000:fn"},
		Generations:  map[string]int{"fn": 1},
		Observations: map[string]map[string]ledger.ObsRecord{},
		EvalClock:    clock,
		Providers:    map[string]provider.Provider{"aws": &provider.Fake{}},
	}
	_, err := Compile(c, cand, nil, report, "proj", in)
	if err == nil || !strings.Contains(err.Error(), "re-observe first") {
		t.Fatalf("a read error (no evidence) must block re-observe, not recreate; got err=%v", err)
	}
}
