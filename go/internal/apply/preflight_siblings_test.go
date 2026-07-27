package apply

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/compiler"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	perr "groundhold/internal/perr"
	"groundhold/internal/provider"
	"groundhold/internal/verify"
)

// Two capabilities, so the plan carries TWO create actions.
const sibContract = `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: sib, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
  - id: cache
    type: capability.cache.keyvalue
constraints:
  hard:
    - id: c-db-region
      subject: db
      path: location.region
      op: equals
      value: europe-west1
      verify: { method: static }
    - id: c-cache-region
      subject: cache
      path: location.region
      op: equals
      value: europe-west1
      verify: { method: static }
`

const sibCandidate = `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: sib
capabilities:
  db:
    provider: fake
    service: mock
    attributes:
      location.region: europe-west1
  cache:
    provider: fake
    service: doomed
    attributes:
      location.region: europe-west1
`

func setupSiblingPlan(t *testing.T) (*contract.Contract, *contract.Candidate, map[string]any) {
	t.Helper()
	td := t.TempDir()
	cp, kp := filepath.Join(td, "c.yaml"), filepath.Join(td, "k.yaml")
	if err := os.WriteFile(cp, []byte(sibContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(sibCandidate), 0o600); err != nil {
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
	doc, err := compiler.Compile(c, cand, nil, report, "proj-x", compiler.Inputs{
		Heads:        map[string]string{},
		Bindings:     map[string]string{},
		Observations: map[string]map[string]ledger.ObsRecord{},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(doc)
	var planDoc map[string]any
	if err := json.Unmarshal(raw, &planDoc); err != nil {
		t.Fatal(err)
	}
	// the compiler wraps its output; Apply unwraps it, and this assertion is the
	// reason the test means anything at all — a one-action plan cannot tell an
	// up-front preflight from an interleaved one
	inner, _ := planDoc["plan"].(map[string]any)
	acts, _ := inner["actions"].([]any)
	if len(acts) != 2 {
		t.Fatalf("this test needs a two-action plan to mean anything, got %d", len(acts))
	}
	return c, cand, planDoc
}

// A refusal on ONE action must abort before ANY sibling mutates (D378).
//
// The existing provider-refused test uses a single-action plan, where "nothing was
// appended to the ledger" is also what you would see if Validate ran immediately
// before that action's own create. It cannot distinguish an up-front preflight
// from an interleaved one — and the difference is the whole point.
//
// It is the difference a field partner paid for: a plan of theirs held an action
// that could only ever be refused, next to one that deployed an image. The image
// went out, the refusal followed, and the run's status reported only the refusal.
// Had the refusal been raised before the first mutation, nothing would have
// deployed and there would have been nothing to discover by hand.
//
// So: two actions, the SECOND one refused. If validation were interleaved with
// execution, the first would already have run and left events behind.
func TestApplyRefusesBeforeAnySiblingMutates(t *testing.T) {
	c, cand, plan := setupSiblingPlan(t)
	fake := &provider.Fake{RefuseServices: map[string]bool{"doomed": true}}

	res := Apply(c, cand, nil, plan, freshLedger(t), fake, pfAt, false)

	if res.Code != perr.ProviderRefused || res.Exit != 2 {
		t.Fatalf("expected provider-refused/2, got %s/%d (reasons=%v)", res.Code, res.Exit, res.Reasons)
	}
	if len(res.Events) != 0 {
		t.Fatalf("a refusal on one action left %d ledger events behind — a sibling "+
			"mutated before the plan was fully validated, which is exactly the shape "+
			"that deployed a bad image while the run reported only the refusal: %v",
			len(res.Events), res.Events)
	}
	if len(res.Outcomes) != 0 {
		t.Errorf("outcomes = %v; a run refused at preflight executed nothing, so it "+
			"has no per-action outcomes to report", res.Outcomes)
	}
}
