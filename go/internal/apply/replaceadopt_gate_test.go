package apply

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/compiler"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/provider"
	"groundhold/internal/verify"
)

// D723. A replacement is create-before-destroy: create at generation N+1, then delete
// the generation-N resource, pinned by providerId. Several drivers first scan for an
// existing resource carrying our ownership tags and BIND it rather than create (D253,
// so a lost ledger does not mint a duplicate) — and those tags carry no generation.
//
// So a replacement's create could return the identity of the very resource the delete
// was about to destroy. The binding is written to it, the delete then acts on the
// pinned id — the same id — and removes it. Both actions report `succeeded`, apply
// exits 0, and the capability is left unbound with its resource gone.
//
// The driver-side fix (keying the scan on the generation-bearing name) is per-driver;
// this is the backstop that does not depend on any driver getting that right.
func TestAReplacementCreateThatReturnsTheOldIdentityIsRefused(t *testing.T) {
	const oldID = "fake:the-resource-being-replaced"
	c, cand, planDoc := replPlan(t, oldID)
	lp := freshLedger(t)

	// The driver "adopts" the resource being replaced instead of creating one.
	key := idemKeyOf(t, planDoc, "a-create-db-g2")
	fake := &provider.Fake{AdoptAsProviderID: map[string]string{key: oldID}}

	res := Apply(c, cand, nil, planDoc, lp, fake, pfAt, false)

	if got := res.Outcomes["a-create-db-g2"]; got == "succeeded" {
		t.Fatalf("the replacement create returned the identity it was replacing and was "+
			"recorded as a success — the delete that follows destroys it, and the run "+
			"exits reporting a converged estate (outcomes=%v)", res.Outcomes)
	}
	if res.Bindings["db"] == oldID {
		t.Fatalf("the capability was bound to the resource this run is about to delete")
	}
	var sawReason bool
	for _, r := range res.Reasons {
		if strings.Contains(r, "identity it is replacing") {
			sawReason = true
		}
	}
	if !sawReason && res.Outcomes["a-create-db-g2"] != "failed" {
		t.Fatalf("the refusal must name what happened; reasons=%v outcomes=%v",
			res.Reasons, res.Outcomes)
	}
}

const replContract = `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: repl, environment: test, version: 1 }
autonomy:
  allow_replace_stateful: [db]
capabilities:
  - id: db
    type: capability.database.relational
`

const replCandidate = `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: repl
capabilities:
  db:
    provider: fake
    service: mock
    attributes:
      location.region: europe-west1
`

// replPlan builds a REPLACEMENT plan by hand: the compiler emits one for an immutable
// drift, and the shape (a create at g2 carrying `replaces`, and a delete pinned to the
// g1 identity) is what this gate is about.
func replPlan(t *testing.T, oldID string) (*contract.Contract, *contract.Candidate, map[string]any) {
	t.Helper()
	td := t.TempDir()
	cp := filepath.Join(td, "c.yaml")
	kp := filepath.Join(td, "k.yaml")
	if err := os.WriteFile(cp, []byte(replContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(replCandidate), 0o600); err != nil {
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
	p, _ := planDoc["plan"].(map[string]any)
	actions, _ := p["actions"].([]any)
	for _, it := range actions {
		a, _ := it.(map[string]any)
		if a["id"] == "a-create-db" {
			a["id"] = "a-create-db-g2"
			a["targetGeneration"] = float64(2)
			a["replaces"] = map[string]any{
				"providerId": oldID, "generation": float64(1),
				"because": []any{map[string]any{"path": "location.region"}},
			}
		}
	}
	return c, cand, planDoc
}
