package compiler

import (
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/provider"
	"groundhold/internal/verify"
)

// Part B — a bound capability the compile produces no action for is a converged
// no-op, and the plan must name WHY (so "converge did nothing" is never a
// mystery). Here capa is bound and observed EQUAL to its declared value (a
// no-op), while capb has drifted and updates — the plan seals with capb's action
// and records capa as a no-op with an honest reason.
func TestCompileNamesConvergedNoOp(t *testing.T) {
	td := t.TempDir()
	cp := filepath.Join(td, "c.yaml")
	kp := filepath.Join(td, "k.yaml")
	if err := os.WriteFile(cp, []byte(mixContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(mixCandidate), 0o600); err != nil {
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
	at := "2026-07-12T10:00:00Z"
	clock, _ := ledger.ParseTs(at)
	// capa: observed == declared (europe-west1) -> converged no-op.
	// capb: observed drifted (us-central1) -> update.
	obs := map[string]map[string]ledger.ObsRecord{
		"capa": {"location.region": {Value: "europe-west1",
			ObservedAt: at, TTLSeconds: 86400, Derivation: "measured"}},
		"capb": {"location.region": {Value: "us-central1",
			ObservedAt: at, TTLSeconds: 86400, Derivation: "measured"}},
	}
	in := Inputs{
		Bindings:     map[string]string{"capa": "pa:db-a", "capb": "pb:db-b"},
		Observations: obs,
		Observed:     map[string]bool{"capa": true, "capb": true},
		Generations:  map[string]int{"capa": 1, "capb": 1},
		EvalClock:    clock,
		Providers: map[string]provider.Provider{
			"pa": classifyDouble{&provider.Fake{}, "n"},
			"pb": classifyDouble{&provider.Fake{}, "n"},
		},
	}
	doc, err := Compile(c, cand, nil, report, "proj", in)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// capb still updates — the no-op of capa must not suppress independent work.
	var sawUpdate bool
	for _, a := range doc.Plan.Actions {
		if a.Capability == "capb" && a.Operation == "update" {
			sawUpdate = true
		}
		if a.Capability == "capa" {
			t.Fatalf("a converged capability must produce no action, got %s", a.ID)
		}
	}
	if !sawUpdate {
		t.Fatalf("capb must still update, actions=%v", doc.Plan.Actions)
	}

	// capa is recorded as a no-op with the honest observed==declared reason.
	if len(doc.Plan.NoOp) != 1 {
		t.Fatalf("expected exactly one no-op, got %v", doc.Plan.NoOp)
	}
	if doc.Plan.NoOp[0].Capability != "capa" {
		t.Fatalf("no-op capability = %q, want capa", doc.Plan.NoOp[0].Capability)
	}
	if doc.Plan.NoOp[0].Reason != "bound, observed==declared" {
		t.Fatalf("no-op reason = %q, want %q",
			doc.Plan.NoOp[0].Reason, "bound, observed==declared")
	}
}
