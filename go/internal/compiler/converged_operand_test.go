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

// D564. D530 was reported from the field in these words: a partner declared
// `memory_mb` on a BOUND, CONVERGED function; `validate` said OK, `plan` sealed with
// zero actions and zero warnings, and the operand was ignored while the function was
// being killed for running out of the default 128 MB.
//
// The fix made the guard iterate CAPABILITIES instead of ACTIONS, which is right —
// and its test calls `refuseUnknownOperands(nil, cand, in)` DIRECTLY. That proves
// the function. It does not prove the wiring, and the wiring is where the case lives:
// `Compile` returns `nothing-to-change` sixty lines BEFORE it reaches the guard, so a
// FULLY converged deployment — the exact one reported — never runs it.
//
// Half a deployment converged is covered (a plan gets sealed, the guard runs).
// All of it converged is not. The reported case is the second one.
func TestConvergedPlanStillRefusesAnUnknownOperand(t *testing.T) {
	c, cand, in := convergedFixture(t, map[string]any{"memroy_mb": 1024})
	_, err := Compile(c, cand, nil, mustVerify(t, c, cand), "proj", in)
	if err == nil {
		t.Fatal("a fully converged world accepted an operand no driver reads — " +
			"nothing-to-change short-circuits the silent-ignore guard")
	}
	if strings.Contains(err.Error(), "nothing to change") {
		t.Errorf("the run reported convergence while carrying an operand nobody reads: %v\n"+
			"This is the reported case verbatim: validate OK, zero actions, zero "+
			"warnings, operand ignored.", err)
	}
	if !strings.Contains(err.Error(), "memroy_mb") {
		t.Errorf("the refusal does not name the operand: %v", err)
	}
}

// The converse, or every converged deployment refuses and the guard is unusable.
func TestConvergedPlanStaysQuietWithKnownOperands(t *testing.T) {
	c, cand, in := convergedFixture(t, map[string]any{"size": 10})
	_, err := Compile(c, cand, nil, mustVerify(t, c, cand), "proj", in)
	if err == nil || !strings.Contains(err.Error(), "nothing to change") {
		t.Fatalf("a converged world with only known operands must report convergence, got %v", err)
	}
}

func mustVerify(t *testing.T, c *contract.Contract, cand *contract.Candidate) *verify.Report {
	t.Helper()
	r, _ := verify.Verify(c, cand, nil)
	if !r.Executable {
		t.Fatalf("not executable: %v", r.BlockingReasons)
	}
	return r
}

// convergedFixture: one bound capability whose observation MATCHES the candidate, so
// the compiler produces no action at all, carrying the given implementation block.
func convergedFixture(t *testing.T, impl map[string]any) (*contract.Contract, *contract.Candidate, Inputs) {
	t.Helper()
	td := t.TempDir()
	cp, kp := filepath.Join(td, "c.yaml"), filepath.Join(td, "k.yaml")
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
	if cand.Extras == nil {
		cand.Extras = map[string]map[string]any{}
	}
	for _, capID := range []string{"capa", "capb"} {
		if cand.Extras[capID] == nil {
			cand.Extras[capID] = map[string]any{}
		}
	}
	cand.Extras["capa"]["implementation"] = impl

	at := "2026-07-12T10:00:00Z"
	clock, _ := ledger.ParseTs(at)
	obs := map[string]map[string]ledger.ObsRecord{}
	for _, capID := range []string{"capa", "capb"} {
		obs[capID] = map[string]ledger.ObsRecord{"location.region": {Value: "europe-west1",
			ObservedAt: at, TTLSeconds: 86400, Derivation: "measured"}}
	}
	return c, cand, Inputs{
		Bindings:         map[string]string{"capa": "pa:db-a", "capb": "pb:db-b"},
		BindingProviders: map[string]string{"capa": "pa", "capb": "pb"},
		BindingServices:  map[string]string{"capa": "sa", "capb": "sb"},
		Observations:     obs,
		Observed:         map[string]bool{"capa": true, "capb": true},
		Generations:      map[string]int{"capa": 1, "capb": 1},
		EvalClock:        clock,
		Providers: map[string]provider.Provider{
			"pa": operandDouble{classifyDouble{&provider.Fake{}, "n"}},
			"pb": classifyDouble{&provider.Fake{}, "n"},
		},
	}
}

// operandDouble is a REAL-shaped driver: it declares a consumed set, so the guard
// binds it (a driver declaring none is exempt, which is the Fake).
type operandDouble struct{ classifyDouble }

func (operandDouble) ConsumedOperands(service string) []string { return []string{"size"} }
