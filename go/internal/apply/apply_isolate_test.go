package apply

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/compiler"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/perr"
	"groundhold/internal/progress"
	"groundhold/internal/provider"
	"groundhold/internal/verify"
)

// Part A — fail-isolated apply (Acme field report #2). Three capabilities:
// alpha and beta are INDEPENDENT; gamma depends on alpha. alpha's create fails
// (injected). The old fail-fast executor aborted the whole run on alpha, so beta
// never ran and the operator had to strip their contract. Fail-isolated: beta
// still applies, gamma is skipped (its dependency failed), and the run reports
// per-action outcomes with exit 4.

const isoContract = `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: iso, environment: test, version: 1 }
capabilities:
  - id: alpha
    type: capability.database.relational
  - id: beta
    type: capability.database.relational
  - id: gamma
    type: capability.database.relational
`

const isoCandidate = `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: iso
capabilities:
  alpha:
    provider: fake
    service: mock
    attributes:
      location.region: europe-west1
  beta:
    provider: fake
    service: mock
    attributes:
      location.region: europe-west1
  gamma:
    provider: fake
    service: mock
    attributes:
      location.region: europe-west1
`

// isoPlan compiles the 3-capability contract into three independent create
// actions, then injects gamma -> alpha dependency so a failure of alpha
// transitively skips gamma while beta (independent) still runs.
func isoPlan(t *testing.T) (*contract.Contract, *contract.Candidate, map[string]any) {
	t.Helper()
	td := t.TempDir()
	cp := filepath.Join(td, "c.yaml")
	kp := filepath.Join(td, "k.yaml")
	if err := os.WriteFile(cp, []byte(isoContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(isoCandidate), 0o600); err != nil {
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
	// inject the gamma -> alpha edge (independent creates carry no dependsOn).
	p, _ := planDoc["plan"].(map[string]any)
	actions, _ := p["actions"].([]any)
	for _, it := range actions {
		a, _ := it.(map[string]any)
		if a["id"] == "a-create-gamma" {
			a["dependsOn"] = []any{"a-create-alpha"}
		}
	}
	return c, cand, planDoc
}

func TestApplyIsolatesIndependentActionsOnFailure(t *testing.T) {
	c, cand, plan := isoPlan(t)
	lp := freshLedger(t)
	alphaKey := idemKeyOf(t, plan, "a-create-alpha")
	fake := &provider.Fake{FailKeys: map[string]bool{alphaKey: true}}

	res := Apply(c, cand, nil, plan, lp, fake, pfAt, false)

	if res.Exit != 4 || res.Code != perr.ApplyFailed {
		t.Fatalf("a terminal failure must exit 4/apply-failed, got %d/%s (%v)",
			res.Exit, res.Code, res.Reasons)
	}
	if res.Status != "failed" {
		t.Fatalf("run status = %q, want failed", res.Status)
	}
	// the whole point: the INDEPENDENT branch still applied.
	if got := res.Outcomes["a-create-beta"]; got != "succeeded" {
		t.Fatalf("independent action beta must still succeed, got %q (%v)", got, res.Outcomes)
	}
	if res.Bindings["beta"] == "" {
		t.Fatalf("beta must be bound after an independent success, bindings=%v", res.Bindings)
	}
	// the failed action failed, and its dependent was skipped (never mutated).
	if got := res.Outcomes["a-create-alpha"]; got != "failed" {
		t.Fatalf("alpha must be failed, got %q", got)
	}
	if got := res.Outcomes["a-create-gamma"]; got != "skipped" {
		t.Fatalf("gamma depends on the failed alpha and must be skipped, got %q", got)
	}
	if res.Bindings["alpha"] != "" || res.Bindings["gamma"] != "" {
		t.Fatalf("neither the failed nor the skipped capability may bind, bindings=%v", res.Bindings)
	}

	// ledger: beta bound; gamma never wrote a receipt (no intent, nothing pending).
	evs := ledgerEvents(t, lp)
	if len(receiptsFor(evs, "gamma")) != 0 {
		t.Fatalf("a skipped action must write no receipt for gamma: %v", receiptsFor(evs, "gamma"))
	}
	var betaBound bool
	for _, ev := range evs {
		if ev["type"] == "binding.updated" {
			body, _ := ev["body"].(map[string]any)
			if body["capability"] == "beta" {
				betaBound = true
			}
		}
	}
	if !betaBound {
		t.Fatal("beta's binding must be durable in the ledger despite alpha's failure")
	}
}

// pollingFake is a driver whose create emits an intra-action heartbeat, standing
// in for a real LRO poll (a Lambda ENI provision, a cluster upgrade). It is the
// smallest honest source Part D needs to prove the provider-wait wiring.
type pollingFake struct {
	*provider.Fake
	sink func(string)
}

func (p *pollingFake) SetProgress(report func(phase string)) { p.sink = report }

func (p *pollingFake) Create(service, capability, environment string,
	attrs, impl map[string]any, key string, generation int) provider.CreateResult {
	if p.sink != nil {
		p.sink("Pending — function provisioning")
		p.sink("Pending — function provisioning")
	}
	return p.Fake.Create(service, capability, environment, attrs, impl, key, generation)
}

// TestApplyEmitsProviderWaitDuringLROPoll pins Part D: a driver that polls an LRO
// (emits d.progress) moves the action running -> provider-wait once, then ticks
// the phase within it, carrying MEASURED elapsed. The provider-wait state — gated
// in the D227 addendum until a driver polled — is now live off a real source.
func TestApplyEmitsProviderWaitDuringLROPoll(t *testing.T) {
	c, cand, plan := setupPlan(t)
	var buf bytes.Buffer
	prov := &pollingFake{Fake: &provider.Fake{}}
	res := Apply(c, cand, nil, plan, freshLedger(t), prov, pfAt, false,
		WithProgress(progress.ModeNDJSON, &buf, virtualClock()))
	if res.Status != "applied" {
		t.Fatalf("apply status = %s (%v)", res.Status, res.Reasons)
	}

	f := progress.NewFold()
	var sawWaitTransition, sawPhaseTick bool
	sc := bufio.NewScanner(&buf)
	for sc.Scan() {
		var ev progress.Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("progress line not valid json: %v", err)
		}
		if err := f.Apply(ev); err != nil {
			t.Fatalf("fold rejected an emitted event (seq %d): %v", ev.Seq, err)
		}
		if ev.Kind == progress.KindTransition && ev.State == progress.StateProviderWait {
			sawWaitTransition = true
			if ev.ProviderPhase == "" {
				t.Fatal("the provider-wait transition must carry the provider phase")
			}
			if ev.ElapsedMS <= 0 {
				t.Fatal("provider-wait must carry measured elapsed, never a guess")
			}
		}
		if ev.Kind == progress.KindTick && ev.State == progress.StateProviderWait && ev.ProviderPhase != "" {
			sawPhaseTick = true
		}
	}
	if ok, err := f.Done(); !ok {
		t.Fatalf("stream did not close cleanly: %v", err)
	}
	if !sawWaitTransition {
		t.Fatal("a polling driver must move the action into provider-wait")
	}
	if !sawPhaseTick {
		t.Fatal("subsequent poll beats must tick the phase within provider-wait")
	}
}

// TestApplyPlainProgressShowsProviderPhase pins that the plain (no-TTY, CI) render
// surfaces the provider phase — it was carried on the stream but dropped by the
// renderer, so the "what is it waiting on" signal never reached the human.
func TestApplyPlainProgressShowsProviderPhase(t *testing.T) {
	c, cand, plan := setupPlan(t)
	var buf bytes.Buffer
	prov := &pollingFake{Fake: &provider.Fake{}}
	Apply(c, cand, nil, plan, freshLedger(t), prov, pfAt, false,
		WithProgress(progress.ModePlain, &buf, virtualClock()))
	if !strings.Contains(buf.String(), "phase=Pending") {
		t.Fatalf("plain progress must surface the provider phase, got:\n%s", buf.String())
	}
}
