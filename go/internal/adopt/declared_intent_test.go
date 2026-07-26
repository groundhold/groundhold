package adopt

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

// intentFake emits service.managed=true and, when region != "", a
// location.region observation. cost.monthly is NEVER emitted (structurally
// non-observable), so adopt must record it as declared-intent, not refuse.
type intentFake struct {
	*provider.Fake
	region string
}

func (f intentFake) Observe(service, capability, providerID string) ([]provider.Observation, []string, error) {
	obs := []provider.Observation{{Path: "service.managed", Value: true, Derivation: "measured"}}
	if f.region != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: f.region, Derivation: "measured"})
	}
	return obs, nil, nil
}

func intentFixture(t *testing.T) (*contract.Contract, *contract.Candidate, *ledger.Ledger, string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cPath := write("c.yaml", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: t, owner: o@e.test, environment: dev, version: 1 }
capabilities:
  - id: store
    type: capability.storage.object
constraints:
  hard:
    - id: c-managed
      subject: store
      path: service.managed
      op: equals
      value: true
      verify: { method: static }
`)
	candPath := write("cand.yaml", `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: t
capabilities:
  store:
    provider: fake
    service: sql
    attributes:
      service.managed: true
      location.region: eu-central-1
      cost.monthly: 50
`)
	c, err := contract.LoadContract(cPath)
	if err != nil {
		t.Fatal(err)
	}
	cand, err := contract.LoadCandidate(candPath, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(dir, "ledger.ndjson")
	w := &ledger.Writer{Path: ledgerPath, Led: ledger.New(), Env: "dev", Clock: 1752600000, Actor: "o@e.test"}
	if err := w.Append("contract.published", []string{"store"},
		map[string]any{"contract": "t", "version": 1}, 0); err != nil {
		t.Fatal(err)
	}
	led, err := ledger.ReplayFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	return c, cand, led, ledgerPath
}

// TestAdoptRecordsNonObservableAsIntent pins F-LC3 part 3: a NON-OBSERVABLE
// declared attribute (cost.monthly — the driver never emits it) is adopted with
// the candidate's own provenance (declared, NOT measured), never refused. The
// OBSERVABLE service.managed still confirms against reality.
func TestAdoptRecordsNonObservableAsIntent(t *testing.T) {
	c, cand, led, ledgerPath := intentFixture(t)
	report, _ := verify.Verify(c, cand, nil)
	prov := intentFake{Fake: &provider.Fake{}, region: "eu-central-1"}
	res, code := Run(c, cand, report, map[string]string{"store": "fake:my-bucket"},
		prov, led, ledgerPath, "2026-07-25T11:00:00Z", "")
	if code != 0 {
		t.Fatalf("adopt must record a non-observable attr as intent, not refuse; got code %d: %+v", code, res)
	}

	replayed, err := ledger.ReplayFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := replayed.Observations["store"]["cost.monthly"]
	if !ok {
		t.Fatalf("cost.monthly must be recorded as declared-intent, got %v", replayed.Observations["store"])
	}
	if rec.Source != provider.DeclaredIntentSource {
		t.Fatalf("intent must carry source %q, got %q", provider.DeclaredIntentSource, rec.Source)
	}
	if rec.Derivation == "measured" {
		t.Fatalf("intent must NOT be recorded as measured (provenance survives), got %q", rec.Derivation)
	}
	// the observable attribute keeps its measured record — intent never masks reality.
	if sm := replayed.Observations["store"]["service.managed"]; sm.Derivation != "measured" {
		t.Fatalf("service.managed must remain measured, got %q", sm.Derivation)
	}
}

// TestAdoptRefusesObservableMismatch pins the honesty boundary (F-LC3 part 3):
// an OBSERVABLE attribute whose declared value MISMATCHES reality still refuses —
// only NON-observable attributes become declared-intent. This guards the
// Acme recovery.rpo class: an observed-and-wrong value is a lie, not intent.
func TestAdoptRefusesObservableMismatch(t *testing.T) {
	c, cand, led, ledgerPath := intentFixture(t)
	report, _ := verify.Verify(c, cand, nil)
	// the driver observes location.region=us-east-1, the candidate declares
	// eu-central-1 — an OBSERVABLE mismatch, which must still refuse.
	prov := intentFake{Fake: &provider.Fake{}, region: "us-east-1"}
	res, code := Run(c, cand, report, map[string]string{"store": "fake:my-bucket"},
		prov, led, ledgerPath, "2026-07-25T11:00:00Z", "")
	if code == 0 {
		t.Fatalf("an observable mismatch must refuse (adoption must not lie), got adopted: %+v", res)
	}
	if !strings.Contains(strings.Join(res.Reasons, " "), "reality says") {
		t.Fatalf("refusal must name the observed/declared mismatch, got %v", res.Reasons)
	}
}
