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

// confirmedFake measures everything the confirmed candidate declares.
type confirmedFake struct{ *provider.Fake }

func (f confirmedFake) Observe(service, capability, providerID string) ([]provider.Observation, []string, error) {
	return []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "location.region", Value: "eu-central-1", Derivation: "measured"},
	}, nil, nil
}

// confirmedFixture is intentFixture's candidate minus the non-observable attribute.
func confirmedFixture(t *testing.T) (*contract.Contract, *contract.Candidate, *ledger.Ledger, string) {
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
	w := &ledger.Writer{Path: ledgerPath, Led: ledger.New(), Env: "dev", Clock: 1752600000, Actor: "t"}
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

// D555. Adopt already knows this and already has the channel. `Notes` exists for
// exactly this shape (D322) and its comment states the principle in this file:
//
//	adopt is holding the contradicting observation in its hand at the one moment
//	designed to confront a declaration with the world. Skipping it silently is
//	the lie of omission the package's own first line forbids.
//
// D322 applied it to an `assumed` declaration reality contradicts. An attribute
// the driver could not measure AT ALL gets nothing — the run prints
// `"status": "adopted"` and stops there.
//
// Measured on a live k3d cluster. With the referenced GitRepository present, adopt
// REFUSED `adoption-mismatch` because it could read the URL and it differed. With
// the GitRepository deleted, the same declaration could not be read at all and adopt
// succeeded in silence. The weaker evidence bought the friendlier outcome, and
// nothing in the human-facing output distinguished a capability confirmed against
// reality from one taken on faith.
//
// The ledger is honest — source `candidate-declared`, derivation `declared`, which
// is F-LC3 part 3 working. This is the D529 shape the pilot found: the machine
// record right, the sentence a human reads wrong, in the direction of comfort.
func TestAdoptNotesWhatItCouldNotConfirm(t *testing.T) {
	c, cand, led, ledgerPath := intentFixture(t)
	report, _ := verify.Verify(c, cand, nil)
	prov := intentFake{Fake: &provider.Fake{}, region: "eu-central-1"}
	res, code := Run(c, cand, report, map[string]string{"store": "fake:my-bucket"},
		prov, led, ledgerPath, "2026-07-25T11:00:00Z", "")
	if code != 0 {
		t.Fatalf("setup: adopt must succeed, got code %d: %+v", code, res)
	}
	joined := strings.Join(res.Notes, " | ")
	if !strings.Contains(joined, "cost.monthly") {
		t.Errorf("adopt recorded cost.monthly as declared intent — never measured — and "+
			"said nothing about it.\nnotes = %v\nAn operator adopting many capabilities "+
			"cannot tell which were confirmed against reality and which were taken on "+
			"faith, and the quiet ones are the ones worth knowing about.", res.Notes)
	}
	if !strings.Contains(joined, "store") {
		t.Errorf("the note must name the capability, not just the path: %v", res.Notes)
	}
}

// The converse: a run where everything declared WAS measured must stay quiet. A note
// on every adoption is a note nobody reads (the pilot's own argument, D537: a signal
// that is always on stops being a signal).
func TestAdoptSaysNothingWhenEverythingWasConfirmed(t *testing.T) {
	c, cand, led, ledgerPath := confirmedFixture(t)
	report, _ := verify.Verify(c, cand, nil)
	prov := confirmedFake{Fake: &provider.Fake{}}
	res, code := Run(c, cand, report, map[string]string{"store": "fake:my-bucket"},
		prov, led, ledgerPath, "2026-07-25T11:00:00Z", "")
	if code != 0 {
		t.Fatalf("setup: adopt must succeed, got code %d: %+v", code, res)
	}
	for _, n := range res.Notes {
		if strings.Contains(n, "not confirmed") || strings.Contains(n, "declared intent") {
			t.Errorf("every declared attribute was measured, yet adopt noted %q", n)
		}
	}
}

// D556. The note from D555 says an attribute was NOT confirmed. The driver knows
// WHY, and adopt is holding that sentence: `observe.Run` returns diagnostics and
// adopt discarded them with `_`. On the live cluster the driver said
//
//	GitRepository "platform" referenced by spec.sourceRef.name does not exist
//	— spec.url not represented
//
// and the operator got only "the provider emitted no value for it". The difference
// is between knowing something is unverified and knowing what to fix.
func TestAdoptCarriesTheDriversReasonForNotMeasuring(t *testing.T) {
	c, cand, led, ledgerPath := intentFixture(t)
	report, _ := verify.Verify(c, cand, nil)
	prov := diagFake{Fake: &provider.Fake{}}
	res, code := Run(c, cand, report, map[string]string{"store": "fake:my-bucket"},
		prov, led, ledgerPath, "2026-07-25T11:00:00Z", "")
	if code != 0 {
		t.Fatalf("setup: adopt must succeed, got code %d: %+v", code, res)
	}
	if !strings.Contains(strings.Join(res.Notes, " | "), "billing export is not enabled") {
		t.Errorf("the driver explained why it could not measure and adopt dropped it.\n"+
			"notes = %v\nKnowing an attribute is unverified is worth less than knowing "+
			"what would make it verifiable.", res.Notes)
	}
}

// diagFake measures service.managed and location.region and EXPLAINS why it cannot
// measure cost.monthly — the shape every driver uses for an unreadable sub-read.
type diagFake struct{ *provider.Fake }

func (f diagFake) Observe(service, capability, providerID string) ([]provider.Observation, []string, error) {
	return []provider.Observation{
			{Path: "service.managed", Value: true, Derivation: "measured"},
			{Path: "location.region", Value: "eu-central-1", Derivation: "measured"},
		}, []string{"cost.monthly not observed: billing export is not enabled for this project"},
		nil
}
