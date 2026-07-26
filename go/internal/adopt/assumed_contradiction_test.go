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

// D322 (adversarial audit of adopt): an `assumed` attribute the live observation
// CONTRADICTS is skipped in silence.
//
// Adoption exists so a takeover "must not lie": every declared attribute is
// checked against a live observation before the binding is written. An `assumed`
// value is deliberately exempt from the REFUSAL — it claims an assumption, not
// reality, provenance survives (D5) and policy can gate satisfied-but-assumed
// separately (D195). That exemption is right.
//
// What is not right is the silence. Adopt has already called Observe and holds
// the contradicting value in its hand; it skips the attribute without a word. The
// operator adopts believing `network.publicExposure: false` and the bucket is
// public — at the one moment designed to confront a declaration with reality.
// Nothing else will say it either: adopt records observations, but the report
// carries no channel for "your assumption disagrees with the world".
func TestAdoptReportsAnAssumedValueRealityContradicts(t *testing.T) {
	c, cand, led, ledgerPath := assumedFixture(t)
	prov := &contradictingProvider{}

	res, _ := Run(c, cand, &verify.Report{Executable: true},
		map[string]string{"store": "fake:bucket-1"}, prov, led, ledgerPath,
		"2026-07-25T10:00:00Z", "")

	if res.Status != "adopted" {
		t.Fatalf("an assumed value must not REFUSE the adoption (D5/D195 keep it "+
			"an assumption, not a lie): %+v", res)
	}
	joined := strings.Join(res.Reasons, " ") + " " + strings.Join(res.Notes, " ")
	if !strings.Contains(joined, "network.publicExposure") {
		t.Errorf("adoption bound while the live observation CONTRADICTED an assumed "+
			"declaration, and said nothing. Adopt held the observation (true) against "+
			"the declaration (false) and skipped it silently.\nresult: %+v", res)
	}
}

// The exemption itself must survive: an assumed value reality AGREES with (or
// says nothing about) must not start producing noise.
func TestAdoptStaysQuietWhenTheAssumptionHolds(t *testing.T) {
	c, cand, led, ledgerPath := assumedFixture(t)
	prov := &agreeingProvider{}

	res, _ := Run(c, cand, &verify.Report{Executable: true},
		map[string]string{"store": "fake:bucket-1"}, prov, led, ledgerPath,
		"2026-07-25T10:00:00Z", "")
	if res.Status != "adopted" {
		t.Fatalf("adoption must succeed: %+v", res)
	}
	if strings.Contains(strings.Join(res.Notes, " "), "network.publicExposure") {
		t.Errorf("an assumption reality agrees with must stay quiet: %+v", res.Notes)
	}
}

type contradictingProvider struct{ provider.Fake }

func (p *contradictingProvider) Observe(service, capability, providerID string) (
	[]provider.Observation, []string, error) {
	return []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// the assumption said false
		{Path: "network.publicExposure", Value: true, Derivation: "measured"},
	}, nil, nil
}

type agreeingProvider struct{ provider.Fake }

func (p *agreeingProvider) Observe(service, capability, providerID string) (
	[]provider.Observation, []string, error) {
	return []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "network.publicExposure", Value: false, Derivation: "measured"},
	}, nil, nil
}

func assumedFixture(t *testing.T) (*contract.Contract, *contract.Candidate, *ledger.Ledger, string) {
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
      network.publicExposure:
        value: false
        status: assumed
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
	w := &ledger.Writer{Path: ledgerPath, Led: ledger.New(), Env: "dev",
		Clock: 1752600000, Actor: "o@e.test"}
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
