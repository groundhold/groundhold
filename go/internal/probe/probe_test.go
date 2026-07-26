package probe

import (
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/provider"
)

// rogueProber ignores the allowIntrusive flag and always returns an intrusive
// measurement — a buggy or hostile driver that does not self-police consent.
type rogueProber struct{ *provider.Fake }

func (rogueProber) Probe(service, capability, providerID string,
	allowIntrusive bool) (provider.ProbeOutcome, error) {
	return provider.ProbeOutcome{Measurements: []provider.ProbeMeasurement{{
		Path: "recovery.rto", Value: "35m", Method: "restore-test",
		Evidence: "scratch restore", Intrusive: true}}}, nil
}

// TestProbeRefusesUnconsentedIntrusiveMeasurement pins D188 Finding 2: the
// double-consent invariant must be enforced IN THE FRAMEWORK, not only inside
// the driver. A driver that returns an intrusive measurement without consent
// must not launder it into the observation stream — the run refuses.
func TestProbeRefusesUnconsentedIntrusiveMeasurement(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/l.jsonl"
	led := ledger.New()
	w := &ledger.Writer{Path: path, Led: led, Env: "test", Clock: 1000, Actor: "t"}
	tok, err := w.AppendLease([]string{"db"}, map[string]any{"ttlSeconds": 300})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append("binding.updated", []string{"db"},
		map[string]any{"resources": []any{map[string]any{"id": "primary",
			"type": "t", "providerId": "fake:db-1", "generation": 1}}}, tok); err != nil {
		t.Fatal(err)
	}
	if err := w.Append("lease.released", []string{"db"}, nil, tok); err != nil {
		t.Fatal(err)
	}
	// the file is authoritative (D67 re-replays under the lock); fold it back
	// so the binding projection ("db" is bound) is populated
	led, err = ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(led.BoundProviderIDs()) == 0 {
		t.Fatal("precondition: db must be bound so the run reaches the measurement loop")
	}

	// no allow_intrusive_probes in the contract AND allowIntrusive=false:
	// consent is not granted on either axis
	c := &contract.Contract{Environment: "test"}
	res := Run(c, led, path, rogueProber{&provider.Fake{}},
		"2026-07-15T12:00:00Z", "", false /*allowIntrusive*/, false /*record*/)

	if res.Status != "refused" {
		t.Fatalf("an unconsented intrusive measurement must refuse the run, got %+v", res)
	}
	// and it must NOT have leaked into the observation/measurement stream
	if len(res.Measurements) != 0 {
		t.Fatalf("no intrusive measurement may be recorded without consent, got %+v",
			res.Measurements)
	}
}
