package refresh

import (
	"path/filepath"
	"testing"
	"time"

	"groundhold/internal/ledger"
	"groundhold/internal/pace"
	"groundhold/internal/provider"
)

func noopClock() pace.Clock {
	return pace.Clock{Now: time.Now, Sleep: func(time.Duration) {}, Jitter: func() float64 { return 0 }}
}

// fixture builds a ledger with one bound capability ("store" -> fake:my-db) and,
// when obsAt != "", one recorded proof with the given freshness. Bindings and
// Observations are set directly (the freshness logic reads them); the file carries
// the published capability so a re-observation can chain onto its head.
func fixture(t *testing.T, obsAt string, ttl int) (*ledger.Ledger, string) {
	t.Helper()
	dir := t.TempDir()
	lp := filepath.Join(dir, "ledger.ndjson")
	w := &ledger.Writer{Path: lp, Led: ledger.New(), Env: "dev", Clock: 1600000000, Actor: "o@e.test"}
	if err := w.Append("contract.published", []string{"store"},
		map[string]any{"contract": "t", "version": 1}, 0); err != nil {
		t.Fatal(err)
	}
	led, err := ledger.ReplayFile(lp)
	if err != nil {
		t.Fatal(err)
	}
	led.Bindings["store"] = map[string]any{
		"resources": []any{map[string]any{"providerId": "fake:my-db", "type": "capability.cache.keyvalue"}},
	}
	if obsAt != "" {
		led.Observations["store"] = map[string]ledger.ObsRecord{
			"service.managed": {Value: true, ObservedAt: obsAt, TTLSeconds: ttl,
				Derivation: "measured", Source: "provider-api"},
		}
	}
	return led, lp
}

func run(t *testing.T, led *ledger.Ledger, lp, at string, window int) *Report {
	t.Helper()
	sched := pace.New(pace.DefaultPolicy(), noopClock())
	rep, err := Run(led, lp, &provider.Fake{}, sched, pace.DefaultPolicy().Budget, at, window, 0)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func has(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}

func TestRefreshReObservesDecayedProof(t *testing.T) {
	led, lp := fixture(t, "2020-01-01T00:00:00Z", 900) // long expired
	rep := run(t, led, lp, "2026-07-18T00:00:00Z", 0)
	if !has(rep.Refreshed, "store") || has(rep.Fresh, "store") {
		t.Fatalf("a decayed proof must be re-observed: %+v", rep)
	}
	if rep.Crawl.RequestsMade != 1 {
		t.Fatalf("exactly one paced re-observation expected, got %d", rep.Crawl.RequestsMade)
	}
}

func TestRefreshSkipsFreshProof(t *testing.T) {
	led, lp := fixture(t, "2026-07-18T00:00:00Z", 86400) // fresh for a day
	rep := run(t, led, lp, "2026-07-18T00:10:00Z", 0)
	if !has(rep.Fresh, "store") || has(rep.Refreshed, "store") {
		t.Fatalf("a fresh proof must be left alone: %+v", rep)
	}
	if rep.Crawl.RequestsMade != 0 {
		t.Fatalf("a fresh estate must issue no requests, got %d", rep.Crawl.RequestsMade)
	}
}

func TestRefreshNeverObservedIsStale(t *testing.T) {
	led, lp := fixture(t, "", 0) // bound but never observed
	rep := run(t, led, lp, "2026-07-18T00:00:00Z", 0)
	if !has(rep.Refreshed, "store") {
		t.Fatalf("a bound capability with no proof must be observed: %+v", rep)
	}
}

func TestRefreshWindowRefreshesBeforeExpiry(t *testing.T) {
	// proof recorded at 00:00 with ttl 900s -> decays at 00:15
	led, lp := fixture(t, "2026-07-18T00:00:00Z", 900)
	// at 00:10 with no window: deadline 00:10 < 00:15 -> still fresh
	if rep := run(t, led, lp, "2026-07-18T00:10:00Z", 0); !has(rep.Fresh, "store") {
		t.Fatalf("without a window the not-yet-decayed proof is fresh: %+v", rep)
	}
	// at 00:10 with a 600s window: deadline 00:20 > 00:15 -> refresh proactively
	led2, lp2 := fixture(t, "2026-07-18T00:00:00Z", 900)
	if rep := run(t, led2, lp2, "2026-07-18T00:10:00Z", 600); !has(rep.Refreshed, "store") {
		t.Fatalf("a window past the decay time must refresh proactively: %+v", rep)
	}
}
