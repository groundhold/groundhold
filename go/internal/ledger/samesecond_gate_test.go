package ledger

import (
	"os"
	"path/filepath"
	"testing"
)

// D667. Two observations of one path recorded in the SAME clock second: the
// projection kept the incumbent, so the fresher reading was silently discarded.
// Reachable by construction — `converge` runs two observe phases under one `--at`,
// and any scheduler pinning one `--at` per tick re-observes into the same second.
//
// Measured with the product before the fix: a second `observe --record` at the same
// `--at` wrote `service.managed ttl=60` on line 23 while line 19 held `ttl=86400`;
// `audit` at +2min said clean, because it used line 19. With `--at` one second
// later, the same pair blocked as stale.
func TestASameSecondReObservationWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	led := New()
	w := &Writer{Path: path, Led: led, Env: "test", Clock: 1767225600, Actor: "t"}
	tok, err := w.AppendLease([]string{"db"}, map[string]any{"ttlSeconds": 900})
	if err != nil {
		t.Fatal(err)
	}
	rec := func(value any, ttl int) map[string]any {
		return map[string]any{"observations": []any{map[string]any{
			"path": "service.managed", "value": value,
			"observedAt": "2026-01-01T00:00:00Z", "ttlSeconds": ttl,
			"derivation": "measured", "source": "provider-api"}}}
	}
	if err := w.Append("observation.recorded", []string{"db"}, rec(true, 86400), tok); err != nil {
		t.Fatal(err)
	}
	if err := w.Append("observation.recorded", []string{"db"}, rec(false, 60), tok); err != nil {
		t.Fatal(err)
	}

	led2, err := ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := led2.Observations["db"]["service.managed"]
	if v, _ := got.Value.(bool); v {
		t.Errorf("the projection kept the FIRST reading (value=%v) — the ledger holds "+
			"a later one recorded in the same second, and every verdict is computed "+
			"from the one that was superseded", got.Value)
	}
	if got.TTLSeconds != 60 {
		t.Errorf("ttlSeconds = %d, want 60 — the fresher record's own freshness "+
			"window was discarded with it", got.TTLSeconds)
	}
}

// The control, from D45: a measurement outranks a declaration at the same instant
// whatever order they arrive in. Recency must not override the basis.
func TestAMeasurementStillOutranksADeclarationAtTheSameInstant(t *testing.T) {
	measured := ObsRecord{ObservedAt: "2026-01-01T00:00:00Z", Derivation: "measured"}
	declared := ObsRecord{ObservedAt: "2026-01-01T00:00:00Z", Derivation: "config-intent"}
	if !obsNewer(measured, declared) {
		t.Error("a measurement arriving after a declaration must win")
	}
	if obsNewer(declared, measured) {
		t.Error("a declaration arriving after a measurement must NOT win — the basis " +
			"outranks the order (D45)")
	}
}
