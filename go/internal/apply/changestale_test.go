package apply

import (
	"testing"

	"groundhold/internal/ledger"
)

// TestChangeStaleReasonMatchesCanonicalFreshness pins D967: changeStaleReason (the
// D632 pre-lease gate that lets apply MUTATE on a change whose `from` value
// asserts current reality) judged freshness differently from every sibling —
// ledger.ObservationExpired, foldStaleReason right below it, audit, forecast, the
// compiler. Two reassuring-direction holes let a real mutation ride on evidence
// all of them call stale: a `TTLSeconds > 0` conjunct that SKIPS the check when
// ttl==0 (stale at any age reads fresh), and no D189 future-date guard.
func TestChangeStaleReasonMatchesCanonicalFreshness(t *testing.T) {
	at, _ := ledger.ParseTs("2026-08-02T00:00:00Z")
	action := func(cap, path string) []any {
		return []any{map[string]any{"id": "a1", "capability": cap,
			"changes": []any{map[string]any{"path": path}}}}
	}

	t.Run("ttl=0 observation is stale at any age (canonical: age>0)", func(t *testing.T) {
		led := ledger.New()
		led.Observations["db"] = map[string]ledger.ObsRecord{
			"service.managed": {Value: true, ObservedAt: "2026-01-01T00:00:00Z",
				TTLSeconds: 0, Derivation: "measured"}, // ~7 months old, no ttl window
		}
		if changeStaleReason(led, action("db", "service.managed"), at) == "" {
			t.Fatal("a ttl=0 observation 7 months old justified a mutation — canonical " +
				"ObservationExpired and every sibling call it stale; apply must not re-seal on it")
		}
	})

	t.Run("future-dated observation is invalid, never fresh (D189)", func(t *testing.T) {
		led := ledger.New()
		led.Observations["db"] = map[string]ledger.ObsRecord{
			"service.managed": {Value: true, ObservedAt: "2026-08-10T00:00:00Z",
				TTLSeconds: 3600, Derivation: "measured"}, // dated 8 days AFTER --at
		}
		if changeStaleReason(led, action("db", "service.managed"), at) == "" {
			t.Fatal("an observation dated after the evaluation time justified a mutation — " +
				"foldStaleReason, audit and forecast all reject a negative age (D189)")
		}
	})

	t.Run("a fresh observation within ttl still passes (control)", func(t *testing.T) {
		led := ledger.New()
		led.Observations["db"] = map[string]ledger.ObsRecord{
			"service.managed": {Value: true, ObservedAt: "2026-08-01T23:50:00Z",
				TTLSeconds: 3600, Derivation: "measured"}, // 10 min old, ttl 1h
		}
		if r := changeStaleReason(led, action("db", "service.managed"), at); r != "" {
			t.Fatalf("a fresh observation must not be refused, got %q", r)
		}
	})
}
