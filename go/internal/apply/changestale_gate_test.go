package apply

import (
	"strings"
	"testing"

	"groundhold/internal/ledger"
)

// D632. `plan` refuses to seal against a decayed observation. `apply` never re-judged
// it: its only freshness check was `foldStaleReason`, which covers folded operands and
// nothing else. So the change set's own `from:` value — the assertion about current
// reality that justifies the mutation — was trusted from the plan, however old the plan
// was. Measured by an audit of the safety clock:
//
//	observation service.managed=true at 01:00:00Z, ttl 3600 (expires 02:00:00Z)
//	plan sealed 01:00:01Z with changes [{path: service.managed, from: true, to: false}]
//
//	plan  … --at 2030-01-01T00:00:00Z   exit 2   "observation is stale — re-observe first"
//	apply … --at 2030-01-01T00:00:00Z   exit 0   APPLIED
//
// and a real receipt in the ledger: a mutation justified by a proof that died four
// years earlier. `converge` is safe because it re-plans; the hole is reachable through
// exactly the seal-now-apply-later review workflow the docs promote.
//
// D42/D47/D325 state that apply re-derives rather than trusts. Freshness was the one
// thing it still took on the plan's word.
func TestApplyRefusesAChangeItsEvidenceNoLongerSupports(t *testing.T) {
	led := &ledger.Ledger{
		Observations: map[string]map[string]ledger.ObsRecord{
			"db": {"service.managed": {
				ObservedAt: "2026-01-01T01:00:00Z", TTLSeconds: 3600,
			}},
		},
	}
	actions := []any{map[string]any{
		"id": "a-update-db", "capability": "db",
		"changes": []any{map[string]any{
			"path": "service.managed", "from": true, "to": false,
		}},
	}}

	at := func(ts string) int {
		c, err := ledger.ParseTs(ts)
		if err != nil {
			t.Fatalf("fixture clock %q: %v", ts, err)
		}
		return c
	}

	t.Run("inside the ttl the change stands", func(t *testing.T) {
		if r := changeStaleReason(led, actions, at("2026-01-01T01:59:59Z")); r != "" {
			t.Errorf("a change one second INSIDE the ttl was refused: %s", r)
		}
	})

	t.Run("past the ttl the change is refused", func(t *testing.T) {
		r := changeStaleReason(led, actions, at("2026-01-01T02:00:01Z"))
		if r == "" {
			t.Fatal("a change justified by an expired observation was accepted — the " +
				"plan asserts a `from` value nothing currently witnesses")
		}
		if !strings.Contains(r, "service.managed") || !strings.Contains(r, "expired") {
			t.Errorf("the refusal does not name the attribute and the reason: %s", r)
		}
	})

	t.Run("years later, emphatically refused", func(t *testing.T) {
		if changeStaleReason(led, actions, at("2030-01-01T00:00:00Z")) == "" {
			t.Error("a four-year-old proof still justified a mutation")
		}
	})

	// The other control, and the one the conformance suite taught me. A change whose
	// attribute has NO observation is not this check's business: the compiler derives
	// changes from bindings as well, and a legitimately seeded binding carries no
	// observation.recorded at all. My first version refused those and broke
	// `apply-updates-a-bound-capability` — an over-reach caught by the suite, which is
	// what the suite is for.
	t.Run("a change with no observation of that attribute is not this check", func(t *testing.T) {
		orphan := []any{map[string]any{
			"id": "a-update-db", "capability": "db",
			"changes": []any{map[string]any{"path": "encryption.atRest", "to": false}},
		}}
		if r := changeStaleReason(led, orphan, at("2026-01-01T01:30:00Z")); r != "" {
			t.Errorf("refused a change the ledger has no observation for: %s", r)
		}
	})

	// The control: an action with no change set (a create, a delete) is untouched.
	t.Run("an action with no changes is not affected", func(t *testing.T) {
		creates := []any{map[string]any{
			"id": "a-create-db", "capability": "db", "operation": "create",
		}}
		if r := changeStaleReason(led, creates, at("2030-01-01T00:00:00Z")); r != "" {
			t.Errorf("a create was refused by a change-set check: %s", r)
		}
	})
}
