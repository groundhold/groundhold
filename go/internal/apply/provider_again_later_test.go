package apply

import (
	"testing"

	"groundhold/internal/perr"
	"groundhold/internal/provider"
)

// D237: a mutation throttled BEFORE it lands is unknown+Retryable, so apply emits
// provider-again-later (retry the same verb after backoff), NOT reconcile-required
// (which would burn a reconcile round-trip for a resource that never landed). The
// receipt still stays pending — unknown never claims a fabricated success.
func TestApplyMapsRetryableUnknownToProviderAgainLater(t *testing.T) {
	c, cand, plan := setupPlan(t)
	key := firstCreateKey(t, plan)
	fake := &provider.Fake{RetryableKeys: map[string]bool{key: true}}
	res := Apply(c, cand, nil, plan, freshLedger(t), fake, pfAt, false)
	if res.Code != perr.ProviderAgainLater {
		t.Fatalf("expected provider-again-later, got %s/%d (reasons=%v)", res.Code, res.Exit, res.Reasons)
	}
	if res.Status != "unknown" {
		t.Fatalf("a throttle is unknown, never failed/succeeded: got %q", res.Status)
	}
}

// Contrast: a non-retryable unknown (5xx/transport/live-403) MAY have landed, so
// it stays reconcile-required — the throttle carve-out must not swallow it.
func TestApplyMapsAmbiguousUnknownToReconcileRequired(t *testing.T) {
	c, cand, plan := setupPlan(t)
	key := firstCreateKey(t, plan)
	fake := &provider.Fake{UnknownKeys: map[string]bool{key: true}}
	res := Apply(c, cand, nil, plan, freshLedger(t), fake, pfAt, false)
	if res.Code != perr.ReconcileRequired {
		t.Fatalf("expected reconcile-required, got %s (reasons=%v)", res.Code, res.Reasons)
	}
}

// D241: a throttle concludes as a `retryable` receipt that CLEARS the pending set
// (unlike an unknown, which blocks a re-apply with reconcile-required). Re-applying
// the SAME sealed plan is then no longer blocked by the pending gate — it instead
// hits the stale-decision gate (the receipt moved the capability's head), which is
// exactly why converge RE-PLANS on backoff rather than re-applying the old plan.
func TestApplyThrottleClearsPendingForCleanRetry(t *testing.T) {
	c, cand, plan := setupPlan(t)
	key := firstCreateKey(t, plan)
	led := freshLedger(t)
	r1 := Apply(c, cand, nil, plan, led, &provider.Fake{RetryableKeys: map[string]bool{key: true}}, pfAt, false)
	if r1.Code != perr.ProviderAgainLater {
		t.Fatalf("1st apply: want provider-again-later, got %s (%v)", r1.Code, r1.Reasons)
	}
	// 2nd apply of the same plan: the retryable receipt cleared pending, so this is
	// NOT reconcile-required. (It is stale — the head moved — which is why converge
	// re-plans; a re-planned apply lands cleanly, covered by the converge test.)
	r2 := Apply(c, cand, nil, plan, led, &provider.Fake{}, pfAt, false)
	if r2.Code == perr.ReconcileRequired {
		t.Fatalf("2nd apply blocked by a pending receipt — throttle did not clear it: %v", r2.Reasons)
	}
}

func firstCreateKey(t *testing.T, plan map[string]any) string {
	t.Helper()
	body, _ := plan["plan"].(map[string]any)
	actions, _ := body["actions"].([]any)
	for _, it := range actions {
		a, _ := it.(map[string]any)
		if a["operation"] == "create" {
			if k, _ := a["idempotencyKey"].(string); k != "" {
				return k
			}
		}
	}
	t.Fatal("no create action with an idempotencyKey in the plan")
	return ""
}

// D243: a driver-captured Retry-After hint propagates from the CreateResult into
// the apply result, so converge can honor it as the backoff delay.
func TestApplyPropagatesRetryAfter(t *testing.T) {
	c, cand, plan := setupPlan(t)
	key := firstCreateKey(t, plan)
	res := Apply(c, cand, nil, plan,
		freshLedger(t), &provider.Fake{RetryableKeys: map[string]bool{key: true}, RetryAfterSeconds: 12},
		pfAt, false)
	if res.Code != perr.ProviderAgainLater {
		t.Fatalf("want provider-again-later, got %s", res.Code)
	}
	if res.RetryAfterSeconds != 12 {
		t.Fatalf("Retry-After hint must propagate to the apply result, got %d", res.RetryAfterSeconds)
	}
}
