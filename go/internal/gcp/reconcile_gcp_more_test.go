package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file extends reconcile_gcp_test.go, which exercises the generic
// reconciler's CREATE path across representative services plus the LRO-first
// short-circuit. These tests pin: the two small pure helpers (reasonOr,
// receiptGenerationGCP — probeUnreadable is exercised as a byproduct), and
// the DELETE/UPDATE op branches of reconcileGeneric that the create-focused
// suite does not reach (no pinned id, an unreadable/malformed-pid probe, a
// vanished update target, a foreign-owned update target).

func TestReasonOr(t *testing.T) {
	if got := reasonOr("explicit reason", "fallback"); got != "explicit reason" {
		t.Fatalf("a non-empty reason must win, got %q", got)
	}
	if got := reasonOr("", "fallback"); got != "fallback" {
		t.Fatalf("an empty reason must fall back, got %q", got)
	}
}

func TestProbeUnreadable(t *testing.T) {
	pr := probeUnreadable("transient read failure")
	if pr.readable {
		t.Fatal("probeUnreadable must report readable=false")
	}
	if pr.found || pr.ours || pr.ready {
		t.Fatalf("probeUnreadable must not assert found/ours/ready, got %+v", pr)
	}
	if pr.reason != "transient read failure" {
		t.Fatalf("reason = %q", pr.reason)
	}
}

func TestReceiptGenerationGCP(t *testing.T) {
	cases := []struct {
		name string
		gen  any
		want int
	}{
		{"missing", nil, 1},
		{"int normal", 3, 3},
		{"int zero defaults to 1", 0, 1},
		{"float64 normal (ledger round-trip)", float64(4), 4},
		{"float64 zero defaults to 1", float64(0), 1},
		{"wrong type defaults to 1", "3", 1},
	}
	for _, c := range cases {
		receipt := map[string]any{}
		if c.gen != nil {
			receipt["generation"] = c.gen
		}
		if got := receiptGenerationGCP(receipt); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

// ─── reconcileGeneric: delete op branches ───────────────────────────────────

func TestReconcileDeleteBranches(t *testing.T) {
	d := recDriver(t, "acme-prod")

	t.Run("no pinned id is unknown", func(t *testing.T) {
		r := d.Reconcile("cache", "prod", map[string]any{
			"target": "gcp.memorystore/cache", "operation": "delete"})
		if r.Status != "unknown" || !strings.Contains(r.Reason, "no targetProviderId") {
			t.Fatalf("a delete receipt with no pinned id must be unknown, got %+v", r)
		}
	})

	t.Run("malformed pid is unknown with the probe's own reason", func(t *testing.T) {
		r := d.Reconcile("cache", "prod", map[string]any{
			"target": "gcp.memorystore/cache", "operation": "delete",
			"targetProviderId": "not-a-valid-pid"})
		if r.Status != "unknown" || !strings.Contains(r.Reason, "gredis") {
			t.Fatalf("an unreadable (malformed pid) delete probe must be unknown with the split error, got %+v", r)
		}
	})

	t.Run("unwired service reconcile fails closed to unknown", func(t *testing.T) {
		r := d.Reconcile("x", "prod", map[string]any{
			"target": "gcp.__not_a_service__/x", "operation": "delete"})
		if r.Status != "unknown" || !strings.Contains(r.Reason, "not wired") {
			t.Fatalf("an unwired service must fail closed to unknown, got %+v", r)
		}
	})
}

// ─── reconcileGeneric: update op branches ───────────────────────────────────

func TestReconcileUpdateBranches(t *testing.T) {
	d := recDriver(t, "acme-prod")

	t.Run("no pinned id is unknown", func(t *testing.T) {
		r := d.Reconcile("cache", "prod", map[string]any{
			"target": "gcp.memorystore/cache", "operation": "update"})
		if r.Status != "unknown" || !strings.Contains(r.Reason, "no targetProviderId") {
			t.Fatalf("an update receipt with no pinned id must be unknown, got %+v", r)
		}
	})

	t.Run("malformed pid is unknown with the probe's own reason", func(t *testing.T) {
		r := d.Reconcile("cache", "prod", map[string]any{
			"target": "gcp.memorystore/cache", "operation": "update",
			"targetProviderId": "not-a-valid-pid"})
		if r.Status != "unknown" || !strings.Contains(r.Reason, "gredis") {
			t.Fatalf("an unreadable update probe must be unknown with the split error, got %+v", r)
		}
	})

	t.Run("vanished update target is unknown", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		d.MemorystoreBaseURL = srv.URL
		pid := gredisProviderID("acme-prod", "europe-central2", "red-x")
		r := d.Reconcile("cache", "prod", map[string]any{
			"target": "gcp.memorystore/cache", "operation": "update", "targetProviderId": pid})
		if r.Status != "unknown" || !strings.Contains(r.Reason, "not found") {
			t.Fatalf("an update target that vanished must be unknown, got %+v", r)
		}
	})

	t.Run("foreign update target fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"labels":{},"state":"READY"}`))
		}))
		defer srv.Close()
		d.MemorystoreBaseURL = srv.URL
		pid := gredisProviderID("acme-prod", "europe-central2", "red-x")
		r := d.Reconcile("cache", "prod", map[string]any{
			"target": "gcp.memorystore/cache", "operation": "update", "targetProviderId": pid})
		if r.Status != "failed" || !strings.Contains(r.Reason, "not ours") {
			t.Fatalf("a foreign-owned update target must fail, got %+v", r)
		}
	})
}
