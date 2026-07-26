package gcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// pqUpdateServer serves GET subscription (ours, with a retention) and PATCH, recording
// the patch body + query so the test can assert the updateMask and new retention.
func pqUpdateServer(t *testing.T, capLabel string, patched, query *string) *httptest.Server {
	t.Helper()
	sub := `{"name":"projects/acme-prod/subscriptions/pv-orders-abcd1234",` +
		`"labels":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
		`"messageRetentionDuration":"600s"}`
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PATCH":
				b, _ := io.ReadAll(r.Body)
				*patched = string(b)
				*query = r.URL.RawQuery
				_, _ = w.Write([]byte(sub))
			case "GET":
				_, _ = w.Write([]byte(sub))
			default:
				w.WriteHeader(500)
			}
		}))
}

func TestUpdatePubSubQueueRetention(t *testing.T) {
	var patched, query string
	srv := pqUpdateServer(t, "orders", &patched, &query)
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.Update("pubsub-queue", "orders", "prod", "pubsub:acme-prod:pv-orders-abcd1234",
		map[string]any{"retention.minimum": "86400s"}, nil, []string{"retention.minimum"}, "k")
	if res.Status != "succeeded" {
		t.Fatalf("update: %+v", res)
	}
	if !strings.Contains(query, "updateMask=messageRetentionDuration") {
		t.Fatalf("updateMask missing from query: %q", query)
	}
	if !strings.Contains(patched, `"messageRetentionDuration":"86400s"`) {
		t.Fatalf("patch body did not set the new retention: %s", patched)
	}
}

func TestUpdatePubSubQueueRetentionEnvelopeRefused(t *testing.T) {
	var patched, query string
	srv := pqUpdateServer(t, "orders", &patched, &query)
	defer srv.Close()
	d := queueDriver(t, srv)
	// 60s is below the 600s Pub/Sub floor — must refuse, never clamp, never patch.
	res := d.Update("pubsub-queue", "orders", "prod", "pubsub:acme-prod:pv-orders-abcd1234",
		map[string]any{"retention.minimum": "60s"}, nil, []string{"retention.minimum"}, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "envelope") {
		t.Fatalf("sub-floor retention must refuse, got %+v", res)
	}
	if patched != "" {
		t.Fatalf("no patch must be sent when the value is refused, got %s", patched)
	}
}

func TestUpdatePubSubQueueForeignRefused(t *testing.T) {
	var patched, query string
	srv := pqUpdateServer(t, "someone-else", &patched, &query)
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.Update("pubsub-queue", "orders", "prod", "pubsub:acme-prod:pv-orders-abcd1234",
		map[string]any{"retention.minimum": "86400s"}, nil, []string{"retention.minimum"}, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign subscription must refuse patch, got %+v", res)
	}
}

func TestClassifyPubSubQueueChange(t *testing.T) {
	d := NewDriver("acme-prod")
	if cls, _ := d.ClassifyChange("pubsub-queue", "retention.minimum", "600s", "86400s", nil); cls != "mutable" {
		t.Fatalf("retention.minimum must be mutable, got %q", cls)
	}
	if cls, _ := d.ClassifyChange("pubsub-queue", "reliability.deadLetter", false, true, nil); cls != "mutable" {
		t.Fatalf("reliability.deadLetter must be mutable (patchable in place), got %q", cls)
	}
	if cls, _ := d.ClassifyChange("pubsub-queue", "delivery.guarantee", "at-least-once", "exactly-once", nil); cls != "immutable" {
		t.Fatalf("delivery.guarantee must be immutable, got %q", cls)
	}
	if cls, _ := d.ClassifyChange("pubsub-queue", "network.publicExposure", false, true, nil); cls != "unsupported" {
		t.Fatalf("exposure must be unsupported (not wired this slice), got %q", cls)
	}
}

// enabling deadLetter in place: the patch sends a deadLetterPolicy (from the impl
// operands) and lists it in the updateMask.
func TestUpdatePubSubQueueDeadLetterSet(t *testing.T) {
	var patched, query string
	srv := pqUpdateServer(t, "orders", &patched, &query)
	defer srv.Close()
	d := queueDriver(t, srv)
	impl := map[string]any{
		"dead_letter_topic":     "projects/acme-prod/topics/orders-dlq",
		"max_delivery_attempts": 5,
	}
	res := d.Update("pubsub-queue", "orders", "prod", "pubsub:acme-prod:pv-orders-abcd1234",
		map[string]any{"reliability.deadLetter": true}, impl, []string{"reliability.deadLetter"}, "k")
	if res.Status != "succeeded" {
		t.Fatalf("update: %+v", res)
	}
	if !strings.Contains(query, "updateMask=deadLetterPolicy") {
		t.Fatalf("updateMask missing deadLetterPolicy: %q", query)
	}
	if !strings.Contains(patched, `"deadLetterTopic":"projects/acme-prod/topics/orders-dlq"`) ||
		!strings.Contains(patched, `"maxDeliveryAttempts":5`) {
		t.Fatalf("patch body did not carry the deadLetterPolicy: %s", patched)
	}
}

// enabling deadLetter with a missing operand must refuse — never patch a half-
// specified policy.
func TestUpdatePubSubQueueDeadLetterMissingOperandRefused(t *testing.T) {
	var patched, query string
	srv := pqUpdateServer(t, "orders", &patched, &query)
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.Update("pubsub-queue", "orders", "prod", "pubsub:acme-prod:pv-orders-abcd1234",
		map[string]any{"reliability.deadLetter": true}, nil, []string{"reliability.deadLetter"}, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "dead_letter_topic") {
		t.Fatalf("missing operand must refuse, got %+v", res)
	}
	if patched != "" {
		t.Fatalf("no patch must be sent when the operand is missing, got %s", patched)
	}
}

// disabling deadLetter in place: the field is absent from the body and the
// updateMask entry resets it (patch-to-empty).
func TestUpdatePubSubQueueDeadLetterClear(t *testing.T) {
	var patched, query string
	srv := pqUpdateServer(t, "orders", &patched, &query)
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.Update("pubsub-queue", "orders", "prod", "pubsub:acme-prod:pv-orders-abcd1234",
		map[string]any{"reliability.deadLetter": false}, nil, []string{"reliability.deadLetter"}, "k")
	if res.Status != "succeeded" {
		t.Fatalf("clear update: %+v", res)
	}
	if !strings.Contains(query, "updateMask=deadLetterPolicy") {
		t.Fatalf("updateMask missing deadLetterPolicy on clear: %q", query)
	}
	if strings.Contains(patched, "deadLetterTopic") {
		t.Fatalf("clearing must not carry a deadLetterPolicy body: %s", patched)
	}
}
