package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file extends pubsub_queue_test.go, which pins the happy composite
// create/observe/delete loop, the residency + dead-letter honesty branches,
// and the metamorphic round-trip. These tests pin the remaining branches:
// subscriptionConfigMatches (0% before this file), the backing-topic and
// subscription conflict/transport/5xx ladders in createPubSubQueue,
// pubsubGetSubscription's error branches, observePubSubQueue's backing-topic
// read-error diagnostics, and deletePubSubQueue/updatePubSubQueue's remaining
// branches.

// --- subscriptionConfigMatches -------------------------------------------

func TestSubscriptionConfigMatches(t *testing.T) {
	base := subscriptionDoc{EnableExactlyOnceDelivery: true, EnableMessageOrdering: false,
		MessageRetentionDuration: "600s"}
	match := map[string]any{"enableExactlyOnceDelivery": true, "enableMessageOrdering": false,
		"messageRetentionDuration": "600s"}
	if !subscriptionConfigMatches(base, match) {
		t.Fatal("an identical config must match")
	}
	if subscriptionConfigMatches(base, map[string]any{"enableExactlyOnceDelivery": false, "enableMessageOrdering": false}) {
		t.Fatal("a differing exactly-once flag must not match")
	}
	if subscriptionConfigMatches(base, map[string]any{"enableExactlyOnceDelivery": true, "enableMessageOrdering": true}) {
		t.Fatal("a differing ordering flag must not match")
	}
	if subscriptionConfigMatches(base, map[string]any{"enableExactlyOnceDelivery": true, "enableMessageOrdering": false,
		"messageRetentionDuration": "1200s"}) {
		t.Fatal("a differing pinned retention must not match")
	}
	// retention unpinned in `want` is not compared.
	if !subscriptionConfigMatches(base, map[string]any{"enableExactlyOnceDelivery": true, "enableMessageOrdering": false}) {
		t.Fatal("an unpinned retention must not be compared")
	}
	// dead-letter: absent in `want` -> not compared; present in `want` but absent
	// on the doc -> mismatch; present + matching -> match.
	wantDL := map[string]any{"enableExactlyOnceDelivery": true, "enableMessageOrdering": false,
		"deadLetterPolicy": map[string]any{"deadLetterTopic": "projects/p/topics/dlq", "maxDeliveryAttempts": 5}}
	if subscriptionConfigMatches(base, wantDL) {
		t.Fatal("a doc with no deadLetterPolicy must not match a desired one")
	}
	withDL := base
	withDL.DeadLetterPolicy = &struct {
		DeadLetterTopic     string `json:"deadLetterTopic"`
		MaxDeliveryAttempts int    `json:"maxDeliveryAttempts"`
	}{DeadLetterTopic: "projects/p/topics/dlq", MaxDeliveryAttempts: 5}
	if !subscriptionConfigMatches(withDL, wantDL) {
		t.Fatal("a matching deadLetterPolicy must match")
	}
	wantDLDiff := map[string]any{"enableExactlyOnceDelivery": true, "enableMessageOrdering": false,
		"deadLetterPolicy": map[string]any{"deadLetterTopic": "projects/p/topics/dlq", "maxDeliveryAttempts": 9}}
	if subscriptionConfigMatches(withDL, wantDLDiff) {
		t.Fatal("a differing maxDeliveryAttempts must not match")
	}
}

// --- createPubSubQueue: backing-topic ladder --------------------------

func TestCreatePubSubQueueBackingTopicTransportErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d := queueDriver(t, srv)
	srv.Close()
	res := d.createPubSubQueue("orders", "prod", queueAttrs(), nil, 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a lost backing-topic create must be unknown WITH the pid, got %+v", res)
	}
}

func TestCreatePubSubQueueBackingTopic5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.createPubSubQueue("orders", "prod", queueAttrs(), nil, 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a 503 on the backing topic PUT must be unknown WITH the pid, got %+v", res)
	}
}

func TestCreatePubSubQueueBackingTopicEmptyBodyIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.createPubSubQueue("orders", "prod", queueAttrs(), nil, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "carried no topic") {
		t.Fatalf("an empty backing-topic create response must be unknown, got %+v", res)
	}
}

func TestCreatePubSubQueueBackingTopicConflictNotOurs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/topics/"):
			w.WriteHeader(http.StatusConflict)
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/topics/"):
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/the-q","labels":{"groundhold-capability":"other"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.createPubSubQueue("orders", "prod", queueAttrs(), nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign backing-topic conflict must be failed, got %+v", res)
	}
}

func TestCreatePubSubQueueBackingTopicConflictResidencyMismatch(t *testing.T) {
	topic := `{"name":"projects/acme-prod/topics/the-q",` +
		`"labels":{"groundhold-capability":"orders","groundhold-environment":"prod"},` +
		`"messageStoragePolicy":{"allowedPersistenceRegions":["europe-west4"]}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/topics/"):
			w.WriteHeader(http.StatusConflict)
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/topics/"):
			_, _ = w.Write([]byte(topic))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.createPubSubQueue("orders", "prod", queueAttrs(), nil, 1) // wants europe-west1
	if res.Status != "failed" || !strings.Contains(res.Reason, "storage regions") {
		t.Fatalf("a residency mismatch on the backing topic must be failed, got %+v", res)
	}
}

// --- createPubSubQueue: subscription ladder ------------------------------

func TestCreatePubSubQueueSubscriptionTransportErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" && strings.Contains(r.URL.Path, "/topics/") {
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/the-q"}`))
		}
	}))
	d := queueDriver(t, srv)
	// close after wiring — the subscription PUT will hit a dead connection.
	srv.Close()
	res := d.createPubSubQueue("orders", "prod", queueAttrs(), nil, 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a lost subscription create must be unknown WITH the pid, got %+v", res)
	}
}

func TestCreatePubSubQueueSubscription5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/topics/"):
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/the-q"}`))
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/subscriptions/"):
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.createPubSubQueue("orders", "prod", queueAttrs(), nil, 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a 503 on the subscription PUT must be unknown WITH the pid, got %+v", res)
	}
}

func TestCreatePubSubQueueSubscriptionTerminal4xxKeepsPID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/topics/"):
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/the-q"}`))
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/subscriptions/"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"malformed subscription"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.createPubSubQueue("orders", "prod", queueAttrs(), nil, 1)
	// D29: even a terminal 4xx on the subscription keeps the pid — the backing
	// topic landed and the pid is deterministic, so the handle must never drop.
	if res.Status != "failed" || res.ProviderID == "" {
		t.Fatalf("a terminal subscription failure must still carry the pid, got %+v", res)
	}
}

func TestCreatePubSubQueueSubscriptionEmptyBodyIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/topics/"):
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/the-q"}`))
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/subscriptions/"):
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.createPubSubQueue("orders", "prod", queueAttrs(), nil, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "carried no subscription") {
		t.Fatalf("an empty subscription create response must be unknown, got %+v", res)
	}
}

func TestCreatePubSubQueueSubscriptionConflictNotOurs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/topics/"):
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/the-q"}`))
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/subscriptions/"):
			w.WriteHeader(http.StatusConflict)
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/subscriptions/"):
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/subscriptions/the-q","labels":{"groundhold-capability":"other"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.createPubSubQueue("orders", "prod", queueAttrs(), nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign subscription conflict must be failed, got %+v", res)
	}
}

func TestCreatePubSubQueueSubscriptionConflictConfigMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/topics/"):
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/the-q"}`))
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/subscriptions/"):
			w.WriteHeader(http.StatusConflict)
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/subscriptions/"):
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/subscriptions/the-q",` +
				`"labels":{"groundhold-capability":"orders","groundhold-environment":"prod"},` +
				`"enableExactlyOnceDelivery":true}`)) // queueAttrs() wants at-least-once (false)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.createPubSubQueue("orders", "prod", queueAttrs(), nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "config differs") {
		t.Fatalf("a subscription config mismatch must be failed, got %+v", res)
	}
}

func TestCreatePubSubQueueSubscriptionConflictReadUnreadable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/topics/"):
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/the-q"}`))
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/subscriptions/"):
			w.WriteHeader(http.StatusConflict)
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/subscriptions/"):
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.createPubSubQueue("orders", "prod", queueAttrs(), nil, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("an unreadable subscription follow-up must be unknown, got %+v", res)
	}
}

func TestCreatePubSubQueueSubscriptionConflictGoneOnFollowup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/topics/"):
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/the-q"}`))
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/subscriptions/"):
			w.WriteHeader(http.StatusConflict)
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/subscriptions/"):
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.createPubSubQueue("orders", "prod", queueAttrs(), nil, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gone on the follow-up read") {
		t.Fatalf("a vanished conflicting subscription must be unknown, got %+v", res)
	}
}

// --- pubsubGetSubscription error branches --------------------------------

func TestPubsubGetSubscriptionErrorBranches(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := queueDriver(t, srv)
		srv.Close()
		if _, _, _, err := d.pubsubGetSubscription("x", "orders", "prod"); err == nil {
			t.Fatal("expected a transport error")
		}
	})
	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		d := queueDriver(t, srv)
		if _, _, _, err := d.pubsubGetSubscription("x", "orders", "prod"); err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("expected an HTTP 403 error, got %v", err)
		}
	})
	t.Run("unparseable body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()
		d := queueDriver(t, srv)
		if _, _, _, err := d.pubsubGetSubscription("x", "orders", "prod"); err == nil {
			t.Fatal("expected a body-parse error")
		}
	})
}

// --- observePubSubQueue backing-topic diagnostics --------------------------

func TestObservePubSubQueueBackingTopicTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"e1","bindings":[]}`))
		case strings.Contains(r.URL.Path, "/subscriptions/"):
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/subscriptions/the-q",` +
				`"labels":{"groundhold-capability":"orders","groundhold-environment":"prod"}}`))
		default:
			w.WriteHeader(500) // topics.get: not-200
		}
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	obs, diags, err := d.observePubSubQueue("orders", "pubsub:acme-prod:the-q")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "location.region" {
			t.Fatalf("an unreadable backing topic must not observe residency: %+v", o)
		}
	}
	found := false
	for _, dg := range diags {
		if strings.Contains(dg, "not observed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a residency diagnostic, got %v", diags)
	}
}

func TestObservePubSubQueueSubscriptionNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/subscriptions/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	obs, diags, err := d.observePubSubQueue("orders", "pubsub:acme-prod:the-q")
	// Corrected with D521: this asserted SILENCE for an absent bound resource,
	// which is the defect F-LC3 exists to prevent.
	if err != nil || !absentMarked(obs) || len(diags) == 0 {
		t.Fatalf("a gone subscription must be nothing-to-observe, got obs=%v diags=%v err=%v", obs, diags, err)
	}
}

func TestObservePubSubQueueSubscriptionReadErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/subscriptions/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	if _, _, err := d.observePubSubQueue("orders", "pubsub:acme-prod:the-q"); err == nil {
		t.Fatal("an unreadable subscription must propagate an error")
	}
}

// --- deletePubSubQueue additional branches -------------------------------

func TestDeletePubSubQueueSubscriptionTransportErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d := queueDriver(t, srv)
	srv.Close()
	res := d.deletePubSubQueue("orders", "prod", "pubsub:acme-prod:the-q")
	if res.Status != "unknown" {
		t.Fatalf("a lost pre-delete subscription read must be unknown, got %+v", res)
	}
}

func TestDeletePubSubQueueSubscriptionAlreadyGoneRetiresTopic(t *testing.T) {
	srv := pubsubQueueServer(t, "orders", "prod")
	defer srv.Close()
	// force the FIRST subscription GET to 404 so the reverse-delete falls
	// through directly to retiring the backing topic.
	n := 0
	orig := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/subscriptions/") {
			n++
			if n == 1 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}
		orig.ServeHTTP(w, r)
	})
	d := queueDriver(t, srv)
	res := d.deletePubSubQueue("orders", "prod", "pubsub:acme-prod:the-q")
	if res.Status != "succeeded" {
		t.Fatalf("a gone subscription must fall through to retiring the backing topic, got %+v", res)
	}
}

func TestDeletePubSubQueueSubscriptionDelete5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/subscriptions/"):
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/subscriptions/the-q",` +
				`"labels":{"groundhold-capability":"orders","groundhold-environment":"prod"}}`))
		case r.Method == "DELETE" && strings.Contains(r.URL.Path, "/subscriptions/"):
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.deletePubSubQueue("orders", "prod", "pubsub:acme-prod:the-q")
	if res.Status != "unknown" {
		t.Fatalf("a 503 on the subscription delete must be unknown, got %+v", res)
	}
}

// --- updatePubSubQueue additional branches -------------------------------

func TestUpdatePubSubQueueUnsupportedPathRefuses(t *testing.T) {
	srv := pubsubQueueServer(t, "orders", "prod")
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.Update("pubsub-queue", "orders", "prod", "pubsub:acme-prod:the-q",
		map[string]any{"location.region": "us"}, nil, []string{"location.region"}, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not patchable in place") {
		t.Fatalf("an unsupported path must refuse, got %+v", res)
	}
}

func TestUpdatePubSubQueueNotFoundRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.Update("pubsub-queue", "orders", "prod", "pubsub:acme-prod:the-q",
		map[string]any{"retention.minimum": "1h"}, nil, []string{"retention.minimum"}, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "no longer exists") {
		t.Fatalf("a vanished subscription must refuse the update, got %+v", res)
	}
}

func TestUpdatePubSubQueuePatch5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PATCH":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "GET":
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/subscriptions/the-q",` +
				`"labels":{"groundhold-capability":"orders","groundhold-environment":"prod"}}`))
		}
	}))
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.Update("pubsub-queue", "orders", "prod", "pubsub:acme-prod:the-q",
		map[string]any{"retention.minimum": "1h"}, nil, []string{"retention.minimum"}, "k")
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a 503 on the subscription patch must be unknown WITH the pid, got %+v", res)
	}
}
