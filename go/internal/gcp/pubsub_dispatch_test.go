package gcp

import (
	"testing"
)

// Regression guard (token-split): the driver MUST decide Pub/Sub queue-vs-topic
// from the SERVICE token (pubsub-queue / pubsub-topic), NOT by comparing the
// `capability` argument to the literal type string. Through the real apply path
// that argument is the capability ID (e.g. "orders"), never the type — so the
// old `capability == "capability.messaging.queue"` dispatch built a QUEUE
// candidate as a TOPIC. Here every call uses a realistic capability ID, exactly
// as apply does.

func pubsubDispatchDriver(t *testing.T) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	return NewDriver("acme-prod")
}

// A queue that declares a queue-EXCLUSIVE attribute (delivery.guarantee) must
// validate through the queue builder. Misdispatched to the topic builder it would
// be REFUSED (the topic builder rejects unknown attributes) — which is exactly
// how the pre-fix bug manifested for a realistic capability ID.
func TestPubSubQueueDispatchByServiceToken(t *testing.T) {
	d := pubsubDispatchDriver(t)
	queueAttrs := map[string]any{
		"location.region":        "europe-west1",
		"delivery.guarantee":     "exactly-once",
		"ordering.enabled":       true,
		"retention.minimum":      "1h",
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"service.managed":        true,
	}
	// capability ID is "orders" (NOT the type) — the apply-path reality.
	if err := d.Validate("pubsub-queue", "orders", "prod", queueAttrs, nil, 1); err != nil {
		t.Fatalf("queue with a queue-exclusive attr must validate via the queue builder, got: %v", err)
	}
	// The same attrs under the topic token MUST be refused (a topic holds no
	// delivery.guarantee) — proving the tokens route to different builders.
	if err := d.Validate("pubsub-topic", "orders", "prod", queueAttrs, nil, 1); err == nil {
		t.Fatal("queue-exclusive attrs must be refused by the topic builder")
	}
}

// Create through the queue token runs the constitutive-composite queue sequence
// (backing topic + subscription) and succeeds — the end-to-end dispatch proof.
// The ownership label written is the capability ID ("orders"), not the type.
func TestPubSubQueueCreateYieldsQueueHandle(t *testing.T) {
	srv := pubsubQueueServer(t, sanitizeLabel("orders"), "prod")
	defer srv.Close()
	d := pubsubDispatchDriver(t)
	d.PubSubBaseURL = srv.URL
	attrs := map[string]any{
		"location.region":        "europe-west1",
		"delivery.guarantee":     "exactly-once",
		"ordering.enabled":       true,
		"retention.minimum":      "10m",
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"service.managed":        true,
	}
	res := d.Create("pubsub-queue", "orders", "prod", attrs, nil, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("queue create must succeed via the queue builder: %+v", res)
	}
	if res.ProviderID == "" {
		t.Fatalf("queue create produced no providerID: %+v", res)
	}
	// A degenerate queue (no queue-exclusive attr) must STILL route to the queue
	// builder by its token — the silent-mis-build case the old heuristic missed.
	if err := d.Validate("pubsub-queue", "orders", "prod", map[string]any{
		"location.region": "europe-west1", "encryption.atRest": true, "service.managed": true,
	}, nil, 1); err != nil {
		t.Fatalf("degenerate queue must still validate as a queue: %v", err)
	}
}
