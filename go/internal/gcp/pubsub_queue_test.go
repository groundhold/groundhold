package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func queueAttrs() map[string]any {
	return map[string]any{
		"location.region":        "europe-west1",
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"service.managed":        true,
	}
}

// Residency is honored ONLY via the backing topic's messageStoragePolicy — the
// create plan ALWAYS pins it (a global topic would be a compliance lie).
func TestBuildPubSubQueueResidencyPinned(t *testing.T) {
	plan, err := BuildPubSubQueuePlan("acme-prod", "prod", "orders", queueAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	msp, ok := plan.TopicBody["messageStoragePolicy"].(map[string]any)
	if !ok {
		t.Fatal("residency must be pinned on the backing topic — a global topic is a lie")
	}
	regions, _ := msp["allowedPersistenceRegions"].([]any)
	if len(regions) != 1 || regions[0] != "europe-west1" {
		t.Fatalf("storage policy must pin exactly the region, got %v", regions)
	}
	// the subscription references the backing topic by resource name (one binding).
	if plan.SubBody["topic"] != "projects/acme-prod/topics/"+plan.Name {
		t.Fatalf("subscription must reference the backing topic by name, got %v", plan.SubBody["topic"])
	}
}

func TestBuildPubSubQueueSemantics(t *testing.T) {
	a := queueAttrs()
	a["delivery.guarantee"] = "exactly-once"
	a["ordering.enabled"] = true
	a["retention.minimum"] = "1h"
	a["encryption.customerManagedKeys"] = true
	impl := map[string]any{"kms_key_name": "projects/p/locations/eu/keyRings/r/cryptoKeys/k"}
	plan, err := BuildPubSubQueuePlan("acme-prod", "prod", "orders", a, impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SubBody["enableExactlyOnceDelivery"] != true {
		t.Errorf("exactly-once must set enableExactlyOnceDelivery")
	}
	if plan.SubBody["enableMessageOrdering"] != true {
		t.Errorf("ordering must set enableMessageOrdering")
	}
	if plan.SubBody["messageRetentionDuration"] != "3600s" {
		t.Errorf("retention 1h must map to 3600s, got %v", plan.SubBody["messageRetentionDuration"])
	}
	if plan.TopicBody["kmsKeyName"] != impl["kms_key_name"] {
		t.Errorf("CMEK must set kmsKeyName on the backing topic, got %v", plan.TopicBody["kmsKeyName"])
	}
}

// reliability.deadLetter=true maps to the subscription deadLetterPolicy (target
// topic + attempt threshold), both impl operands (D26).
func TestBuildPubSubQueueDeadLetter(t *testing.T) {
	a := queueAttrs()
	a["reliability.deadLetter"] = true
	impl := map[string]any{
		"dead_letter_topic":     "projects/acme-prod/topics/orders-dlq",
		"max_delivery_attempts": 5,
	}
	plan, err := BuildPubSubQueuePlan("acme-prod", "prod", "orders", a, impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	dl, ok := plan.SubBody["deadLetterPolicy"].(map[string]any)
	if !ok {
		t.Fatal("deadLetter must set a deadLetterPolicy on the subscription")
	}
	if dl["deadLetterTopic"] != "projects/acme-prod/topics/orders-dlq" {
		t.Fatalf("deadLetterTopic operand not mapped, got %v", dl["deadLetterTopic"])
	}
	if dl["maxDeliveryAttempts"] != 5 {
		t.Fatalf("maxDeliveryAttempts operand not mapped, got %v", dl["maxDeliveryAttempts"])
	}
	// deadLetter absent => no policy (backward compatible).
	plain, err := BuildPubSubQueuePlan("acme-prod", "prod", "orders", queueAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := plain.SubBody["deadLetterPolicy"]; has {
		t.Fatal("no deadLetter attribute must leave the subscription policy-free")
	}
}

func TestBuildPubSubQueueDeadLetterRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"missing topic":      {"max_delivery_attempts": 5},
		"missing attempts":   {"dead_letter_topic": "projects/acme-prod/topics/orders-dlq"},
		"bad topic name":     {"dead_letter_topic": "orders-dlq", "max_delivery_attempts": 5},
		"attempts too low":   {"dead_letter_topic": "projects/acme-prod/topics/orders-dlq", "max_delivery_attempts": 4},
		"attempts too high":  {"dead_letter_topic": "projects/acme-prod/topics/orders-dlq", "max_delivery_attempts": 101},
		"attempts non-whole": {"dead_letter_topic": "projects/acme-prod/topics/orders-dlq", "max_delivery_attempts": 5.5},
	}
	for name, impl := range cases {
		t.Run(name, func(t *testing.T) {
			a := queueAttrs()
			a["reliability.deadLetter"] = true
			if _, err := BuildPubSubQueuePlan("acme-prod", "prod", "orders", a, impl, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}

func TestBuildPubSubQueueRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate func(map[string]any)
		impl   map[string]any
	}{
		"atRest false":        {func(a map[string]any) { a["encryption.atRest"] = false }, nil},
		"cmek without key":    {func(a map[string]any) { a["encryption.customerManagedKeys"] = true }, nil},
		"retention too short": {func(a map[string]any) { a["retention.minimum"] = "1m" }, nil},
		"retention too long":  {func(a map[string]any) { a["retention.minimum"] = "40d" }, nil},
		"bad delivery":        {func(a map[string]any) { a["delivery.guarantee"] = "maybe" }, nil},
		"unmanaged":           {func(a map[string]any) { a["service.managed"] = false }, nil},
		"no region":           {func(a map[string]any) { delete(a, "location.region") }, nil},
		"unknown attr":        {func(a map[string]any) { a["visibility.timeout"] = "30s" }, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := queueAttrs()
			c.mutate(a)
			if _, err := BuildPubSubQueuePlan("acme-prod", "prod", "orders", a, c.impl, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}

// pubsubQueueServer is a stateful Pub/Sub v1 fake covering the composite: topic
// PUT + subscription PUT, GET on both, subscription IAM (allUsers subscriber
// after setIamPolicy), and DELETE. Labels use capLabel/env so ownership checks
// pass. Used by the happy-path/observe unit tests AND the honesty harness.
func pubsubQueueServer(t *testing.T, capLabel, env string) *httptest.Server {
	t.Helper()
	granted := false
	subDoc := func() string {
		b, _ := json.Marshal(map[string]any{
			"name":                      "projects/acme-prod/subscriptions/the-q",
			"topic":                     "projects/acme-prod/topics/the-q",
			"labels":                    map[string]any{"groundhold-capability": capLabel, "groundhold-environment": env},
			"enableExactlyOnceDelivery": true,
			"enableMessageOrdering":     true,
			"messageRetentionDuration":  "600s",
		})
		return string(b)
	}
	topicDocJSON := func() string {
		b, _ := json.Marshal(map[string]any{
			"name":                 "projects/acme-prod/topics/the-q",
			"labels":               map[string]any{"groundhold-capability": capLabel, "groundhold-environment": env},
			"messageStoragePolicy": map[string]any{"allowedPersistenceRegions": []string{"europe-west1"}},
		})
		return string(b)
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case strings.HasSuffix(p, ":getIamPolicy") && r.Method == "GET":
				if granted {
					_, _ = w.Write([]byte(`{"etag":"e1","version":3,"bindings":[` +
						`{"role":"roles/pubsub.subscriber","members":["allUsers"]}]}`))
				} else {
					_, _ = w.Write([]byte(`{"etag":"e1","version":3,"bindings":[]}`))
				}
			case strings.HasSuffix(p, ":setIamPolicy") && r.Method == "POST":
				granted = true
				_, _ = w.Write([]byte(`{"etag":"e2"}`))
			case r.Method == "PUT" && strings.Contains(p, "/subscriptions/"):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/subscriptions/the-q"}`))
			case r.Method == "PUT" && strings.Contains(p, "/topics/"):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/the-q"}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{}`))
			case r.Method == "GET" && strings.Contains(p, "/subscriptions/"):
				_, _ = w.Write([]byte(subDoc()))
			case r.Method == "GET" && strings.Contains(p, "/topics/"):
				_, _ = w.Write([]byte(topicDocJSON()))
			default:
				w.WriteHeader(500)
			}
		}))
}

func queueDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.PubSubBaseURL = srv.URL
	return d
}

func TestCreatePubSubQueuePublicGrantsSubscriber(t *testing.T) {
	srv := pubsubQueueServer(t, "orders", "prod")
	defer srv.Close()
	d := queueDriver(t, srv)
	a := queueAttrs()
	a["network.publicExposure"] = true
	res := d.createPubSubQueue("orders", "prod", a, nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "pubsub:acme-prod:") {
		t.Fatalf("got %+v, want succeeded + pubsub-prefixed id", res)
	}
}

func TestDeletePubSubQueueOurs(t *testing.T) {
	srv := pubsubQueueServer(t, "orders", "prod")
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.deletePubSubQueue("orders", "prod", "pubsub:acme-prod:the-q")
	if res.Status != "succeeded" {
		t.Fatalf("delete of an owned queue must succeed, got %+v", res)
	}
}

func TestDeletePubSubQueueForeignRefused(t *testing.T) {
	// foreign subscription labels: the reverse delete must refuse BEFORE mutating.
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && strings.Contains(r.URL.Path, "/subscriptions/") {
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/subscriptions/the-q",` +
					`"labels":{"groundhold-capability":"other"}}`))
				return
			}
			if r.Method == "DELETE" {
				t.Errorf("delete must not proceed past the ownership check")
			}
			w.WriteHeader(500)
		}))
	defer srv.Close()
	d := queueDriver(t, srv)
	res := d.deletePubSubQueue("orders", "prod", "pubsub:acme-prod:the-q")
	if res.Status != "failed" {
		t.Fatalf("delete of a foreign queue must be refused, got %+v", res)
	}
}

// THE residency honesty test on the composite: a queue whose BACKING topic has a
// storage policy observes its region; a queue on a GLOBAL backing topic does NOT
// observe a region — a diagnostic, never a default.
func TestObservePubSubQueueResidencyHonesty(t *testing.T) {
	t.Run("pinned", func(t *testing.T) {
		srv := pubsubQueueServer(t, "orders", "prod")
		defer srv.Close()
		d := queueDriver(t, srv)
		obs, diags, err := d.observePubSubQueue("orders", "pubsub:acme-prod:the-q")
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]any{}
		for _, o := range obs {
			got[o.Path] = o.Value
		}
		if got["location.region"] != "europe-west1" {
			t.Fatalf("a region-pinned backing topic must observe its region, got %v (diags %v)", got["location.region"], diags)
		}
		if got["delivery.guarantee"] != "exactly-once" || got["ordering.enabled"] != true {
			t.Fatalf("subscription semantics not observed: %v", got)
		}
	})
	t.Run("global", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[]}`))
				case strings.Contains(r.URL.Path, "/subscriptions/"):
					_, _ = w.Write([]byte(`{"name":"projects/acme-prod/subscriptions/the-q",` +
						`"labels":{"groundhold-capability":"orders","groundhold-environment":"prod"}}`))
				case strings.Contains(r.URL.Path, "/topics/"):
					// a GLOBAL backing topic — no messageStoragePolicy.
					_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/the-q","labels":{}}`))
				default:
					w.WriteHeader(500)
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
				t.Fatalf("a GLOBAL backing topic must NOT observe a region: %+v", o)
			}
		}
		found := false
		for _, dg := range diags {
			if strings.Contains(dg, "GLOBAL") {
				found = true
			}
		}
		if !found {
			t.Fatalf("a global backing topic must emit a residency diagnostic, got %v", diags)
		}
	})
}

// observe reverse-maps the subscription deadLetterPolicy to reliability.deadLetter.
// Present-with-target => true; absent => a measured false (never unknown), so a
// "deadLetter equals true" constraint reads violated, not unknown.
func TestObservePubSubQueueDeadLetter(t *testing.T) {
	serve := func(withDL bool) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[]}`))
				case strings.Contains(r.URL.Path, "/subscriptions/"):
					doc := `{"name":"projects/acme-prod/subscriptions/the-q",` +
						`"labels":{"groundhold-capability":"orders","groundhold-environment":"prod"}`
					if withDL {
						doc += `,"deadLetterPolicy":{"deadLetterTopic":"projects/acme-prod/topics/orders-dlq","maxDeliveryAttempts":5}`
					}
					doc += `}`
					_, _ = w.Write([]byte(doc))
				case strings.Contains(r.URL.Path, "/topics/"):
					_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/the-q",` +
						`"messageStoragePolicy":{"allowedPersistenceRegions":["europe-west1"]}}`))
				default:
					w.WriteHeader(500)
				}
			}))
	}
	for _, tc := range []struct {
		name   string
		withDL bool
		want   bool
	}{{"with-dlq", true, true}, {"no-dlq", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			srv := serve(tc.withDL)
			defer srv.Close()
			d := queueDriver(t, srv)
			obs, _, err := d.observePubSubQueue("orders", "pubsub:acme-prod:the-q")
			if err != nil {
				t.Fatal(err)
			}
			var got any
			seen := false
			for _, o := range obs {
				if o.Path == "reliability.deadLetter" {
					got, seen = o.Value, true
				}
			}
			if !seen {
				t.Fatal("reliability.deadLetter must always be observed (measured)")
			}
			if got != tc.want {
				t.Fatalf("reliability.deadLetter: got %v, want %v", got, tc.want)
			}
		})
	}
}

// Weapon 2 (D87): the metamorphic write/read round-trip across the composite. A
// stateful fake records what the topic PUT and subscription PUT WRITE and
// reflects them on GET; observePubSubQueue must reverse-map the SAME semantics.
func metamorphicQueueServer(t *testing.T) *httptest.Server {
	t.Helper()
	var kms string
	var regions []string
	var sub map[string]any
	granted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case strings.HasSuffix(p, ":getIamPolicy") && r.Method == "GET":
				if granted {
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[` +
						`{"role":"roles/pubsub.subscriber","members":["allUsers"]}]}`))
				} else {
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[]}`))
				}
			case strings.HasSuffix(p, ":setIamPolicy") && r.Method == "POST":
				granted = true
				_, _ = w.Write([]byte(`{"etag":"e2"}`))
			case r.Method == "PUT" && strings.Contains(p, "/topics/"):
				raw, _ := io.ReadAll(r.Body)
				var b topicDoc
				_ = json.Unmarshal(raw, &b)
				kms = b.KmsKeyName
				regions = b.MessageStoragePolicy.AllowedPersistenceRegions
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/the-q"}`))
			case r.Method == "PUT" && strings.Contains(p, "/subscriptions/"):
				raw, _ := io.ReadAll(r.Body)
				sub = map[string]any{}
				_ = json.Unmarshal(raw, &sub)
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/subscriptions/the-q"}`))
			case r.Method == "GET" && strings.Contains(p, "/subscriptions/"):
				doc := map[string]any{
					"name":                      "projects/acme-prod/subscriptions/the-q",
					"labels":                    map[string]any{"groundhold-capability": "orders", "groundhold-environment": "prod"},
					"enableExactlyOnceDelivery": sub["enableExactlyOnceDelivery"] == true,
					"enableMessageOrdering":     sub["enableMessageOrdering"] == true,
				}
				if r, ok := sub["messageRetentionDuration"].(string); ok {
					doc["messageRetentionDuration"] = r
				}
				_ = json.NewEncoder(w).Encode(doc)
			case r.Method == "GET" && strings.Contains(p, "/topics/"):
				doc := map[string]any{
					"name":                 "projects/acme-prod/topics/the-q",
					"labels":               map[string]any{"groundhold-capability": "orders", "groundhold-environment": "prod"},
					"kmsKeyName":           kms,
					"messageStoragePolicy": map[string]any{"allowedPersistenceRegions": regions},
				}
				_ = json.NewEncoder(w).Encode(doc)
			default:
				w.WriteHeader(500)
			}
		}))
}

func TestMetamorphicPubSubQueueRoundTrip(t *testing.T) {
	cases := []struct {
		name        string
		public      bool
		cmek        bool
		exactlyOnce bool
		ordering    bool
	}{
		{"private-baseline", false, false, false, false},
		{"public-cmek-exactly-ordered", true, true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicQueueServer(t)
			defer srv.Close()
			d := queueDriver(t, srv)
			attrs := map[string]any{
				"location.region":        "europe-west1",
				"network.publicExposure": c.public,
				"encryption.atRest":      true,
				"service.managed":        true,
				"retention.minimum":      "1h",
			}
			if c.exactlyOnce {
				attrs["delivery.guarantee"] = "exactly-once"
			}
			if c.ordering {
				attrs["ordering.enabled"] = true
			}
			var impl map[string]any
			if c.cmek {
				attrs["encryption.customerManagedKeys"] = true
				impl = map[string]any{"kms_key_name": "projects/p/locations/eu/keyRings/r/cryptoKeys/k"}
			}
			res := d.createPubSubQueue("orders", "prod", attrs, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create failed: %+v", res)
			}
			obs, _, err := d.observePubSubQueue("orders", res.ProviderID)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["location.region"] != "europe-west1" {
				t.Errorf("residency round-trip broke: %v", got["location.region"])
			}
			if got["network.publicExposure"] != c.public {
				t.Errorf("public round-trip broke: wrote %v observed %v", c.public, got["network.publicExposure"])
			}
			wantGuarantee := "at-least-once"
			if c.exactlyOnce {
				wantGuarantee = "exactly-once"
			}
			if got["delivery.guarantee"] != wantGuarantee {
				t.Errorf("guarantee round-trip broke: want %v observed %v", wantGuarantee, got["delivery.guarantee"])
			}
			if got["ordering.enabled"] != c.ordering {
				t.Errorf("ordering round-trip broke: want %v observed %v", c.ordering, got["ordering.enabled"])
			}
			if got["retention.minimum"] != "3600s" {
				t.Errorf("retention round-trip broke: observed %v", got["retention.minimum"])
			}
			_, hasCMEK := got["encryption.customerManagedKeys"]
			if hasCMEK != c.cmek {
				t.Errorf("cmek presence round-trip broke: want %v observed %v", c.cmek, hasCMEK)
			}
		})
	}
}
