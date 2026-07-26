package gcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestClaimCloudSQLMergesLabels: claiming a TF-created instance ADDS groundhold's
// ownership labels via a read-modify-write patch that PRESERVES the operator's
// existing labels (no clobber) and carries settingsVersion for concurrency.
func TestClaimCloudSQLMergesLabels(t *testing.T) {
	var patchBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
			fmt.Fprint(w, `{"status":"DONE"}`)
		case r.Method == "GET":
			// a TF-created instance: an operator label, NO groundhold labels.
			fmt.Fprint(w, `{"settings":{"settingsVersion":"7","userLabels":{"team":"ops"}}}`)
		case r.Method == "PATCH":
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &patchBody)
			fmt.Fprint(w, `{"name":"op1"}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := testDriver(t, srv)

	cr := d.Claim("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x")
	if cr.Status != "succeeded" {
		t.Fatalf("claim must succeed, got %+v", cr)
	}
	if cr.ProviderID != "acme-prod:europe-west1:orders-db-x" {
		t.Fatalf("claim must carry the providerId, got %q", cr.ProviderID)
	}
	settings, _ := patchBody["settings"].(map[string]any)
	labels, _ := settings["userLabels"].(map[string]any)
	if labels["groundhold-capability"] != "orders-db" || labels["groundhold-environment"] != "production" {
		t.Fatalf("claim must stamp groundhold's ownership labels: %v", labels)
	}
	if labels["team"] != "ops" {
		t.Fatalf("claim must PRESERVE the operator's labels (additive, no clobber): %v", labels)
	}
	if settings["settingsVersion"] != "7" {
		t.Fatalf("claim must carry settingsVersion (optimistic concurrency): %v", settings)
	}
}

// TestClaimVanishedInstanceFails: a claim on an instance that is gone fails
// cleanly (never a fabricated success).
func TestClaimVanishedInstanceFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	cr := d.Claim("cloudsql", "orders-db", "production", "acme-prod:europe-west1:gone")
	if cr.Status != "failed" {
		t.Fatalf("a vanished instance must fail the claim, got %+v", cr)
	}
}

// TestClaimUnwiredServiceRefusesHonestly: a service groundhold cannot yet claim
// refuses (failed) so the converge stops and the resource stays externally owned
// — a failed claim is safer than a silent one (no orphan).
func TestClaimUnwiredServiceRefusesHonestly(t *testing.T) {
	d := NewDriver("acme-prod")
	cr := d.Claim("dashboard", "cpu", "production", "gdash:acme-prod:xyz")
	if cr.Status != "failed" {
		t.Fatalf("an unclaimable service must refuse (failed), got %+v", cr)
	}
	if !strings.Contains(cr.Reason, "externally owned") {
		t.Fatalf("the refusal must say it stays externally owned: %q", cr.Reason)
	}
}

// TestClaimSecretManagerMergesLabels: an immediate label patch (secrets.patch
// ?updateMask=labels) ADDS groundhold's ownership labels via read-modify-write and
// PRESERVES the operator's existing labels (no clobber). Bearer asserted.
func TestClaimSecretManagerMergesLabels(t *testing.T) {
	var patchBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("missing/wrong bearer: %q", got)
		}
		switch r.Method {
		case "GET":
			fmt.Fprint(w, `{"labels":{"team":"ops"}}`)
		case "PATCH":
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &patchBody)
			fmt.Fprint(w, `{"name":"projects/acme-prod/secrets/s"}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.SecretBaseURL = srv.URL

	cr := d.Claim("secretmanager", "orders-secret", "production", "gsecret:acme-prod:orders-secret-x")
	if cr.Status != "succeeded" || cr.ProviderID != "gsecret:acme-prod:orders-secret-x" {
		t.Fatalf("claim must succeed with providerId, got %+v", cr)
	}
	labels, _ := patchBody["labels"].(map[string]any)
	if labels["groundhold-capability"] != "orders-secret" || labels["groundhold-environment"] != "production" {
		t.Fatalf("claim must stamp groundhold labels: %v", labels)
	}
	if labels["team"] != "ops" {
		t.Fatalf("claim must PRESERVE the operator's labels (additive, no clobber): %v", labels)
	}
}

// TestClaimPubSubTopicMergesLabels: Pub/Sub uses a WRAPPED patch body
// ({topic:{name,labels}, updateMask:"labels"}); the union still preserves the
// operator's labels.
func TestClaimPubSubTopicMergesLabels(t *testing.T) {
	var patchBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("missing/wrong bearer: %q", got)
		}
		switch r.Method {
		case "GET":
			fmt.Fprint(w, `{"labels":{"team":"ops"}}`)
		case "PATCH":
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &patchBody)
			fmt.Fprint(w, `{"name":"projects/acme-prod/topics/orders-topic-x"}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.PubSubBaseURL = srv.URL

	cr := d.Claim("pubsub-topic", "orders-topic", "production", "pubsub:acme-prod:orders-topic-x")
	if cr.Status != "succeeded" || cr.ProviderID != "pubsub:acme-prod:orders-topic-x" {
		t.Fatalf("claim must succeed with providerId, got %+v", cr)
	}
	if patchBody["updateMask"] != "labels" {
		t.Fatalf("pubsub patch must carry updateMask=labels: %v", patchBody)
	}
	topic, _ := patchBody["topic"].(map[string]any)
	labels, _ := topic["labels"].(map[string]any)
	if labels["groundhold-capability"] != "orders-topic" || labels["groundhold-environment"] != "production" {
		t.Fatalf("claim must stamp groundhold labels inside the wrapped topic: %v", labels)
	}
	if labels["team"] != "ops" {
		t.Fatalf("claim must PRESERVE the operator's labels: %v", labels)
	}
}

// TestClaimMemorystoreMergesLabelsLRO: an LRO label patch polls the returned
// operation to DONE (like Cloud SQL) before reporting succeeded, and the patched
// union preserves the operator's labels.
func TestClaimMemorystoreMergesLabelsLRO(t *testing.T) {
	var patchBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("missing/wrong bearer: %q", got)
		}
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
			fmt.Fprint(w, `{"done":true}`)
		case r.Method == "GET":
			fmt.Fprint(w, `{"labels":{"team":"ops"}}`)
		case r.Method == "PATCH":
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &patchBody)
			fmt.Fprint(w, `{"name":"projects/acme-prod/locations/us-central1/operations/op1"}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.MemorystoreBaseURL = srv.URL

	cr := d.Claim("memorystore", "orders-cache", "production", "gredis:acme-prod:us-central1:orders-cache-x")
	if cr.Status != "succeeded" || cr.ProviderID != "gredis:acme-prod:us-central1:orders-cache-x" {
		t.Fatalf("LRO claim must succeed with providerId after DONE, got %+v", cr)
	}
	labels, _ := patchBody["labels"].(map[string]any)
	if labels["groundhold-capability"] != "orders-cache" || labels["groundhold-environment"] != "production" {
		t.Fatalf("claim must stamp groundhold labels: %v", labels)
	}
	if labels["team"] != "ops" {
		t.Fatalf("claim must PRESERVE the operator's labels: %v", labels)
	}
}

// TestClaimAlertPolicyMergesUserLabels: the monitoring family marks ownership
// with userLabels (not labels); the merge preserves the operator's userLabels.
func TestClaimAlertPolicyMergesUserLabels(t *testing.T) {
	var patchBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("missing/wrong bearer: %q", got)
		}
		switch r.Method {
		case "GET":
			fmt.Fprint(w, `{"userLabels":{"team":"ops"}}`)
		case "PATCH":
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &patchBody)
			fmt.Fprint(w, `{"name":"projects/acme-prod/alertPolicies/123"}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.MonitoringBaseURL = srv.URL

	cr := d.Claim("monitoring", "cpu-alert", "production", "galert:acme-prod:123")
	if cr.Status != "succeeded" || cr.ProviderID != "galert:acme-prod:123" {
		t.Fatalf("claim must succeed with providerId, got %+v", cr)
	}
	labels, _ := patchBody["userLabels"].(map[string]any)
	if labels["groundhold-capability"] != "cpu-alert" || labels["groundhold-environment"] != "production" {
		t.Fatalf("claim must stamp groundhold userLabels: %v", labels)
	}
	if labels["team"] != "ops" {
		t.Fatalf("claim must PRESERVE the operator's userLabels: %v", labels)
	}
}

// TestClaimVanishedLabelServiceFails: a 404 on the pre-claim read of a
// newly-wired label service is a clean failure (never a fabricated success).
func TestClaimVanishedLabelServiceFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.SecretBaseURL = srv.URL
	cr := d.Claim("secretmanager", "orders-secret", "production", "gsecret:acme-prod:gone")
	if cr.Status != "failed" {
		t.Fatalf("a vanished secret must fail the claim, got %+v", cr)
	}
}

// TestClaimUnknownServiceFailsClosed: dispatch is fail-closed (D76).
func TestClaimUnknownServiceFailsClosed(t *testing.T) {
	d := NewDriver("acme-prod")
	cr := d.Claim("__not_a_service__", "x", "y", "a:b:c")
	if cr.Status != "failed" {
		t.Fatalf("an unknown service must fail closed, got %+v", cr)
	}
}
