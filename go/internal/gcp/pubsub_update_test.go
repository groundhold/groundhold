package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ourTopicJSON(capLabel string) string {
	return `{"name":"projects/acme-prod/topics/pv-events-abcd1234",` +
		`"labels":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"}}`
}

func TestUpdatePubSubGrantExposure(t *testing.T) {
	srv := pubsubServer(t, ourTopicJSON("events"), 0, 0)
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.Update("pubsub-topic", "events", "prod", "pubsub:acme-prod:pv-events-abcd1234",
		map[string]any{"network.publicExposure": true}, nil, []string{"network.publicExposure"}, "k")
	if res.Status != "succeeded" {
		t.Fatalf("grant update: %+v", res)
	}
}

// startPublicServer starts with the allUsers publisher binding present, so a revoke
// (setIamPolicy without allUsers) makes it private; getIamPolicy reflects the flip.
func startPublicServer(t *testing.T, capLabel string) *httptest.Server {
	t.Helper()
	public := true
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case strings.HasSuffix(p, ":getIamPolicy"):
				if public {
					_, _ = w.Write([]byte(`{"etag":"e1","version":3,"bindings":[{"role":"roles/pubsub.publisher","members":["allUsers"]}]}`))
				} else {
					_, _ = w.Write([]byte(`{"etag":"e1","version":3,"bindings":[]}`))
				}
			case strings.HasSuffix(p, ":setIamPolicy"):
				public = false // the revoke landed
				_, _ = w.Write([]byte(`{"etag":"e2"}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(ourTopicJSON(capLabel)))
			default:
				w.WriteHeader(500)
			}
		}))
}

func TestUpdatePubSubRevokeExposure(t *testing.T) {
	srv := startPublicServer(t, "events")
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.Update("pubsub-topic", "events", "prod", "pubsub:acme-prod:pv-events-abcd1234",
		map[string]any{"network.publicExposure": false}, nil, []string{"network.publicExposure"}, "k")
	if res.Status != "succeeded" {
		t.Fatalf("revoke update: %+v", res)
	}
}

func TestUpdatePubSubForeignRefused(t *testing.T) {
	srv := pubsubServer(t, ourTopicJSON("someone-else"), 0, 0)
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.Update("pubsub-topic", "events", "prod", "pubsub:acme-prod:pv-events-abcd1234",
		map[string]any{"network.publicExposure": true}, nil, []string{"network.publicExposure"}, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign topic must refuse patch, got %+v", res)
	}
}

func TestClassifyPubSubChange(t *testing.T) {
	d := NewDriver("acme-prod")
	if cls, _ := d.ClassifyChange("pubsub-topic", "network.publicExposure", false, true, nil); cls != "mutable" {
		t.Fatalf("publicExposure must be mutable, got %q", cls)
	}
	if cls, _ := d.ClassifyChange("pubsub-topic", "encryption.customerManagedKeys", nil, true, nil); cls != "unsupported" {
		t.Fatalf("cmk must be unsupported (not wired this slice), got %q", cls)
	}
}

func TestRemoveMember(t *testing.T) {
	bindings := []map[string]any{
		{"role": "roles/pubsub.publisher", "members": []any{"allUsers", "user:a@x.com"}},
		{"role": "roles/pubsub.viewer", "members": []any{"user:b@x.com"}},
	}
	out := removeMember(bindings, "roles/pubsub.publisher", "allUsers")
	for _, b := range out {
		if b["role"] == "roles/pubsub.publisher" && hasMember(b, "allUsers") {
			t.Fatal("allUsers should have been removed")
		}
	}
	// an emptied binding is dropped
	only := removeMember([]map[string]any{{"role": "r", "members": []any{"allUsers"}}}, "r", "allUsers")
	if len(only) != 0 {
		t.Fatalf("emptied binding must be dropped, got %+v", only)
	}
}
