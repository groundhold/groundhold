package azure

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// armTagServer serves a GET returning the given tags (nil status 404 = absent).
func armTagServer(t *testing.T, status int, tags map[string]string) *Driver {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status == http.StatusNotFound {
			w.WriteHeader(404)
			return
		}
		b, _ := json.Marshal(map[string]any{"tags": tags,
			"properties": map[string]any{"provisioningState": "Succeeded"}})
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	return d
}

// TestRefuseForeignUpsert pins D254: a tag-owned PUT over a FOREIGN resource is
// refused; over OURS or an ABSENT one it proceeds; a tagless body always proceeds.
func TestRefuseForeignUpsert(t *testing.T) {
	ourBody, _ := json.Marshal(map[string]any{"location": "eastus",
		"tags": map[string]string{"groundhold-capability": "db", "groundhold-environment": "prod"}})

	// foreign existing resource -> REFUSE
	d := armTagServer(t, 200, map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"})
	if r := d.refuseForeignUpsert(d.BaseURL+"/x", ourBody); r == nil || r.Status != "failed" {
		t.Fatalf("a foreign existing resource must be refused, got %+v", r)
	}
	// untagged existing resource (no groundhold-capability) is NOT ours -> REFUSE
	d = armTagServer(t, 200, map[string]string{"team": "x"})
	if r := d.refuseForeignUpsert(d.BaseURL+"/x", ourBody); r == nil {
		t.Fatal("an existing untagged resource is not ours — must be refused")
	}
	// OURS existing resource -> proceed (nil)
	d = armTagServer(t, 200, map[string]string{"groundhold-capability": "db", "groundhold-environment": "prod"})
	if r := d.refuseForeignUpsert(d.BaseURL+"/x", ourBody); r != nil {
		t.Fatalf("our own resource must proceed (idempotent), got %+v", r)
	}
	// ABSENT (404) -> proceed
	d = armTagServer(t, 404, nil)
	if r := d.refuseForeignUpsert(d.BaseURL+"/x", ourBody); r != nil {
		t.Fatalf("an absent resource must proceed (genuine create), got %+v", r)
	}
	// TAGLESS body (content-addressed / child) -> proceed regardless of existing
	d = armTagServer(t, 200, map[string]string{"groundhold-capability": "someone-else"})
	tagless, _ := json.Marshal(map[string]any{"properties": map[string]any{"x": 1}})
	if r := d.refuseForeignUpsert(d.BaseURL+"/x", tagless); r != nil {
		t.Fatalf("a tagless body carries no ownership claim — must proceed, got %+v", r)
	}
}
