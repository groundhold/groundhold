package k8s

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// openapiServer serves the /openapi/v3 discovery doc, the core group's schema, and
// one ResourceQuota object — enough to exercise the live drift fetch end to end.
func openapiServer(t *testing.T, schema []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/openapi/v3":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"paths": map[string]any{"api/v1": map[string]any{"serverRelativeURL": "/openapi/v3/api/v1"}},
			})
		case r.URL.Path == "/openapi/v3/api/v1":
			_, _ = w.Write(schema)
		case strings.HasSuffix(r.URL.Path, "/namespaces/team/resourcequotas/budget"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]any{"name": "budget", "namespace": "team"},
				"spec":     map[string]any{"hard": map[string]any{"limits.cpu": "10"}},
			})
		default:
			http.Error(w, "nf", http.StatusNotFound)
		}
	}))
}

func TestLiveSchemaFetchMatchingProceeds(t *testing.T) {
	schema, err := os.ReadFile("testdata/resourcequota-openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := openapiServer(t, schema)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	d.SchemaFetch = d.fetchOpenAPISchema // as the kubeconfig driver wires it
	m := loadRealMapping(t, "k8s.resourcequota.yaml")

	obs, diags, err := d.observeMapped(m, quotaProviderID("team", "budget"))
	if err != nil {
		t.Fatalf("matching live schema must not drift: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("no diagnostics expected (schema fetched + matched), got %v", diags)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["cpu.limit"] != "10" || got["service.managed"] != true {
		t.Fatalf("observe = %v", got)
	}
}

func TestLiveSchemaFetchDriftRefuses(t *testing.T) {
	schema, _ := os.ReadFile("testdata/resourcequota-openapi.json")
	var doc map[string]any
	_ = json.Unmarshal(schema, &doc)
	// mutate a mapped field's type in the LIVE schema (Quantity string -> integer)
	doc["components"].(map[string]any)["schemas"].(map[string]any)["io.k8s.apimachinery.pkg.api.resource.Quantity"].(map[string]any)["type"] = "integer"
	mutated, _ := json.Marshal(doc)

	srv := openapiServer(t, mutated)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	d.SchemaFetch = d.fetchOpenAPISchema
	m := loadRealMapping(t, "k8s.resourcequota.yaml")

	_, _, err := d.observeMapped(m, quotaProviderID("team", "budget"))
	if err == nil || !strings.Contains(err.Error(), "mapping-schema-drift") {
		t.Fatalf("a drifted live schema must refuse the observe, got %v", err)
	}
}

func TestLiveSchemaFetchUnreachableSkipsLoudly(t *testing.T) {
	// a server that 404s /openapi/v3 but serves the object
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/namespaces/team/resourcequotas/budget") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]any{"name": "budget", "namespace": "team"},
				"spec":     map[string]any{"hard": map[string]any{"limits.cpu": "10"}},
			})
			return
		}
		http.Error(w, "nf", http.StatusNotFound)
	}))
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	d.SchemaFetch = d.fetchOpenAPISchema
	m := loadRealMapping(t, "k8s.resourcequota.yaml")

	_, diags, err := d.observeMapped(m, quotaProviderID("team", "budget"))
	if err != nil {
		t.Fatalf("an unreachable schema must skip loudly, not fail: %v", err)
	}
	if len(diags) == 0 || !strings.Contains(diags[0], "UNCHECKED") {
		t.Fatalf("must surface an UNCHECKED diagnostic, got %v", diags)
	}
}
