package k8s

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// loadFixtureSchemas reads a vendored OpenAPI fixture and returns components.schemas.
func loadFixtureSchemas(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Components.Schemas
}

func TestFieldInventoryListsLeaves(t *testing.T) {
	schemas := loadFixtureSchemas(t, "resourcequota-openapi.json")
	gvk, ok := findGVKSchema(schemas, "", "v1", "ResourceQuota")
	if !ok {
		t.Fatal("fixture must carry the ResourceQuota GVK")
	}
	inv := fieldInventory(gvk, schemas)
	if len(inv) == 0 {
		t.Fatal("inventory must not be empty")
	}
	// the mapped surface (spec.hard) must appear in the raw menu, as a map leaf.
	var sawHard bool
	for _, f := range inv {
		if strings.HasPrefix(f, `spec.hard["*"]`) {
			sawHard = true
		}
	}
	if !sawHard {
		t.Fatalf("spec.hard[*] must be in the inventory, got %v", inv)
	}
}

func TestSkeletonIsMachineHalfOnly(t *testing.T) {
	// discovery for the core group + the schema fetcher, both served from a fake.
	schemaRaw, _ := os.ReadFile("testdata/resourcequota-openapi.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1" && r.Method == "GET" && r.URL.RawQuery == "":
			// APIResourceList
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resources": []map[string]any{
					{"name": "resourcequotas", "kind": "ResourceQuota", "namespaced": true},
					{"name": "resourcequotas/status", "kind": "ResourceQuota", "namespaced": true},
				},
			})
		case r.URL.Path == "/openapi/v3":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"paths": map[string]any{"api/v1": map[string]any{"serverRelativeURL": "/openapi/v3/api/v1"}},
			})
		case r.URL.Path == "/openapi/v3/api/v1":
			_, _ = w.Write(schemaRaw)
		default:
			http.Error(w, "nf", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	d := NewDriver(srv.URL, "tok")
	d.SchemaFetch = d.fetchOpenAPISchema
	out, err := d.SkeletonFor("", "v1", "ResourceQuota", "k8s.resourcequota", "capability.compute.quota")
	if err != nil {
		t.Fatal(err)
	}

	// machine-authoritative profile is filled from discovery, not guessed.
	for _, want := range []string{"plural: resourcequotas", "scope: Namespaced", "kind: ResourceQuota"} {
		if !strings.Contains(out, want) {
			t.Fatalf("skeleton missing %q\n%s", want, out)
		}
	}
	// the subresource must not become the plural.
	if strings.Contains(out, "resourcequotas/status") {
		t.Fatal("subresource leaked into the profile")
	}
	// attributes stay EMPTY — the generator authors no semantics.
	if !strings.Contains(out, "attributes: {}") {
		t.Fatalf("generator must not author attributes\n%s", out)
	}
	// the field inventory is present as comments (menu, not mapping).
	if !strings.Contains(out, "field inventory") || !strings.Contains(out, `#   spec.hard`) {
		t.Fatalf("skeleton missing the commented inventory\n%s", out)
	}
	// mappedSurface deferred to the human (drift off until authored).
	if !strings.Contains(out, `mappedSurface: ""`) {
		t.Fatalf("mappedSurface must be left blank for post-authoring\n%s", out)
	}
}
