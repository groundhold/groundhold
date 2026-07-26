package k8s

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func loadQuotaSchemas(t *testing.T) map[string]any {
	t.Helper()
	fd, err := os.ReadFile("testdata/resourcequota-openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(fd, &doc); err != nil {
		t.Fatal(err)
	}
	return doc["components"].(map[string]any)["schemas"].(map[string]any)
}

// The committed mapping's pinned mappedSurface must equal the hash of the vendored
// schema it was authored against — pins that the pin is honest.
func TestQuotaMappingPinMatchesVendoredSchema(t *testing.T) {
	m := loadRealMapping(t, "k8s.resourcequota.yaml")
	got, err := m.MappedSurfaceHash(loadQuotaSchemas(t))
	if err != nil {
		t.Fatal(err)
	}
	if got != m.Schema.MappedSurface {
		t.Fatalf("committed pin %s != vendored-schema hash %s", m.Schema.MappedSurface, got)
	}
	// matching schema -> no drift, no diagnostics
	diags, err := m.checkDrift(loadQuotaSchemas(t))
	if err != nil || len(diags) != 0 {
		t.Fatalf("matching schema must not drift, got diags=%v err=%v", diags, err)
	}
}

func TestDriftInsideMappedSurfaceRefuses(t *testing.T) {
	m := loadRealMapping(t, "k8s.resourcequota.yaml")
	schemas := loadQuotaSchemas(t)
	// mutate a MAPPED field's type: Quantity string -> integer
	schemas["io.k8s.apimachinery.pkg.api.resource.Quantity"].(map[string]any)["type"] = "integer"
	_, err := m.checkDrift(schemas)
	if err == nil || !strings.Contains(err.Error(), "mapping-schema-drift") {
		t.Fatalf("a mapped-field type change must refuse with mapping-schema-drift, got %v", err)
	}
}

func TestDriftMappedFieldVanishedRefuses(t *testing.T) {
	m := loadRealMapping(t, "k8s.resourcequota.yaml")
	schemas := loadQuotaSchemas(t)
	// remove the whole hard map -> every mapped path vanishes
	spec := schemas["io.k8s.api.core.v1.ResourceQuotaSpec"].(map[string]any)
	delete(spec["properties"].(map[string]any), "hard")
	_, err := m.checkDrift(schemas)
	if err == nil || !strings.Contains(err.Error(), "mapping-schema-drift") {
		t.Fatalf("a vanished mapped field must refuse, got %v", err)
	}
}

func TestDriftOutsideMappedSurfaceTolerated(t *testing.T) {
	m := loadRealMapping(t, "k8s.resourcequota.yaml")
	schemas := loadQuotaSchemas(t)
	// add an UNMAPPED field to the spec — outside the mapped surface
	spec := schemas["io.k8s.api.core.v1.ResourceQuotaSpec"].(map[string]any)
	spec["properties"].(map[string]any)["scopeSelector"] = map[string]any{"type": "object"}
	diags, err := m.checkDrift(schemas)
	if err != nil {
		t.Fatalf("drift OUTSIDE the mapped surface must be tolerated, got %v", err)
	}
	_ = diags
}

func TestGuardDriftEndToEnd(t *testing.T) {
	body := map[string]any{
		"metadata": map[string]any{"name": "budget", "namespace": "team"},
		"spec":     map[string]any{"hard": map[string]any{"limits.cpu": "10"}},
	}
	lbls := map[string]string{}
	srv := coreServer(t, corePathNS("resourcequotas", "team", "budget"), body, &lbls)
	defer srv.Close()
	m := loadRealMapping(t, "k8s.resourcequota.yaml")
	pid := quotaProviderID("team", "budget")

	// matching schema: observe proceeds
	good := loadQuotaSchemas(t)
	d := NewDriver(srv.URL, "tok")
	d.SchemaFetch = func(g, v string) (map[string]any, error) { return good, nil }
	if _, _, err := d.observeMapped(m, pid); err != nil {
		t.Fatalf("matching schema: observe must proceed, got %v", err)
	}

	// drifted schema: observe REFUSES before returning facts
	bad := loadQuotaSchemas(t)
	bad["io.k8s.apimachinery.pkg.api.resource.Quantity"].(map[string]any)["type"] = "integer"
	d2 := NewDriver(srv.URL, "tok")
	d2.SchemaFetch = func(g, v string) (map[string]any, error) { return bad, nil }
	if _, _, err := d2.observeMapped(m, pid); err == nil || !strings.Contains(err.Error(), "mapping-schema-drift") {
		t.Fatalf("drift must refuse the observe, got %v", err)
	}

	// unreachable schema: skip-loudly (a diagnostic), observe still proceeds
	d3 := NewDriver(srv.URL, "tok")
	d3.SchemaFetch = func(g, v string) (map[string]any, error) { return nil, os.ErrDeadlineExceeded }
	_, diags, err := d3.observeMapped(m, pid)
	if err != nil {
		t.Fatalf("unreachable schema must skip-loudly, not fail, got %v", err)
	}
	if len(diags) == 0 || !strings.Contains(diags[0], "UNCHECKED") {
		t.Fatalf("unreachable schema must surface an UNCHECKED diagnostic, got %v", diags)
	}
}
