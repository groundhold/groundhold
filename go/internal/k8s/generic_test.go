package k8s

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// loadRealMapping loads the committed mapping doc from spec/mappings so the test
// pins the REAL artifact, not an inline copy.
func loadRealMapping(t *testing.T, name string) *Mapping {
	t.Helper()
	data, err := os.ReadFile("mappings/" + name)
	if err != nil {
		t.Fatalf("read mapping %s: %v", name, err)
	}
	m, err := loadMapping(data)
	if err != nil {
		t.Fatalf("load mapping %s: %v", name, err)
	}
	return m
}

// quota is fully migrated: its hand-coded twin is deleted, the generic engine is
// the sole path. The pin (once a differential vs the twin) is now a direct
// assertion of the engine's output against a captured object.
func TestGenericObserveQuota(t *testing.T) {
	body := map[string]any{
		"metadata": map[string]any{"name": "budget", "namespace": "team"},
		"spec":     map[string]any{"hard": map[string]any{"limits.cpu": "10", "limits.memory": "20Gi", "pods": "50"}},
	}
	lbls := map[string]string{}
	srv := coreServer(t, corePathNS("resourcequotas", "team", "budget"), body, &lbls)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	m := loadRealMapping(t, "k8s.resourcequota.yaml")
	obs, diags, err := d.observeMapped(m, quotaProviderID("team", "budget"))
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	want := map[string]any{"cpu.limit": "10", "memory.limit": "20Gi", "pods.max": 50, "service.managed": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("observe quota = %#v, want %#v", got, want)
	}
}

// A partial object: the engine emits no value it cannot resolve, and a
// non-integer quantity is a diagnostic, never a fabricated number.
func TestGenericObserveQuotaPartial(t *testing.T) {
	body := map[string]any{
		"metadata": map[string]any{"name": "budget", "namespace": "team"},
		"spec":     map[string]any{"hard": map[string]any{"limits.cpu": "10", "pods": "lots"}},
	}
	lbls := map[string]string{}
	srv := coreServer(t, corePathNS("resourcequotas", "team", "budget"), body, &lbls)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	m := loadRealMapping(t, "k8s.resourcequota.yaml")
	obs, diags, _ := d.observeMapped(m, quotaProviderID("team", "budget"))
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	// no memory (absent), pods not represented (non-integer) — only cpu + service.managed
	want := map[string]any{"cpu.limit": "10", "service.managed": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("partial observe = %#v, want %#v", got, want)
	}
	if len(diags) != 1 || !strings.Contains(diags[0], "integer") {
		t.Fatalf("non-integer pods must be one diagnostic, got %v", diags)
	}
}

func TestLoadMappingRefusals(t *testing.T) {
	bad := []struct{ name, yaml, want string }{
		{"algebra", "mapping: v9\nfieldpath: groundhold/fieldpath/v1\nresource: {version: v1, kind: X, plural: xs, scope: Cluster}\n", "algebra"},
		{"op-not-closed", "mapping: v0.1\nfieldpath: groundhold/fieldpath/v1\nresource: {version: v1, kind: X, plural: xs, scope: Cluster}\nattributes:\n  a: {field: spec.a, op: regex, derivation: measured}\n", "closed set"},
		{"scope", "mapping: v0.1\nfieldpath: groundhold/fieldpath/v1\nresource: {version: v1, kind: X, plural: xs, scope: Galaxy}\n", "scope"},
	}
	for _, c := range bad {
		if _, err := loadMapping([]byte(c.yaml)); err == nil {
			t.Fatalf("%s: expected refusal", c.name)
		}
	}
}

// TestParseFieldPath moved to internal/mapping (the fieldpath grammar is now the
// universal layer's; see internal/mapping/fieldpath_test.go).
