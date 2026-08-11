package k8s

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestMappedSurfacesMatchThePublishedSchemas asks the D509 question offline (D858).
//
// D509: every hermetic drift test in this package computed a mapping's surface against a
// HAND-RECORDED fixture, and the fixtures spelled a reference in a shape a real API server
// cannot emit. The fixtures agreed with the walker and the walker was blind by construction,
// so six of seven mapped services drifted against the first real cluster they ever met — the
// driver could not create anything.
//
// The guard written afterwards, TestLiveMappedSurfacesMatchTheirPins, asks a real cluster.
// It is right, and it SKIPS without one, which is every run here and in CI. So the class
// that took the driver down was guarded by a test that never executes.
//
// Kubernetes publishes the same OpenAPI v3 documents a cluster serves at `/openapi/v3`.
// This recomputes each BUILT-IN mapping's surface hash against them and compares it with the
// pin — no cluster, no credentials, every `make check`. The CRD mappings (Argo, cert-manager,
// Flux) are not published by Kubernetes and stay the live test's job; they are counted here
// rather than passed over, so the share this gate cannot see stays visible.
func TestMappedSurfacesMatchThePublishedSchemas(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "published_v3_schemas.json"))
	if err != nil {
		t.Fatalf("read the published schemas (refresh: scripts/refresh-k8s-surfaces.sh): %v", err)
	}
	var doc struct {
		Groups map[string]map[string]any `json:"groups"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse the published schemas: %v", err)
	}
	// D328: assert the subject. A thin file would make every comparison below vacuous.
	total := 0
	for _, g := range doc.Groups {
		total += len(g)
	}
	if len(doc.Groups) < 3 || total < 30 {
		t.Fatalf("%d groups / %d schemas read — too thin to be the published set; refresh "+
			"with scripts/refresh-k8s-surfaces.sh", len(doc.Groups), total)
	}

	names := make([]string, 0, len(embeddedMappings))
	for n := range embeddedMappings {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("no embedded mappings — this gate would be vacuous")
	}

	checked, crdOnly := 0, 0
	for _, n := range names {
		m := embeddedMappings[n]
		schemas, ok := doc.Groups[m.Resource.Group]
		if !ok {
			// A CRD group: its schemas live in whichever cluster installed it.
			crdOnly++
			continue
		}
		got, err := m.MappedSurfaceHash(schemas)
		if err != nil {
			t.Errorf("%s: surface hash against the published schemas failed: %v", n, err)
			continue
		}
		checked++
		if got != m.Schema.MappedSurface {
			t.Errorf("%s: the pinned mapped surface disagrees with the schema Kubernetes "+
				"PUBLISHES.\n  pinned:    %s\n  published: %s\n\n"+
				"A pin authored against a fixture that a real API server cannot produce is "+
				"exactly D509: the driver believes a shape the cluster does not serve, and "+
				"nothing hermetic can tell, because the fixtures were written from the same "+
				"belief. Re-author the mapping against the published schema, or refresh the "+
				"schemas if Kubernetes moved (scripts/refresh-k8s-surfaces.sh).",
				n, m.Schema.MappedSurface, got)
		}
	}
	if checked < 5 {
		t.Errorf("only %d mappings were checked against a published schema — the subject "+
			"shrank; this gate is meant to cover every built-in kind", checked)
	}
	t.Logf("%d built-in mappings checked against the published OpenAPI v3; %d CRD mappings "+
		"can only be checked against a live cluster (TestLiveMappedSurfacesMatchTheirPins)",
		checked, crdOnly)
}
