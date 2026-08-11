package k8s

import (
	"os"
	"sort"
	"testing"
)

// The gate that would have caught D509 on the day it was written.
//
// Every hermetic drift test in this package computes a mapping's surface against
// a RECORDED fixture, and the fixtures were hand-simplified: they spell a
// reference as a bare {"$ref": ...}, which a real API server cannot emit for any
// property that also carries a description. So the fixtures agreed with the
// walker's assumption and the walker was blind by construction — the same shape
// as D273, where a unit fake mirrored the driver's own wrong assumption about a
// cloud API path. Six of the seven mapped services drifted against the first real
// cluster they ever met, which is to say the driver could not create anything.
//
// This test asks the cluster instead of the fixture. It is opt-in because CI has
// no cluster: set GROUNDHOLD_K8S_LIVE_KUBECONFIG to a kubeconfig (a throwaway
// k3d/kind cluster is enough — it reads schemas only, and mutates nothing).
//
//	GROUNDHOLD_K8S_LIVE_KUBECONFIG=$(k3d kubeconfig write mycluster) \
//	  go test ./internal/k8s -run TestLiveMappedSurfacesMatchTheirPins -v
func TestLiveMappedSurfacesMatchTheirPins(t *testing.T) {
	kc := os.Getenv("GROUNDHOLD_K8S_LIVE_KUBECONFIG")
	if kc == "" {
		t.Skip("no live cluster: set GROUNDHOLD_K8S_LIVE_KUBECONFIG to run this against a real API server")
	}
	d, err := NewFromKubeconfig(kc, "")
	if err != nil {
		t.Fatalf("kubeconfig %s: %v", kc, err)
	}

	names := make([]string, 0, len(embeddedMappings))
	for name := range embeddedMappings {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("no embedded mappings — this gate would be vacuous")
	}

	checked := 0
	for _, name := range names {
		m := embeddedMappings[name]
		schemas, err := d.SchemaFetch(m.Resource.Group, m.Resource.Version)
		if err != nil {
			// A CRD the cluster does not have installed is not a failure of the
			// mapping — cert-manager and Argo are not in a bare cluster.
			t.Logf("%-20s skipped: %v", name, err)
			continue
		}
		model, merr := mappedSurfaceModel(m, schemas)
		if merr != nil {
			t.Logf("%-20s skipped: %v", name, merr)
			continue
		}
		checked++
		surface, _ := model["surface"].(map[string]any)

		// A single ABSENT path is not automatically wrong: one lens serves both
		// Role and ClusterRole, and `aggregationRule` exists only on the latter,
		// so the Role mapping legitimately pins it ABSENT. What cannot be right is
		// a surface that is ABSENT in its ENTIRETY — that is a mapping whose
		// fingerprint pins nothing about the resource, and it is exactly the state
		// a pin authored through a blind walker would be in (the hash would then
		// match all-ABSENT for all-ABSENT and this gate would wave it through).
		var absent []string
		for path, sig := range surface {
			if sig == "ABSENT" {
				absent = append(absent, path)
			}
		}
		if len(surface) > 0 && len(absent) == len(surface) {
			sort.Strings(absent)
			t.Errorf("%s: EVERY mapped path is ABSENT from the live schema (%v) — the "+
				"fingerprint pins nothing, so the drift guard protects nothing", name, absent)
		}

		got, herr := m.MappedSurfaceHash(schemas)
		if herr != nil {
			t.Errorf("%s: %v", name, herr)
			continue
		}
		// An unpinned mapping is UNGUARDED, not fine. It used to be skipped before
		// the hash was even computed, so a live run said nothing about it at all —
		// the quietest possible way to carry debt. Say it, and hand over the value
		// an author needs to close it.
		if m.Schema.MappedSurface == "" {
			t.Logf("%-20s UNPINNED — drift is unchecked for this mapping; live surface is %s",
				name, got)
			continue
		}
		if got != m.Schema.MappedSurface {
			sort.Strings(absent)
			t.Errorf("%s: pinned mapped surface %s does not match the live cluster's %s\n"+
				"  paths the walker could not find live: %v\n"+
				"  live surface: %v\n"+
				"  either the pin was authored from a fixture that does not mirror a real "+
				"API server, or the API genuinely changed — read the surface before re-pinning",
				name, m.Schema.MappedSurface, got, absent, surface)
		}
	}
	if checked == 0 {
		t.Fatal("the cluster answered for no mapping at all — this run proved nothing")
	}
	t.Logf("checked %d mapped surfaces against the live cluster", checked)
}
