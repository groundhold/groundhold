package discover

import (
	"testing"

	"groundhold/internal/provider"
)

// dscFake is a minimal Discoverer: it embeds provider.Fake (so it satisfies the
// full provider.Provider surface) and returns a fixed resource set from List.
type dscFake struct {
	provider.Fake
	resources []provider.Discovered
}

func (f *dscFake) List(string) ([]provider.Discovered, []string, error) {
	return f.resources, nil, nil
}

// A resource whose reverse mapping happens to emit two observations sharing a
// PATH but differing in value/derivation must hash the SAME regardless of the
// order the driver returned them in — the discovery hash is an identity of
// reality, not of enumeration order (determinism follows meaning). Before the
// total-order tiebreak, sort-by-path-alone left equal paths in input order and
// fed that into the hash.
func TestDiscoveryHashIsOrderIndependentForDuplicatePaths(t *testing.T) {
	obsA := []provider.Observation{
		{Path: "network.publicExposure", Value: true, Derivation: "measured"},
		{Path: "tag.owner", Value: "x", Derivation: "measured"},
		{Path: "tag.owner", Value: "y", Derivation: "config-intent"},
	}
	// same three observations, different enumeration order (the two tag.owner
	// entries swapped, and the exposure entry moved).
	obsB := []provider.Observation{
		{Path: "tag.owner", Value: "y", Derivation: "config-intent"},
		{Path: "tag.owner", Value: "x", Derivation: "measured"},
		{Path: "network.publicExposure", Value: true, Derivation: "measured"},
	}

	run := func(obs []provider.Observation) string {
		f := &dscFake{resources: []provider.Discovered{
			{ProviderID: "fake:r1", ResourceType: "capability.workload.container", Observations: obs},
		}}
		res, err := Run(f, "proj", "region", "2026-07-11T00:00:00Z")
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return res.DiscoveryHash
	}

	hA, hB := run(obsA), run(obsB)
	if hA == "" || hA[:7] != "sha256:" {
		t.Fatalf("expected a sha256: discovery hash, got %q", hA)
	}
	if hA != hB {
		t.Fatalf("discovery hash depends on enumeration order for duplicate paths: %s != %s", hA, hB)
	}
}
