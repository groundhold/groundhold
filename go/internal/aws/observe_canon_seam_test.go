package aws

import (
	"testing"

	"groundhold/internal/canonical"
	"groundhold/internal/provider"
)

// canonicalizeObservations is the driver→core SEAM guard. The YAML-fed
// conformance/differential corpus can only ever produce []any/map[string]any, so
// it is structurally blind to the NATIVE Go types drivers emit — the class that
// crashed the first user's `discover --provider aws` on a []string
// (D200). This asserts every observation a driver produces canonicalizes; call it
// from any driver's observe test to catch a fresh un-canonicalizable value in CI,
// not on a user's cloud.
func canonicalizeObservations(t *testing.T, obs []provider.Observation) {
	t.Helper()
	for _, o := range obs {
		if _, err := canonical.Canon(o.Value); err != nil {
			t.Errorf("observation %q value %#v (%T) does not canonicalize: %v",
				o.Path, o.Value, o.Value, err)
		}
	}
}

// TestBedrock_ObservationsCanonicalize crosses the exact seam that regressed:
// observeBedrock emits inference.destinationRegions as a native []string (the
// residency surface). This proves driver→observe→canon holds end to end for the
// value shape a YAML case can never construct.
func TestBedrock_ObservationsCanonicalize(t *testing.T) {
	f := newFakeBedrock()
	rec := newCapture()
	srv := f.handler(t, rec)
	defer srv.Close()
	d := bedrockDriver(t, srv)

	obs, _, err := d.observeBedrock(bedrockCap,
		bedrockProviderID(bedrockRegion, bedrockProfile1))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}

	// guard the guard: the native []string observation must actually be present,
	// otherwise this test would pass vacuously if the driver stopped emitting it.
	found := false
	for _, o := range obs {
		if o.Path == "inference.destinationRegions" {
			if _, ok := o.Value.([]string); !ok {
				t.Fatalf("expected a native []string, got %T — seam no longer exercised",
					o.Value)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("inference.destinationRegions not observed — the []string seam is no longer guarded")
	}

	canonicalizeObservations(t, obs)
}
