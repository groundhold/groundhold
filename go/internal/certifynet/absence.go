package certifynet

import (
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

// The absence property (F-LC3), asked as a class.
//
// `provider.ResourceAbsentPath` is the reserved observation a driver emits when a
// BOUND resource is authoritatively GONE — a readable 404, never a read error —
// and the compiler turns a fresh `true` into a re-create so an out-of-band delete
// self-heals. The contract was written down once and implemented once: of ~145
// certified services, AWS Lambda emitted it and nothing else did. Everywhere else
// the read returned a diagnostic string and NO observation, the compile saw an
// empty set, and `converge` reported the world as matching a world that no longer
// contained the resource. Measured on a real cluster, after a forced fresh
// observation (D513).
//
// This is the D237/AssertTransient shape, deliberately: a property that cannot be
// migrated across every service at once, tracked per service by whether the probe
// supplies the closure rather than by a boolean that can claim coverage it does
// not have. A nil ObserveAbsent is an un-migrated service and the ratchet counts
// it; it can never be a false claim, because the only way to assert the property
// is to hand the harness something it can actually run.
func certifyAbsence(t TestingT, p *Probe) {
	t.Helper()

	// The estate in which nothing exists. Protocol-aware, because "gone" is not
	// one wire answer — see GoneEstate (D521).
	gone := GoneEstateCode(p.GoneCode)
	if p.GoneEmptyList {
		gone = GoneEstateEmptyList()
	}
	defer gone.Close()

	// A driver that PANICS on a 404 is a finding, not a reason to take the test
	// binary down with it — two AWS services did exactly that, and a crashed suite
	// reports nothing about the other hundred probes (D520).
	obs, err := func() (obs []provider.Observation, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("the driver PANICKED observing a 404: %v", r)
			}
		}()
		o, _, e := p.ObserveAbsent(p.New(gone.URL, http.DefaultTransport))
		return o, e
	}()
	if err != nil {
		t.Errorf("%s: observing a resource the API 404s returned an ERROR (%v) — a readable "+
			"absence is a fact about the world, not a failure to read it; an error blocks "+
			"re-observe-first instead of re-creating", p.Name, err)
		return
	}
	for _, o := range obs {
		if o.Path != provider.ResourceAbsentPath {
			continue
		}
		if gone, _ := o.Value.(bool); !gone {
			t.Errorf("%s: %s = %v on a resource that does not exist", p.Name,
				provider.ResourceAbsentPath, o.Value)
		}
		return
	}
	t.Errorf("%s: observing a resource the API 404s emitted no %s at all (got %d observations) "+
		"— the binding stays a no-op forever and converge reports the world as matching while "+
		"the resource is gone", p.Name, provider.ResourceAbsentPath, len(obs))
}
