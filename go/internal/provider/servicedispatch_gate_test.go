package provider_test

import (
	"sort"
	"strings"
	"testing"

	"groundhold/internal/aws"
	"groundhold/internal/azure"
	"groundhold/internal/gcp"
	"groundhold/internal/provider"
)

// D771. `ServiceCapabilities` is what a driver CERTIFIES it fulfils — the map the parity
// query publishes, the bake-off consumes and `checkParityBindings` refuses a candidate
// against. It is a claim made to the outside.
//
// The claim and the dispatch are two different tables. D550 found the k8s twin of this
// gap from a live cluster: two observe-only services that `discover` enumerated with
// measured values and `observe` refused as unknown, because the read was gated on a
// write-safety predicate. D557 closed it for what discovery enumerates. Nothing asked the
// same question of the CERTIFIED map across the three clouds.
//
// Measured today: 54 + 46 + 45 services certified, zero undispatched. This gate makes a
// property that is currently true permanent — and it ASKS the drivers rather than reading
// their switch statements, because a scrape of the drivers is not evidence about the
// drivers (D317).
func TestEveryCertifiedServiceCanBeObserved(t *testing.T) {
	checked := 0
	for _, d := range []struct {
		name string
		p    provider.Provider
		caps map[string]string
	}{
		{"aws", aws.NewDriver("eu-central-1"), aws.NewDriver("").ServiceCapabilities()},
		{"gcp", gcp.NewDriver("p"), gcp.NewDriver("").ServiceCapabilities()},
		{"azure", azure.NewDriver("s"), azure.NewDriver("").ServiceCapabilities()},
	} {
		var undispatched []string
		for svc := range d.caps {
			checked++
			// A syntactically invalid providerId: the service check runs first and
			// needs no network, so the only thing this can elicit is the dispatch
			// answer. Any OTHER error is fine — it means the service was recognised
			// and the driver went on to complain about the id, which is the point.
			_, _, err := d.p.Observe(svc, "cap", "not-a-real-provider-id")
			if err != nil && strings.Contains(err.Error(), "unknown service") {
				undispatched = append(undispatched, svc)
			}
		}
		if len(undispatched) > 0 {
			sort.Strings(undispatched)
			t.Errorf("%s CERTIFIES %d services and Observe refuses %d of them as unknown:\n  %s\n\n"+
				"The certified map is published to the outside — parity answers from it and a "+
				"candidate is refused against it. A service in it that cannot be observed is a "+
				"claim the driver will not honour when asked (D771).",
				d.name, len(d.caps), len(undispatched), strings.Join(undispatched, ", "))
		}
	}
	if checked < 100 {
		t.Fatalf("only %d certified services examined — the gate has lost its subject and "+
			"would pass over a driver that certifies nothing (D328)", checked)
	}
	t.Logf("%d certified services, all dispatched by Observe", checked)
}
