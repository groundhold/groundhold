package gcp

import (
	"sort"
	"strings"
	"testing"
)

// D554. The k8s driver kept a hand-coded list of seven services beside a registry
// that knew ten, and three of them could not be adopted (D550). The list was only
// ever consulted on the paths where it was wrong, so nothing noticed.
//
// Measured across the cloud drivers when that was found: aws, gcp and azure all
// agreed with their registries, in both directions. That agreement was a fact about
// today's maintenance, not a property anything held — which is the state a gap is in
// just before it opens. This holds it.
func TestDispatchGateAgreesWithTheServiceRegistry(t *testing.T) {
	d := NewDriver("acme-prod-123")
	served := d.ServiceCapabilities()
	if len(served) < 5 {
		t.Fatalf("the registry reports %d services — this gate would be near-vacuous", len(served))
	}
	var denied []string
	for s := range served {
		if err := d.requireService(s); err != nil {
			denied = append(denied, s+" ("+err.Error()+")")
		}
	}
	if len(denied) > 0 {
		sort.Strings(denied)
		t.Errorf("the driver SERVES %d services its dispatch gate refuses:\n  %s\n"+
			"Every verb that checks the gate is closed for them, and the refusal names "+
			"the service as unknown rather than the list as stale.",
			len(denied), strings.Join(denied, "\n  "))
	}
}

// D557. The k8s defect had a second half the first gate would not have caught:
// `discover` and `observe` consulted DIFFERENT registries, so discovery enumerated an
// object with measured values that observe then refused. Two channels answering about
// the same object must agree, even when each is internally consistent.
//
// Measured when this was written: all three clouds already agreed — every
// discoverable service is in the registry and passes the dispatch gate. Held now
// rather than left to maintenance.
func TestEverythingDiscoveryEnumeratesCanBeObserved(t *testing.T) {
	d := NewDriver("acme-prod-123")
	disc := d.DiscoverableServices()
	if len(disc) < 5 {
		t.Fatalf("only %d discoverable services — this gate would be near-vacuous", len(disc))
	}
	served := d.ServiceCapabilities()
	var bad []string
	for _, s := range disc {
		if _, ok := served[s]; !ok {
			bad = append(bad, s+" (discovery enumerates it; the registry does not serve it)")
			continue
		}
		if err := d.requireService(s); err != nil {
			bad = append(bad, s+" (discovery enumerates it; the dispatch gate refuses it: "+err.Error()+")")
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("discovery reports %d resources the rest of the driver disowns:\n  %s\n"+
			"A resource enumerated as real and then refused by name is the driver "+
			"contradicting itself within one run.", len(bad), strings.Join(bad, "\n  "))
	}
}
