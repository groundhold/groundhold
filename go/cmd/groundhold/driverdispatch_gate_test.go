package main

import (
	"testing"

	"groundhold/internal/provider"
)

// D734. `--provider cloudflare` was ACCEPTED by the validator and silently dispatched to
// the FAKE, so `discover` answered a DNS sweep with `fake:existing-db` — a fabricated
// relational database. A pilot was one `adopt` away from writing that into their ledger
// as a real binding, and caught it only because they read the output before adopting.
//
// It broke the rule this binary prints a few lines above the validator, in its own
// words: "fake fabricates reality, so it must be chosen deliberately (--provider fake)
// rather than defaulted".
//
// The cause was four copies of the provider→driver mapping, three of which ended in
// `else { prov = &provider.Fake{} }`. This gate drives EVERY name the validator accepts
// through the one dispatch and requires a real driver — the fake only when it was asked
// for by name.
func TestEveryAcceptedProviderNameDispatchesToARealDriver(t *testing.T) {
	if len(knownProviders) < 5 {
		t.Fatalf("only %d provider names known — the gate lost its subject", len(knownProviders))
	}
	checked := 0
	for name := range knownProviders {
		p, err := driverFor(name, "proj", "eu-central-1", "", "")
		if name == "fake" {
			if _, isFake := p.(*provider.Fake); !isFake || err != nil {
				t.Errorf("--provider fake must give the fake, got %T (%v)", p, err)
			}
			continue
		}
		checked++
		if err != nil {
			// k8s needs a kubeconfig; refusing is correct and is NOT a silent fake.
			continue
		}
		if p == nil {
			t.Errorf("--provider %s dispatches to nothing — a caller that does not check "+
				"nil will substitute the fake (D734)", name)
			continue
		}
		if _, isFake := p.(*provider.Fake); isFake {
			t.Errorf("--provider %s dispatches to the FAKE — the validator accepts this "+
				"name, so a user who never typed `fake` receives fabricated reality (D734)",
				name)
		}
		if got := p.Name(); got != name {
			t.Errorf("--provider %s dispatches to a driver calling itself %q — the name a "+
				"user types and the driver they get must be the same thing", name, got)
		}
	}
	if checked < 4 {
		t.Fatalf("only %d non-fake names were dispatched — the gate lost its subject", checked)
	}
}

// D734: a name the validator does NOT accept must refuse at the dispatch too, so the two
// spellings of "which providers exist" cannot drift apart again.
func TestAnUnknownProviderNameHasNoDriver(t *testing.T) {
	if _, err := driverFor("xyzzy", "proj", "eu-central-1", "", ""); err == nil {
		t.Fatal("an unknown provider name produced a driver — this is the fall-through " +
			"that turned `--provider cloudflare` into fabricated reality")
	}
}
