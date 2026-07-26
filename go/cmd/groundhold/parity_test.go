package main

import (
	"testing"

	"groundhold/internal/aws"
	"groundhold/internal/azure"
	"groundhold/internal/cloudflare"
	"groundhold/internal/gcp"
	"groundhold/internal/hetzner"
	"groundhold/internal/k8s"
	"groundhold/internal/provider"
	"groundhold/internal/upstash"
)

// TestDriverParity pins the driver capability matrix documented in spec/drivers.md,
// turning the standard into a live contract: every listable provider MUST be a
// Discoverer (the input to crawl/posture), and the Enumerator gaps (scope fan-out
// on real multi-scope providers) are TRACKED so closing one flags the doc to
// update. A driver that silently loses Discoverer, or gains Enumerator without the
// matrix moving, breaks this test on purpose.
func TestDriverParity(t *testing.T) {
	type caps struct{ discoverer, enumerator bool }
	probe := func(p provider.Provider) caps {
		_, d := p.(provider.Discoverer)
		_, e := p.(provider.Enumerator)
		return caps{d, e}
	}
	got := map[string]caps{
		"aws":        probe(aws.NewDriver("")),
		"gcp":        probe(gcp.NewDriver("")),
		"azure":      probe(azure.NewDriver("sub")),
		"k8s":        probe(k8s.NewDriver("", "")),
		"hetzner":    probe(hetzner.NewDriver("")),
		"upstash":    probe(upstash.NewDriver()),
		"cloudflare": probe(cloudflare.NewDriver("")),
		"fake":       probe(&provider.Fake{}),
	}
	// the documented matrix (spec/drivers.md §7). The real multi-scope drivers now
	// enumerate their scopes (aws regions, gcp projects, azure subscriptions, k8s
	// namespaces); the single-scope drivers correctly omit Enumerator. Closing a gap
	// must move both the matrix and this expectation together.
	want := map[string]caps{
		"aws":        {discoverer: true, enumerator: true},  // regions
		"gcp":        {discoverer: true, enumerator: true},  // projects
		"azure":      {discoverer: true, enumerator: true},  // subscriptions
		"k8s":        {discoverer: true, enumerator: true},  // namespaces
		"hetzner":    {discoverer: true, enumerator: false}, // token = project: no scopes to enumerate
		"upstash":    {discoverer: true, enumerator: false}, // account-global: no scopes
		"cloudflare": {discoverer: true, enumerator: false}, // token = account: zones are records, not scopes
		"fake":       {discoverer: true, enumerator: true},
	}
	for name, w := range want {
		g := got[name]
		if !g.discoverer {
			t.Errorf("%s is not a Discoverer — every listable provider MUST implement it "+
				"to join the proactive posture (spec/drivers.md §2)", name)
		}
		if g.enumerator != w.enumerator {
			t.Errorf("%s Enumerator = %v, want %v — if a parity gap opened or closed, "+
				"update the matrix in spec/drivers.md §7 alongside this expectation",
				name, g.enumerator, w.enumerator)
		}
	}
}
