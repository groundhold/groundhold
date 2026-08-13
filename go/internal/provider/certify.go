package provider

import (
	"sort"
	"strings"
)

// CapabilityMapper is the optional capability a driver implements to make the
// cross-cloud PARITY matrix mechanically checkable: it reports, for every SERVICE
// token it certifies, the capability TYPE that service fulfils (D76: one TYPE,
// many services — rds and aurora both fulfil capability.database.relational).
// CertifyParity reads it so the parity matrix is PROVEN against the real drivers,
// not hand-authored with guessed cells. This is the third iteration of the
// ServiceLister/CertifyDiscoverability pattern — an optional interface + a shared
// battery — closing the symmetry: which services exist (CertifyDriver), which are
// discoverable (CertifyDiscoverability), which capability each fulfils (CertifyParity).
type CapabilityMapper interface {
	ServiceCapabilities() map[string]string
}

// CertifyParity proves the token->capability map is a TOTAL, PHANTOM-FREE
// projection of the driver's certified service set: every certified service maps
// to exactly one capability TYPE, and the map claims no service the dispatch does
// not know. The value's membership in the real vocabulary and the cross-cloud
// coherence (gap-reality, no-silent-omission, generation stability) are proven by
// the parity matrix golden test, which has all three drivers + the vocab at once.
//
// Call it from the driver's test with the SAME service list as CertifyDriver:
// provider.CertifyParity(t, aws.NewDriver("..."), services).
func CertifyParity(t TestingT, prov Provider, services []string) {
	t.Helper()

	cm, ok := prov.(CapabilityMapper)
	if !ok {
		t.Errorf("%s does not implement CapabilityMapper — its cross-cloud parity "+
			"cannot be certified; every provider driver must expose "+
			"ServiceCapabilities() (spec/drivers.md §8)", prov.Name())
		return
	}
	m := cm.ServiceCapabilities()

	want := map[string]bool{}
	for _, s := range services {
		want[s] = true
	}
	// No phantom: the map claims no service outside the certified set.
	for tok := range m {
		if !want[tok] {
			t.Errorf("%s: ServiceCapabilities claims %q, which is not a certified service "+
				"— the parity map must not over-claim the dispatch table", prov.Name(), tok)
		}
	}
	// Totality + well-formedness: every certified service maps to exactly one
	// well-formed capability TYPE (its real vocab membership is checked by the
	// parity golden test, which can read spec/vocab).
	for _, svc := range services {
		typ, present := m[svc]
		if !present {
			t.Errorf("%s: certified service %q has no capability in ServiceCapabilities "+
				"— every observable service must declare the TYPE it fulfils (D76)",
				prov.Name(), svc)
			continue
		}
		if typ == "" || !strings.HasPrefix(typ, "capability.") {
			t.Errorf("%s: service %q maps to %q, which is not a capability.<...> TYPE",
				prov.Name(), svc, typ)
		}
	}
}

// ServiceLister is the optional capability a driver implements to make its
// discoverability MECHANICALLY CHECKABLE: it reports the SERVICE tokens its
// List() sweep covers (the serviceDiscoverers registry keys). CertifyDiscoverability
// reads it so the gate can prove — not trust — that every observable service is
// also discoverable.
type ServiceLister interface {
	DiscoverableServices() []string
}

// NonLister is the optional escape hatch for the discoverability gate: a driver
// declares the certified SERVICE tokens that are NOT standalone listable resources
// (and therefore legitimately have no discoverer), each mapped to a categorical
// reason from the closed set below. A listable-but-unwritten sweep may NOT hide
// here — the reason must be a permanent structural claim, not a to-do.
type NonLister interface {
	NonListableServices() map[string]string
}

// nonListableReasons is the CLOSED set of legitimate exemptions from the
// discoverability gate. Free-text reasons are rejected so the exemption bucket
// cannot become a trust-me allowlist (the thing this gate exists to kill).
var nonListableReasons = map[string]bool{
	"provisioned-feed": true, // an event feed groundhold PROVISIONS, not a resource it discovers
	"sub-resource":     true, // enumerated only relative to a parent (attachment, filter, key-in-vault)
	"test-fixture":     true, // a synthetic service used only by the test battery
	"project-metadata": true, // the account/project envelope itself, not a resource within it
}

// CertifyDiscoverability proves the driver standard's core requirement
// (spec/drivers.md §2): every service the driver OBSERVES must also be
// DISCOVERABLE — either covered by a List sweep, or explicitly declared
// non-listable with a categorical reason. A new Observe cannot ship without
// becoming discoverable, because adding it grows the certified `services` set
// and this gate fails until a discoverer or a reasoned exemption exists.
//
// Call it from the driver's test with the SAME service list passed to
// CertifyDriver: provider.CertifyDiscoverability(t, aws.NewDriver("..."), services).
func CertifyDiscoverability(t TestingT, prov Provider, services []string) {
	t.Helper()

	// D856: a subject of ZERO certifies nothing. Measured, not suspected — with
	// `MappedServiceTokens()` returning nil the k8s driver passed this gate while
	// being able to discover nothing at all, which is the exact condition the gate
	// exists to make impossible (a shadow-blind driver, D513). The cloud drivers
	// pass hand-written lists that cannot silently empty; k8s derives its list from
	// an embedded registry, and a derived subject is one filter away from nothing.
	if len(services) == 0 {
		t.Errorf("%s certified discoverability over ZERO services — the subject is empty, "+
			"so this gate proved nothing. A driver that maps no services is either "+
			"mis-wired or its registry did not load (D328).", prov.Name())
		return
	}

	sl, ok := prov.(ServiceLister)
	if !ok {
		t.Errorf("%s does not implement ServiceLister — its discoverability cannot "+
			"be certified; every driver with listable resources must expose "+
			"DiscoverableServices() (spec/drivers.md §2)", prov.Name())
		return
	}
	covered := map[string]bool{}
	for _, s := range sl.DiscoverableServices() {
		covered[s] = true
	}
	exempt := map[string]string{}
	if nl, ok := prov.(NonLister); ok {
		exempt = nl.NonListableServices()
	}
	// Exemptions must carry a reason from the closed set — no free-text escape.
	for svc, reason := range exempt {
		if !nonListableReasons[reason] {
			t.Errorf("%s declares %q non-listable with reason %q, which is not in the "+
				"closed reason set {provisioned-feed, sub-resource, test-fixture, "+
				"project-metadata} — an exemption must be a structural claim, not a to-do",
				prov.Name(), svc, reason)
		}
	}
	for _, svc := range services {
		if covered[svc] {
			if _, dup := exempt[svc]; dup {
				t.Errorf("%s: %q is both discoverable AND declared non-listable — "+
					"pick one", prov.Name(), svc)
			}
			continue
		}
		if _, ok := exempt[svc]; ok {
			continue
		}
		t.Errorf("%s: service %q is observable (has a PermissionsFor table) but has no "+
			"discoverer sweep and no non-listable exemption — every observable service "+
			"MUST be discoverable so the proactive posture sees it (spec/drivers.md §2)",
			prov.Name(), svc)
	}
}

// TestingT is the subset of *testing.T the certification needs, so a driver in
// any package can run CertifyDriver from its own test without this file
// importing the testing package into the shipped build.
type TestingT interface {
	Helper()
	Errorf(format string, args ...any)
}

// CertifyDriver is the driver-agnostic battery every provider must pass (see
// spec/providers/AUTHORING.md). It exercises only the network-free contract —
// dispatch fail-closed and the permission tables — so it never mutates a
// cloud. Per-service builders, ownership and IAM honesty are certified by the
// driver's own golden/httptest suites; this pins the invariants that are the
// same for every service.
//
// Call it from the driver's test: provider.CertifyDriver(t, gcp.NewDriver(""),
// []string{"cloudsql", "cloudrun", "gcs"}). The fake is exempt — it is
// deliberately service-agnostic.
func CertifyDriver(t TestingT, prov Provider, services []string) {
	t.Helper()

	// Dispatch fails closed on an unknown service — never a silent default
	// into some other service's API (confused-deputy). These refuse before
	// any network call (the dispatch gate is first).
	const bogus = "__not_a_real_service__"
	if r := prov.Create(bogus, "cap", "env", nil, nil, "k", 1); r.Status != "failed" {
		t.Errorf("Create on an unknown service must fail closed, got %q", r.Status)
	}
	if err := prov.Validate(bogus, "cap", "env", nil, nil, 1); err == nil {
		t.Errorf("Validate on an unknown service must refuse")
	}
	if _, _, err := prov.Observe(bogus, "cap", "x:y:z"); err == nil {
		t.Errorf("Observe on an unknown service must refuse")
	}
	if r := prov.Delete(bogus, "cap", "env", "x:y:z", "k"); r.Status != "failed" {
		t.Errorf("Delete on an unknown service must fail closed, got %q", r.Status)
	}

	// Every declared service names a non-empty, sorted, deduped permission set
	// for each mutating operation — an empty set defeats the D75 preflight
	// (a mutation with no declared permissions preflights as satisfiable).
	for _, svc := range services {
		for _, op := range []string{"create", "update", "delete"} {
			p := PermissionsFor(prov.Name(), svc, op, nil)
			if len(p) == 0 {
				t.Errorf("PermissionsFor(%s, %s, %s) is empty — a mutation "+
					"with no declared permissions defeats the D75 preflight",
					prov.Name(), svc, op)
				continue
			}
			if !sort.StringsAreSorted(p) {
				t.Errorf("PermissionsFor(%s, %s, %s) is not sorted: %v",
					prov.Name(), svc, op, p)
			}
			seen := map[string]bool{}
			for _, x := range p {
				if seen[x] {
					t.Errorf("PermissionsFor(%s, %s, %s) has a duplicate %q",
						prov.Name(), svc, op, x)
				}
				seen[x] = true
			}
		}
	}
}

// emittedCompanionFloor is how many (service, companion) emissions CertifyEmissions
// resolves. It may only RISE: a register that quietly empties certifies nothing
// (D328/D856), and this register's whole value is that a companion cannot be added
// to a driver without its name and its governor proven consistent.
const emittedCompanionFloor = 1

// CertifyEmissions proves the emission registry (D1032) is trustworthy for the two
// properties a completeness gate and a future adopt grant both rest on:
//
//   - D329, ONE derivation: every EmittedCompanion.NameOutput is a real output the
//     emitting service PUBLISHES (OutputsFor). The companion's name and the
//     producer's output are then the same value, so a witness reading the companion
//     and a capability governing it cannot drift into disagreement.
//   - no phantom governor: every GovernedBy is a capability this driver actually
//     fulfils (ServiceCapabilities), never a token no service serves.
//
// A driver that emits nothing need not implement EmissionCertifier; one that does is
// held to both invariants and to a floor that may only rise.
func CertifyEmissions(t TestingT, prov Provider) {
	t.Helper()
	ec, ok := prov.(EmissionCertifier)
	if !ok {
		return // optional: a driver with no auto-emitted companions
	}
	op, ok := prov.(OutputProducer)
	if !ok {
		t.Errorf("%s certifies emissions but is not an OutputProducer — a companion's "+
			"NameOutput cannot be proven against the producer's outputs (D329)", prov.Name())
		return
	}
	cm, ok := prov.(CapabilityMapper)
	if !ok {
		t.Errorf("%s certifies emissions but is not a CapabilityMapper — a companion's "+
			"GovernedBy cannot be proven a real capability", prov.Name())
		return
	}
	governors := map[string]bool{}
	for _, capType := range cm.ServiceCapabilities() {
		governors[capType] = true
	}

	count := 0
	for svc, comps := range ec.EmittedCompanions() {
		outs := map[string]bool{}
		for _, o := range op.OutputsFor(svc) {
			outs[o.Name] = true
		}
		if len(comps) == 0 {
			t.Errorf("%s: service %q has an EMPTY emission list — omit the key or name a "+
				"companion; an empty entry certifies nothing (D328)", prov.Name(), svc)
		}
		for _, c := range comps {
			count++
			if c.NameOutput == "" || !outs[c.NameOutput] {
				names := make([]string, 0, len(outs))
				for n := range outs {
					names = append(names, n)
				}
				t.Errorf("%s: emission for %q names its companion via output %q, which %q "+
					"does NOT publish — the emission name and the producer output must be the "+
					"SAME derivation or a witness and a governor drift (D329). Published: %v",
					prov.Name(), svc, c.NameOutput, svc, sortedDedup(names))
			}
			switch {
			case c.GovernedBy == "" || !strings.HasPrefix(c.GovernedBy, "capability."):
				t.Errorf("%s: emission for %q has GovernedBy %q, not a capability.<...> type",
					prov.Name(), svc, c.GovernedBy)
			case !governors[c.GovernedBy]:
				t.Errorf("%s: emission for %q is GovernedBy %q, which no service in this "+
					"driver fulfils — a companion cannot be governed by a phantom capability",
					prov.Name(), svc, c.GovernedBy)
			}
		}
	}
	if count < emittedCompanionFloor {
		t.Errorf("%s: CertifyEmissions resolved %d companions, below floor %d — the register "+
			"shrank and now certifies almost nothing (D328)", prov.Name(), count, emittedCompanionFloor)
	}
}
