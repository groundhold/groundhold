package provider

import "testing"

// snapshotPredicates saves the package-level witness registry and restores it on
// cleanup, so a test may register predicates without leaking into sibling tests
// (the registry is process-global — a real driver registers at init()).
func snapshotPredicates(t *testing.T) {
	t.Helper()
	saved := make(map[string]func(string) bool, len(witnessPredicates))
	for k, v := range witnessPredicates {
		saved[k] = v
	}
	t.Cleanup(func() {
		witnessPredicates = saved
	})
}

// A provider with no registered predicate AUTHORS every service — the cloud
// default (aws/gcp/azure never register; everything they observe, they create).
// This is the fail-OPEN choice that keeps existing behavior unchanged (D177); it
// is load-bearing, so it is pinned directly rather than left implicit.
func TestCanAuthorDefaultsToAuthoring(t *testing.T) {
	snapshotPredicates(t)
	witnessPredicates = map[string]func(string) bool{}

	for _, svc := range []string{"rds", "cloudsql", "", "anything-at-all"} {
		if !CanAuthor("aws", svc) {
			t.Errorf("CanAuthor(aws, %q) = false; an unregistered provider must "+
				"author every service (the cloud default)", svc)
		}
	}
	if !CanAuthor("provider-that-was-never-registered", "svc") {
		t.Errorf("an entirely unknown provider must default to authoring")
	}
}

// A registered predicate is authoritative and per-service: the witness services
// it names cannot be authored (the compiler records them as witnessed, D177),
// while every other service of the SAME provider still authors. This is the
// k8s shape (writeSafe mappings author, observe-only mappings witness) in the
// small, without importing the k8s driver.
func TestCanAuthorFollowsRegisteredPredicate(t *testing.T) {
	snapshotPredicates(t)
	witnessPredicates = map[string]func(string) bool{}

	witnesses := map[string]bool{"gitops-application": true, "some-crd": true}
	RegisterWitnessPredicate("k8s-like", func(service string) bool {
		return witnesses[service]
	})

	if CanAuthor("k8s-like", "gitops-application") {
		t.Errorf("a service the predicate calls witness must NOT be authorable")
	}
	if CanAuthor("k8s-like", "some-crd") {
		t.Errorf("a second witness service must also be non-authorable")
	}
	if !CanAuthor("k8s-like", "rbac-role") {
		t.Errorf("a non-witness service of the same provider must still author — " +
			"authorability is per-service, not per-provider")
	}
	// A different provider is unaffected by k8s-like's registration.
	if !CanAuthor("aws", "gitops-application") {
		t.Errorf("one provider's witness predicate must not leak to another provider")
	}
}

// Registration is last-write-wins for a given provider name — a driver's init()
// installs exactly one predicate; re-registration replaces rather than layers, so
// the resolution stays a single deterministic function call.
func TestRegisterWitnessPredicateOverwrites(t *testing.T) {
	snapshotPredicates(t)
	witnessPredicates = map[string]func(string) bool{}

	RegisterWitnessPredicate("p", func(string) bool { return true })
	if CanAuthor("p", "x") {
		t.Fatalf("first predicate should make everything witness")
	}
	RegisterWitnessPredicate("p", func(string) bool { return false })
	if !CanAuthor("p", "x") {
		t.Errorf("re-registration must replace the predicate, not compose it")
	}
}
