package provider

// Authorability: does a (provider, service) AUTHOR its resource, or only WITNESS it?
//
// The author-vs-witness doctrine made mechanical for the compiler. Most services
// AUTHOR — groundhold creates/updates/deletes them, so the compiler emits actions. A
// WITNESS service (an observe-only k8s mapping with no write lens — a GitOps
// controller's Application, D175) is one groundhold can only OBSERVE/VERIFY, never
// mutate. The compiler must NOT emit a create for it (the plan would lie: the driver
// would refuse the create at apply). Instead it records the capability as witnessed
// and emits no mutating action (D177).
//
// The signal is package-level and name-dispatched, exactly like PermissionsFor —
// the compiler holds provider NAMES per capability (a candidate can be mixed:
// aws podidentity + k8s witness), not a single driver instance. A provider whose
// authorability is uniform (every cloud driver: everything authors) needs no
// registration; the default is CanAuthor == true, so all existing behavior is
// unchanged. Only a provider with observe-only services (k8s) registers a predicate.
// The provider package does not import the drivers (no cycle) — the driver registers
// at init(), the same discipline as database/sql drivers.

// witnessPredicates maps a provider name to "is this service witness-only?" A missing
// entry means the provider authors every service (the cloud default).
var witnessPredicates = map[string]func(service string) bool{}

// RegisterWitnessPredicate lets a driver declare which of its services are
// WITNESS-only (observe/verify, never authored). Called from the driver's init().
func RegisterWitnessPredicate(providerName string, isWitness func(service string) bool) {
	witnessPredicates[providerName] = isWitness
}

// CanAuthor reports whether groundhold can AUTHOR (create/update/delete) the given
// (provider, service). false means the service is WITNESS-only: the compiler records
// it as witnessed and emits no mutating action. Unknown provider / no registered
// predicate => true (authors), so nothing regresses.
func CanAuthor(providerName, service string) bool {
	if isWitness, ok := witnessPredicates[providerName]; ok {
		return !isWitness(service)
	}
	return true
}
