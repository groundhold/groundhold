// Package caplens is the cross-provider capability-lens library: the small set of
// SEMANTIC derivations that were hand-coded identically in every cloud driver
// (aws/gcp/azure) and are now defined ONCE, provider-neutral and network-free.
//
// It is the honest residue of the "learn from the API contract" idea. A driver's
// reverse-map is mostly per-family (auth, transport, identity, the raw field
// extraction), but a few OUTPUTS are genuinely cross-provider — the capability
// vocabulary and the canonicalization that lands on it. Those belong in one place
// so three drivers cannot drift on what "regional" means or how a protocol/version
// is spelled. Each driver still extracts its own raw signal; it hands that signal
// here to get the canonical capability value.
//
// Scope discipline (why this is small): only derivations with genuinely SHARED
// LOGIC live here. `recovery.rpo`, for instance, is NOT here — AWS approximates it
// as a constant while Azure derives it from retention days; they measure different
// things, and forcing them together would be a lie, not a dedup.
package caplens

// The closed capability.database availability vocabulary. One authority, so no
// driver can typo "regional" or invent a fourth class.
const (
	ClassZonal         = "zonal"
	ClassRegional      = "regional"
	ClassMultiRegional = "multi-regional"
)

// AvailabilityClass maps a provider's "is this multi-zone / regional-HA" signal to
// the canonical availability.class. AWS (MultiAZ) and Azure (HA mode ==
// ZoneRedundant) had byte-identical `if x { "regional" } else { "zonal" }`; this is
// that logic, once. GCP's enum path lands on the same constants (see the driver).
func AvailabilityClass(regional bool) string {
	if regional {
		return ClassRegional
	}
	return ClassZonal
}

// Canonical engine.protocol names.
const (
	EnginePostgres = "postgresql"
	EngineMySQL    = "mysql"
)

// CanonicalEngine folds a provider's raw engine name onto the capability
// vocabulary. The only real alias across the drivers is AWS's "postgres" (vs the
// vocabulary's "postgresql"); every other name passes through unchanged.
func CanonicalEngine(engine string) string {
	if engine == "postgres" {
		return EnginePostgres
	}
	return engine
}

// EngineProtocol composes the canonical engine.protocol value: the canonicalized
// engine name, and — when a version is known — "<engine>/<version>". A driver that
// has no version (rare) gets the bare protocol, exactly as the hand-coded paths
// did. It never invents a version.
func EngineProtocol(engine, version string) string {
	p := CanonicalEngine(engine)
	if version != "" {
		return p + "/" + version
	}
	return p
}
