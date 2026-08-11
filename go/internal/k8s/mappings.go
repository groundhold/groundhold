// Embedded mapping documents (learn-from-API-contract). The mappings are driver
// artifacts in data form, so they ship INSIDE the binary — a self-contained runtime
// with no path dependency, which is what lets a migrated service's hand-coded twin
// be deleted safely: the generic path is always present. loadMapping validates each
// at startup; a malformed shipped mapping panics loudly rather than degrading.
package k8s

import (
	"embed"
	"io/fs"

	"groundhold/internal/provider"
)

//go:embed mappings/*.yaml
var mappingFS embed.FS

// embeddedMappings: every shipped mapping, keyed by its service token.
var embeddedMappings = loadEmbeddedMappings()

// init teaches the compiler which k8s services are WITNESS-only (observe/verify,
// never authored) so it emits no create for them (D177). A mapped service that is
// NOT writeSafe (its lenses have no write function — e.g. the GitOps controller
// Application, D175) is a witness; a writeSafe mapping and every hand-coded service
// author. The source of truth is writeSafe(), so nothing is hand-listed to drift.
func init() {
	provider.RegisterWitnessPredicate("k8s", func(service string) bool {
		m := embeddedMappings[service]
		return m != nil && !m.writeSafe()
	})
}

func loadEmbeddedMappings() map[string]*Mapping {
	out := map[string]*Mapping{}
	entries, err := fs.ReadDir(mappingFS, "mappings")
	if err != nil {
		panic("k8s: reading embedded mappings: " + err.Error())
	}
	for _, e := range entries {
		data, err := mappingFS.ReadFile("mappings/" + e.Name())
		if err != nil {
			panic("k8s: reading mapping " + e.Name() + ": " + err.Error())
		}
		m, err := loadMapping(data)
		if err != nil {
			panic("k8s: invalid mapping " + e.Name() + ": " + err.Error())
		}
		if _, dup := out[m.Service]; dup {
			panic("k8s: duplicate mapping service " + m.Service)
		}
		out[m.Service] = m
	}
	return out
}

// writeSafe reports whether the engine can also WRITE this resource generically:
// a closed-op attribute is always invertible; a lens is invertible only if it
// registers a write function. So writeSafe holds when every lens the mapping uses
// has a write-lens. Until then the hand-coded write twin stays.
func (m *Mapping) writeSafe() bool {
	for _, name := range m.Lenses {
		if lensRegistry[name].write == nil {
			return false
		}
	}
	return true
}

// mappingFor returns the mapping for a service (regardless of writeSafe) — used by
// the path-based Claim, which works for any mapped resource.
func (d *Driver) mappingFor(service string) *Mapping {
	if d.Mappings == nil {
		return nil
	}
	return d.Mappings[service]
}
