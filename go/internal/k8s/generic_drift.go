// Schema-drift guard for the generic engine (D132 applied to mappings). A mapping
// is authored against a specific API schema. If the live schema diverges INSIDE the
// mapped surface — a mapped field changed type, lost an enum member, or vanished —
// the mapping may misread it, so the engine REFUSES (mapping-schema-drift) rather
// than reinterpret. Divergence OUTSIDE the mapped surface is a diagnostic: the
// mapping pins what it depends on and tolerates what it doesn't. The mapped-surface
// fingerprint is the only honest tripwire; best-effort against a diverged schema is
// silent semantic migration.
package k8s

import (
	"fmt"

	"groundhold/internal/canonical"
	"groundhold/internal/mapping"
	"groundhold/internal/perr"
)

const mappedSurfaceDomain = "groundhold/canon/v1:k8s-mapped-surface"

type schemaPin struct {
	Fingerprint   string `yaml:"fingerprint"`
	MappedSurface string `yaml:"mappedSurface"`
	Source        string `yaml:"source"`
}

func strOf(v any) string { s, _ := v.(string); return s }

// findGVKSchema locates a resource's schema in an OpenAPI components.schemas map by
// its x-kubernetes-group-version-kind marker — robust to the k8s package-naming
// convention, which is not mechanically derivable from the GVK alone.
func findGVKSchema(schemas map[string]any, group, version, kind string) (map[string]any, bool) {
	for _, v := range schemas {
		node, ok := v.(map[string]any)
		if !ok {
			continue
		}
		gvks, ok := node["x-kubernetes-group-version-kind"].([]any)
		if !ok {
			continue
		}
		for _, g := range gvks {
			gm, _ := g.(map[string]any)
			if strOf(gm["group"]) == group && strOf(gm["version"]) == version && strOf(gm["kind"]) == kind {
				return node, true
			}
		}
	}
	return nil, false
}

// $ref resolution, schema-path walking, and type signatures now live in the
// provider-agnostic internal/mapping package (mapping.ResolveRef / WalkSchemaPath /
// TypeSig). findGVKSchema stays here: locating a resource's schema by the
// x-kubernetes-group-version-kind marker is Kubernetes-specific.

// mappedSurfaceModel is the deterministic model hashed into the mapped-surface
// fingerprint: the identity facts + each mapped field's terminal type signature (or
// ABSENT when the path is gone from the schema — itself a drift the hash catches).
func mappedSurfaceModel(m *Mapping, schemas map[string]any) (map[string]any, error) {
	gvk, ok := findGVKSchema(schemas, m.Resource.Group, m.Resource.Version, m.Resource.Kind)
	if !ok {
		return nil, fmt.Errorf("schema for %q %s/%s not found in the OpenAPI document",
			m.Resource.Kind, m.Resource.Group, m.Resource.Version)
	}
	surface := map[string]any{}
	sigFor := func(fieldPath string) (string, error) {
		segs, err := mapping.ParseFieldPath(fieldPath)
		if err != nil {
			return "", err
		}
		if sig, ok := mapping.WalkSchemaPath(gvk, schemas, segs); ok {
			return sig, nil
		}
		return "ABSENT", nil
	}
	for path, a := range m.Attributes {
		if a.Op == "const" || a.Field == "" {
			continue // const has no schema dependency
		}
		sig, err := sigFor(a.Field)
		if err != nil {
			return nil, err
		}
		surface[path] = sig
		// D551: a resolve-ref attribute reads a field on ANOTHER kind. That field is
		// as much of the mapped surface as a local one — leaving it out would let the
		// referent's schema drift under a fingerprint that claims to cover the
		// attribute, which is the exact hole D132 exists to close.
		if a.Op == "resolve-ref" && a.Ref != nil {
			rgvk, ok := findGVKSchema(schemas, a.Ref.Group, a.Ref.Version, a.Ref.Kind)
			if !ok {
				surface[path+" -> "+a.Ref.Kind+"."+a.Ref.Field] = "REFERENT-SCHEMA-ABSENT"
				continue
			}
			segs, err := mapping.ParseFieldPath(a.Ref.Field)
			if err != nil {
				return nil, err
			}
			rsig := "ABSENT"
			if s, ok := mapping.WalkSchemaPath(rgvk, schemas, segs); ok {
				rsig = s
			}
			surface[path+" -> "+a.Ref.Kind+"."+a.Ref.Field] = rsig
		}
	}
	// a lens's inputs are part of the mapped surface too — drift on a field a lens
	// reads must refuse the same as drift on a copy op's field.
	for _, name := range m.Lenses {
		for _, f := range lensRegistry[name].fields {
			sig, err := sigFor(f)
			if err != nil {
				return nil, err
			}
			surface["lens:"+name+":"+f] = sig
		}
	}
	return map[string]any{
		"kind":    m.Resource.Kind,
		"scope":   m.Resource.Scope,
		"plural":  m.Resource.Plural,
		"surface": surface,
	}, nil
}

// MappedSurfaceHash computes the mapped-surface fingerprint from a live OpenAPI
// components.schemas map. Used to author the pin and to check drift.
func (m *Mapping) MappedSurfaceHash(schemas map[string]any) (string, error) {
	model, err := mappedSurfaceModel(m, schemas)
	if err != nil {
		return "", err
	}
	return canonical.Hash(mappedSurfaceDomain, model)
}

// checkDrift compares the live schema's mapped surface against the pinned hash.
// Mapped-surface mismatch → a mapping-schema-drift error (fail closed). No pin →
// a loud diagnostic (unfingerprinted, per D75 skip-loudly for reads).
// guardDrift fetches the live schema for a mapping's GVK (cached per group/version)
// and checks drift. No fetcher configured → off (nil, nil), so the engine reads
// unfingerprinted and stays byte-identical to a hand-coded twin in tests. A fetch
// FAILURE is skip-loudly (a diagnostic, per D75) for a read; a mapped-surface
// mismatch is a hard refusal.
func (d *Driver) guardDrift(m *Mapping) ([]string, error) {
	if d.SchemaFetch == nil {
		return nil, nil
	}
	key := m.Resource.Group + "/" + m.Resource.Version
	if d.schemaCache == nil {
		d.schemaCache = map[string]map[string]any{}
	}
	schemas, ok := d.schemaCache[key]
	if !ok {
		s, err := d.SchemaFetch(m.Resource.Group, m.Resource.Version)
		if err != nil {
			return []string{"schema fingerprint UNCHECKED — could not fetch the API schema for " + key + " (" + err.Error() + "); reading without the drift guard"}, nil
		}
		schemas = s
		d.schemaCache[key] = s
	}
	// D551: a resolve-ref attribute's referent lives in another API group, whose
	// definitions are in a different OpenAPI document. Merge them in, or the
	// referent's signature fingerprints as ABSENT on every run and the pin stops
	// meaning anything about the half of the surface that is remote.
	merged, copied := schemas, false
	for _, a := range m.Attributes {
		if a.Op != "resolve-ref" || a.Ref == nil {
			continue
		}
		rkey := a.Ref.Group + "/" + a.Ref.Version
		if rkey == key {
			continue
		}
		rs, ok := d.schemaCache[rkey]
		if !ok {
			var err error
			rs, err = d.SchemaFetch(a.Ref.Group, a.Ref.Version)
			if err != nil {
				return []string{"schema fingerprint UNCHECKED for the referent " + rkey +
					" — could not fetch it: " + err.Error()}, nil
			}
			d.schemaCache[rkey] = rs
		}
		if !copied { // never mutate the cached document for the primary group
			m2 := make(map[string]any, len(schemas)+len(rs))
			for k, v := range schemas {
				m2[k] = v
			}
			merged, copied = m2, true
		}
		for k, v := range rs {
			merged[k] = v
		}
	}
	return m.checkDrift(merged)
}

func (m *Mapping) checkDrift(schemas map[string]any) ([]string, error) {
	got, err := m.MappedSurfaceHash(schemas)
	if err != nil {
		return nil, err
	}
	if m.Schema.MappedSurface == "" {
		return []string{"mapping declares no schema.mappedSurface fingerprint — drift is UNCHECKED (author the pin to enforce it)"}, nil
	}
	if got != m.Schema.MappedSurface {
		return nil, fmt.Errorf("%s: live schema mapped surface %s does not match the pinned %s — a mapped field changed type/enum or vanished; re-author the mapping, the engine will not reinterpret",
			perr.MappingSchemaDrift, got, m.Schema.MappedSurface)
	}
	return nil, nil
}
