// The schema-driven generic engine (learn-from-API-contract, Shape C). A MAPPING
// document promotes a vocabulary's `mappings:` table from prose to DATA: it names
// the resource's mechanical profile (GVK, plural, scope — machine-authoritative)
// and the SEMANTIC attribute↔field bindings (human-authored). The engine reads any
// mapped resource with a CLOSED operator set — copy / const / quantity-int at v0.1;
// anything conditional is a NAMED LENS (an in-tree Go function), never an inline
// expression (invariant #4 at the driver layer). It derives no meaning: a field
// becomes an attribute only because a human bound it AND the attribute exists in the
// capability vocabulary. Slice 1 is observe-only, differentially pinned byte-for-byte
// against the hand-coded driver, which is the oracle.
package k8s

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"groundhold/internal/mapping"
	"groundhold/internal/provider"
)

const (
	mappingAlgebra   = "v0.1"
	fieldpathAlgebra = "groundhold/fieldpath/v1"
)

// closedOps is the whole operator set at v0.1. Growing it is a spec change with a
// conformance case + a DESIGN entry (invariant #5) — never an ad-hoc addition.
var closedOps = map[string]bool{"copy": true, "const": true, "quantity-int": true}

type Mapping struct {
	Mapping    string             `yaml:"mapping"`
	FieldPath  string             `yaml:"fieldpath"`
	Service    string             `yaml:"service"`
	Provider   string             `yaml:"provider"`
	Capability string             `yaml:"capability"`
	Resource   resourceProfile    `yaml:"resource"`
	Schema     schemaPin          `yaml:"schema"`
	Lenses     []string           `yaml:"lenses"`
	Attributes map[string]attrMap `yaml:"attributes"`
	// Classify gives the change class for paths a LENS emits (which are not
	// op-attributes, so ClassifyChange cannot read their class from Attributes).
	// Without it a changed lens path returns "unsupported", which the compiler
	// treats as a hard error — so a lens-based mapping must declare its paths here.
	Classify map[string]classifyRule `yaml:"classify"`
}

// classifyRule is a lens path's change class + the note carried into the plan.
type classifyRule struct {
	Change string `yaml:"change"` // mutable | immutable | caveated
	Reason string `yaml:"reason"`
}

// resourceProfile is the MACHINE-authoritative half: a projection of the API
// contract. A human editing it is the bug; it is regenerated, never re-reviewed.
type resourceProfile struct {
	Group   string `yaml:"group"`
	Version string `yaml:"version"`
	Kind    string `yaml:"kind"`
	Plural  string `yaml:"plural"`
	Scope   string `yaml:"scope"` // Namespaced | Cluster
}

// attrMap is one HUMAN-authored semantic binding.
type attrMap struct {
	Field      string `yaml:"field"`
	Op         string `yaml:"op"`
	Type       string `yaml:"type"`
	Value      any    `yaml:"value"`
	Derivation string `yaml:"derivation"`
	Change     string `yaml:"change"`
}

// loadMapping parses + validates a mapping document. It refuses an unknown algebra
// by NAME (D132: no silent interpretation drift) and an op outside the closed set.
func loadMapping(data []byte) (*Mapping, error) {
	var m Mapping
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.Mapping != mappingAlgebra {
		return nil, fmt.Errorf("mapping algebra %q is not %q — refusing to guess (D132)", m.Mapping, mappingAlgebra)
	}
	if m.FieldPath != fieldpathAlgebra {
		return nil, fmt.Errorf("fieldpath algebra %q is not %q", m.FieldPath, fieldpathAlgebra)
	}
	if m.Resource.Scope != "Namespaced" && m.Resource.Scope != "Cluster" {
		return nil, fmt.Errorf("resource.scope %q must be Namespaced or Cluster", m.Resource.Scope)
	}
	for _, name := range m.Lenses {
		if _, ok := lensRegistry[name]; !ok {
			return nil, fmt.Errorf("lens %q is not registered — refusing by name (a lens is in-tree Go, not a mapping directive; D132)", name)
		}
	}
	for path, a := range m.Attributes {
		if !closedOps[a.Op] {
			return nil, fmt.Errorf("attribute %s: op %q is not in the closed set (copy, const, quantity-int) — a richer op is a spec change, not an ad-hoc addition; conditional semantics belong in a NAMED LENS", path, a.Op)
		}
		if a.Op != "const" && a.Field == "" {
			return nil, fmt.Errorf("attribute %s: op %s requires a field path", path, a.Op)
		}
		if a.Derivation == "" {
			return nil, fmt.Errorf("attribute %s: derivation is required (measured | config-intent | ...)", path)
		}
	}
	for path, c := range m.Classify {
		switch c.Change {
		case "mutable", "immutable", "caveated":
		default:
			return nil, fmt.Errorf("classify %s: change %q must be mutable, immutable or caveated", path, c.Change)
		}
	}
	return &m, nil
}

// parseProviderID splits a providerId using the mapping's OWN scope — not the
// hard-coded isNamespacedKind list — so the engine parses a CRD's identity from
// the mapping, never a built-in table. Namespaced: <group>/<version>/<Kind>/<ns>/
// <name>; Cluster: <group>/<version>/<Kind>/<name>.
func (m *Mapping) parseProviderID(providerID string) (namespace, name string, err error) {
	parts := strings.Split(providerID, "/")
	ns := m.Resource.Scope == "Namespaced"
	want, shape := 4, "<group>/<version>/<Kind>/<name>"
	if ns {
		want, shape = 5, "<group>/<version>/<Kind>/<namespace>/<name>"
	}
	if len(parts) != want {
		return "", "", fmt.Errorf("providerId %q is not %s", providerID, shape)
	}
	if parts[2] != m.Resource.Kind {
		return "", "", fmt.Errorf("providerId kind %q is not %s", parts[2], m.Resource.Kind)
	}
	if ns {
		namespace, name = parts[3], parts[4]
		if !k8sNameOK.MatchString(namespace) {
			return "", "", fmt.Errorf("providerId namespace %q is invalid", namespace)
		}
	} else {
		name = parts[3]
	}
	if !k8sNameOK.MatchString(name) {
		return "", "", fmt.Errorf("providerId name %q is invalid", name)
	}
	return namespace, name, nil
}

// objectPath builds the REST path for one object from the resource profile: core
// group (empty) uses /api/v1, everything else /apis/<group>/<version>; namespaced
// kinds carry the namespace segment.
func (m *Mapping) objectPath(namespace, name string) string {
	base := "/apis/" + m.Resource.Group + "/" + m.Resource.Version
	if m.Resource.Group == "" || m.Resource.Group == "core" {
		base = "/api/" + m.Resource.Version
	}
	if m.Resource.Scope == "Namespaced" {
		return base + "/namespaces/" + namespace + "/" + m.Resource.Plural + "/" + name
	}
	return base + "/" + m.Resource.Plural + "/" + name
}

// collectionPath builds the LIST path for a mapped kind's collection. A namespaced
// kind with an empty namespace lists cluster-wide (all namespaces) — the same
// shape the RBAC sweep uses; a concrete namespace narrows to it.
func (m *Mapping) collectionPath(namespace string) string {
	base := "/apis/" + m.Resource.Group + "/" + m.Resource.Version
	if m.Resource.Group == "" || m.Resource.Group == "core" {
		base = "/api/" + m.Resource.Version
	}
	if m.Resource.Scope == "Namespaced" && namespace != "" {
		return base + "/namespaces/" + namespace + "/" + m.Resource.Plural
	}
	return base + "/" + m.Resource.Plural
}

// buildProviderID composes the mapping's providerId for a discovered object — the
// inverse of parseProviderID, so a sweep's Discovered can be observed/adopted
// verbatim through the same generic path.
func (m *Mapping) buildProviderID(namespace, name string) string {
	if m.Resource.Scope == "Namespaced" {
		return m.Resource.Group + "/" + m.Resource.Version + "/" + m.Resource.Kind + "/" + namespace + "/" + name
	}
	return m.Resource.Group + "/" + m.Resource.Version + "/" + m.Resource.Kind + "/" + name
}

// observeMapped is the generic reverse-map: GET the object, apply each attribute's
// closed op. It reproduces a hand-coded observe exactly; the differential test pins
// that. It emits no value it cannot resolve (never a fabricated fact).
func (d *Driver) observeMapped(m *Mapping, providerID string) ([]provider.Observation, []string, error) {
	ns, name, err := m.parseProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	// D132 drift guard: refuse before reading if the live schema diverged inside
	// the mapped surface. Off when no fetcher is configured (reads unfingerprinted).
	driftDiags, err := d.guardDrift(m)
	if err != nil {
		return nil, nil, err
	}
	st, body, err := d.call("GET", m.objectPath(ns, name), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%s.get: unreadable (transport or permission) — not an observation", m.Resource.Plural)
	}
	if st == http.StatusNotFound {
		return nil, []string{m.Resource.Kind + " not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("%s.get: HTTP %d", m.Resource.Plural, st)
	}
	var obj map[string]any
	if json.Unmarshal(body, &obj) != nil {
		return nil, nil, fmt.Errorf("%s.get: unreadable", m.Resource.Plural)
	}
	var obs []provider.Observation
	diags := append([]string(nil), driftDiags...)
	// Lenses run FIRST (conditional semantics), then the closed ops — so a
	// hand-coded twin that emits its conditional facts before its literals is
	// reproduced in order.
	for _, name := range m.Lenses {
		lObs, lDiags := lensRegistry[name].fn(obj)
		obs = append(obs, lObs...)
		diags = append(diags, lDiags...)
	}
	for _, path := range sortedAttrKeys(m.Attributes) {
		a := m.Attributes[path]
		switch a.Op {
		case "const":
			obs = append(obs, provider.Observation{Path: path, Value: a.Value, Derivation: a.Derivation})
		case "copy":
			v, ok, err := mapping.ResolveField(obj, a.Field)
			if err != nil {
				return nil, nil, err
			}
			if ok {
				obs = append(obs, provider.Observation{Path: path, Value: v, Derivation: a.Derivation})
			}
		case "quantity-int":
			v, ok, err := mapping.ResolveField(obj, a.Field)
			if err != nil {
				return nil, nil, err
			}
			if ok {
				s, _ := v.(string)
				if n, e := strconv.Atoi(s); e == nil {
					obs = append(obs, provider.Observation{Path: path, Value: n, Derivation: a.Derivation})
				} else {
					diags = append(diags, path+": "+s+" is not an integer — not represented")
				}
			}
		}
	}
	return obs, diags, nil
}

func sortedAttrKeys(m map[string]attrMap) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// fieldpath/v1 parsing, value resolution, and field-setting now live in the
// provider-agnostic internal/mapping package (mapping.ParseFieldPath /
// ResolveField / SetField) — the universal layer this shell consumes.
