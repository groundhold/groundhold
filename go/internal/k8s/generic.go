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
	"net/url"
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
var closedOps = map[string]bool{"copy": true, "const": true, "quantity-int": true, "resolve-ref": true}

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
// refSpec (D551) declares a SECOND read: the mapped object names another object,
// and the attribute's real value lives there. Flux's Kustomization carries
// spec.sourceRef.name; the repo URL is on the GitRepository it names. Declaring the
// hop keeps it in the mapping document (reviewable, fingerprintable) instead of
// hiding it in Go, and keeps the closed-op discipline: one more NAMED op, not an
// expression language (invariant #4).
type refSpec struct {
	Group     string `yaml:"group"`
	Version   string `yaml:"version"`
	Kind      string `yaml:"kind"`
	Plural    string `yaml:"plural"`
	Scope     string `yaml:"scope"`
	Namespace string `yaml:"namespace"` // optional field path holding the referent's ns
	Field     string `yaml:"field"`     // what to read FROM the referent
}

type attrMap struct {
	Field      string   `yaml:"field"`
	Ref        *refSpec `yaml:"ref"`
	Op         string   `yaml:"op"`
	Type       string   `yaml:"type"`
	Value      any      `yaml:"value"`
	Derivation string   `yaml:"derivation"`
	Change     string   `yaml:"change"`
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
			return nil, fmt.Errorf("attribute %s: op %q is not in the closed set (copy, const, quantity-int, resolve-ref) — a richer op is a spec change, not an ad-hoc addition; conditional semantics belong in a NAMED LENS", path, a.Op)
		}
		if a.Op != "const" && a.Field == "" {
			return nil, fmt.Errorf("attribute %s: op %s requires a field path", path, a.Op)
		}
		if a.Op == "resolve-ref" {
			if a.Ref == nil {
				return nil, fmt.Errorf("attribute %s: op resolve-ref requires a ref block "+
					"naming the referent's group/version/kind/plural/scope and its field", path)
			}
			if a.Ref.Version == "" || a.Ref.Kind == "" || a.Ref.Plural == "" || a.Ref.Field == "" {
				return nil, fmt.Errorf("attribute %s: ref requires version, kind, plural and field "+
					"— a hop the document does not fully name cannot be reviewed or fingerprinted", path)
			}
			if a.Ref.Scope != "Namespaced" && a.Ref.Scope != "Cluster" {
				return nil, fmt.Errorf("attribute %s: ref.scope %q must be Namespaced or Cluster", path, a.Ref.Scope)
			}
		} else if a.Ref != nil {
			return nil, fmt.Errorf("attribute %s: op %s carries a ref block it will never read "+
				"— a declaration nothing acts on is a false statement about the mapping", path, a.Op)
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
// redactURLUserinfo drops any user:pass@ from an observed URL value before it becomes an
// observation. A URL's userinfo is a CREDENTIAL — an ArgoCD/Flux repoURL can carry an
// inline git token (https://user:ghp_xxx@github.com/...) — and is never
// capability-semantic. Observations are persisted to the ledger and republished by
// export/console, and unlike a mutation Reason they are never scrubbed downstream, so the
// strip happens here at the emit (D991). A non-string, a non-URL, or a URL with no
// userinfo is returned unchanged (only strings that parse as a URL WITH userinfo change).
func redactURLUserinfo(v any) any {
	s, ok := v.(string)
	if !ok {
		return v
	}
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return v
	}
	u.User = nil
	return u.String()
}

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
		// F-LC3: a BOUND resource the API server authoritatively 404s is GONE, and
		// the provider contract reserves one way to say so. This used to return a
		// bare diagnostic and NO observation — precisely what leaves a binding a
		// no-op forever: converge re-observes, learns nothing, and reports the world
		// as matching while the resource does not exist. Measured on a real cluster
		// (D513): five governance objects deleted with kubectl, converge CONVERGED.
		return []provider.Observation{
				{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
			}, []string{m.Resource.Kind + " not found — bound resource is gone (will re-create)"},
			nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("%s.get: HTTP %d", m.Resource.Plural, st)
	}
	var obj map[string]any
	if json.Unmarshal(body, &obj) != nil {
		return nil, nil, fmt.Errorf("%s.get: unreadable", m.Resource.Plural)
	}
	// Present: toggle the absence marker back OFF, so a stale "gone" reading from
	// an earlier observe cannot linger after a re-create and plan a second one.
	// The marker has to swing both ways or it is a one-way latch (F-LC3).
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
	}
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
				obs = append(obs, provider.Observation{Path: path, Value: redactURLUserinfo(v), Derivation: a.Derivation})
			}
		case "resolve-ref":
			v, diag, err := d.resolveRefValue(m, obj, ns, a)
			if err != nil {
				return nil, nil, err
			}
			if diag != "" {
				diags = append(diags, diag)
			}
			if v != nil {
				obs = append(obs, provider.Observation{Path: path, Value: redactURLUserinfo(v), Derivation: a.Derivation})
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
