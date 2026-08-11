// D551: the declared second read. An attribute whose value lives on ANOTHER object
// the mapped one names — Flux's Kustomization points at a GitRepository, and the
// repo URL (the whole point of source.repoURL) is over there. Before this, the
// mapping copied the referent's NAME into a path that promises a URL and marked it
// `measured`, which made the neutral GitOps capability non-portable between its two
// controllers and turned provenance into a local label.
package k8s

import (
	"encoding/json"
	"fmt"
	"net/http"

	"groundhold/internal/mapping"
)

// refPath builds the referent's object path. It mirrors Mapping.objectPath rather
// than reusing it: the referent is a different GVK with its own scope, and pretending
// otherwise is how a hop silently reads the wrong collection.
func (r *refSpec) objectPath(namespace, name string) string {
	base := "/apis/" + r.Group + "/" + r.Version
	if r.Group == "" || r.Group == "core" {
		base = "/api/" + r.Version
	}
	if r.Scope == "Namespaced" {
		return base + "/namespaces/" + namespace + "/" + r.Plural + "/" + name
	}
	return base + "/" + r.Plural + "/" + name
}

// resolveRefValue performs the hop. It returns (value, diagnostic, error):
//
//   - the referent's field           -> value
//   - the ref is absent/unresolvable -> "" value + a diagnostic NAMING what was
//     missing, never a fabricated value and never silence (D522: a read that failed
//     and said nothing is indistinguishable from a world that is empty)
//   - transport failure              -> a hard error, exactly as the primary read
//
// The namespace defaults to the referring object's own, which is what every k8s
// controller does with an unqualified ref; a mapping may name a field carrying an
// explicit namespace instead.
func (d *Driver) resolveRefValue(m *Mapping, obj map[string]any, ns string, a attrMap) (any, string, error) {
	nameVal, ok, err := mapping.ResolveField(obj, a.Field)
	if err != nil {
		return nil, "", err
	}
	if !ok {
		return nil, fmt.Sprintf("%s: %s names no referent — nothing to resolve", a.Field, m.Resource.Kind), nil
	}
	name, _ := nameVal.(string)
	if name == "" {
		return nil, fmt.Sprintf("%s: referent name is empty or not a string — not represented", a.Field), nil
	}
	refNS := ns
	if a.Ref.Namespace != "" {
		if v, ok, err := mapping.ResolveField(obj, a.Ref.Namespace); err == nil && ok {
			if s, _ := v.(string); s != "" {
				refNS = s
			}
		}
	}
	st, body, err := d.call("GET", a.Ref.objectPath(refNS, name), nil)
	if err != nil {
		return nil, "", fmt.Errorf("%s/%s.get: unreadable (transport or permission) — not an observation: %w",
			a.Ref.Plural, name, err)
	}
	if st == http.StatusNotFound {
		return nil, fmt.Sprintf("%s %q referenced by %s does not exist — %s not represented",
			a.Ref.Kind, name, a.Field, a.Ref.Field), nil
	}
	if st != http.StatusOK {
		return nil, fmt.Sprintf("%s %q: HTTP %d — %s not represented (the referent was NOT read)",
			a.Ref.Kind, name, st, a.Ref.Field), nil
	}
	var refObj map[string]any
	if json.Unmarshal(body, &refObj) != nil {
		return nil, fmt.Sprintf("%s %q: unreadable — %s not represented", a.Ref.Kind, name, a.Ref.Field), nil
	}
	v, ok, err := mapping.ResolveField(refObj, a.Ref.Field)
	if err != nil {
		return nil, "", err
	}
	if !ok {
		return nil, fmt.Sprintf("%s %q carries no %s — not represented", a.Ref.Kind, name, a.Ref.Field), nil
	}
	return v, "", nil
}
