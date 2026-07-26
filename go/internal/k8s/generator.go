// Offline mapping-skeleton generator (learn-from-API-contract). It crawls the
// cluster's machine contract — the API discovery list (for plural + scope) and the
// OpenAPI schema (for the field tree) — and emits the MACHINE-authoritative half of
// a mapping: the `resource:` profile plus a commented, unranked field inventory in
// schema order. It emits NOTHING normative: no attribute mapping, not even a ranked
// suggestion, because a pre-selected list gets rubber-stamped. A human then authors
// the `attributes:` block (which fields are the SEMANTICS an org contracts), and a
// field enters only when a human binds it AND it exists in the capability vocab.
package k8s

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"groundhold/internal/mapping"
)

// apiResource is one entry of an APIResourceList: the plural name + scope groundhold
// cannot derive from the OpenAPI schema alone.
type apiResource struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Namespaced bool   `json:"namespaced"`
}

func (d *Driver) fetchAPIResources(group, version string) ([]apiResource, error) {
	path := "/apis/" + group + "/" + version
	if group == "" || group == "core" {
		path = "/api/" + version
	}
	st, body, err := d.call("GET", path, nil)
	if err != nil {
		return nil, err
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", path, st)
	}
	var doc struct {
		Resources []apiResource `json:"resources"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil, fmt.Errorf("%s: unreadable", path)
	}
	return doc.Resources, nil
}

// profileFor derives the machine-authoritative resource profile from the discovery
// list — the plural (a subresource like "roles/status" is skipped) and the scope.
func profileFor(resources []apiResource, group, version, kind string) (resourceProfile, error) {
	for _, r := range resources {
		if r.Kind == kind && !strings.Contains(r.Name, "/") {
			scope := "Cluster"
			if r.Namespaced {
				scope = "Namespaced"
			}
			return resourceProfile{Group: group, Version: version, Kind: kind, Plural: r.Name, Scope: scope}, nil
		}
	}
	return resourceProfile{}, fmt.Errorf("kind %q not found in the %s/%s discovery list", kind, group, version)
}

// fieldInventory walks the GVK schema and returns every LEAF field path with its
// type signature, in sorted order — the raw menu a human picks from. Recursion is
// depth-bounded (k8s schemas are cyclic via metadata/ownerReferences).
func fieldInventory(gvk, schemas map[string]any) []string {
	var out []string
	var walk func(prefix string, node map[string]any, depth int)
	walk = func(prefix string, node map[string]any, depth int) {
		if depth > 5 {
			return
		}
		node = mapping.ResolveRef(node, schemas)
		if props, ok := node["properties"].(map[string]any); ok {
			keys := make([]string, 0, len(props))
			for k := range props {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				child, _ := props[k].(map[string]any)
				childR := mapping.ResolveRef(child, schemas)
				path := k
				if prefix != "" {
					path = prefix + "." + k
				}
				if _, hasProps := childR["properties"]; hasProps {
					walk(path, childR, depth+1)
				} else if _, hasMap := childR["additionalProperties"]; hasMap {
					walk(path+`["*"]`, childR, depth+1)
				} else {
					out = append(out, path+": "+mapping.TypeSig(childR))
				}
			}
		} else if ap, ok := node["additionalProperties"].(map[string]any); ok {
			apR := mapping.ResolveRef(ap, schemas)
			if _, hasProps := apR["properties"]; hasProps {
				walk(prefix, apR, depth+1)
			} else {
				out = append(out, prefix+": "+mapping.TypeSig(apR))
			}
		}
	}
	walk("", gvk, 0)
	sort.Strings(out)
	return out
}

// renderSkeleton emits the mapping-skeleton YAML: the machine-authoritative profile
// + the commented field inventory + an EMPTY attributes block for the human to
// author. It never writes an attribute.
func renderSkeleton(p resourceProfile, gvk, schemas map[string]any, service, capability string) string {
	var b strings.Builder
	b.WriteString("# Mapping SKELETON (machine-generated). The `resource:` block is a projection\n")
	b.WriteString("# of the API contract — keep it, regenerate it, never hand-edit it. The field\n")
	b.WriteString("# inventory below is the RAW menu, unranked and in schema order; it is NOT a\n")
	b.WriteString("# suggestion. YOU author the `attributes:` block: which fields are the SEMANTICS\n")
	b.WriteString("# an organization contracts, each bound to a vocabulary attribute. A field\n")
	b.WriteString("# enters ONLY when you bind it AND the attribute exists in the capability vocab.\n")
	b.WriteString("# Conditional/structural fields (arrays, defaults) need a named lens, not an op.\n")
	b.WriteString("# After authoring, compute schema.mappedSurface (the drift fingerprint).\n")
	b.WriteString("mapping: " + mappingAlgebra + "\n")
	b.WriteString("fieldpath: " + fieldpathAlgebra + "\n")
	b.WriteString("service: " + service + "\n")
	b.WriteString("provider: k8s\n")
	b.WriteString("capability: " + capability + "\n")
	b.WriteString("vocab:\n  " + capability + ": \"0.1\"\n\n")
	b.WriteString("resource:\n")
	b.WriteString("  group: \"" + p.Group + "\"\n")
	b.WriteString("  version: " + p.Version + "\n")
	b.WriteString("  kind: " + p.Kind + "\n")
	b.WriteString("  plural: " + p.Plural + "\n")
	b.WriteString("  scope: " + p.Scope + "\n\n")
	b.WriteString("schema:\n")
	b.WriteString("  source: \"kubernetes /openapi/v3 " + p.Kind + "\"\n")
	b.WriteString("  mappedSurface: \"\"   # compute after authoring attributes\n\n")
	b.WriteString("# --- field inventory (raw menu; type|format|enum) -------------------------\n")
	for _, f := range fieldInventory(gvk, schemas) {
		b.WriteString("#   " + f + "\n")
	}
	b.WriteString("# -------------------------------------------------------------------------\n\n")
	b.WriteString("lenses: []\n")
	b.WriteString("attributes: {}   # author me\n")
	return b.String()
}

// SkeletonFor fetches the discovery list + OpenAPI schema for a GVK and renders the
// mapping skeleton. Offline scaffolding — it writes nothing to the cluster and
// produces nothing normative.
func (d *Driver) SkeletonFor(group, version, kind, service, capability string) (string, error) {
	if d.SchemaFetch == nil {
		return "", fmt.Errorf("SkeletonFor needs a schema fetcher")
	}
	resources, err := d.fetchAPIResources(group, version)
	if err != nil {
		return "", err
	}
	p, err := profileFor(resources, group, version, kind)
	if err != nil {
		return "", err
	}
	schemas, err := d.SchemaFetch(group, version)
	if err != nil {
		return "", err
	}
	gvk, ok := findGVKSchema(schemas, group, version, kind)
	if !ok {
		return "", fmt.Errorf("no OpenAPI schema for %s %s/%s", kind, group, version)
	}
	return renderSkeleton(p, gvk, schemas, service, capability), nil
}
