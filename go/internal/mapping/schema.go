// The pure OpenAPI schema drift-walker. It knows nothing of Kubernetes: how a
// resource's schema NODE is located (the k8s x-kubernetes-group-version-kind
// marker) stays in the shell and is passed the located root. These three functions
// resolve $ref, follow a fieldpath through properties/additionalProperties, and
// reduce a node to its drift-relevant signature. They are provider-agnostic — any
// OpenAPI-described API reuses them.
package mapping

import (
	"fmt"
	"sort"
	"strings"
)

func strOf(v any) string { s, _ := v.(string); return s }

// ResolveRef dereferences a `$ref` node against the components.schemas map. A node
// with no $ref is returned unchanged.
func ResolveRef(node, schemas map[string]any) map[string]any {
	ref, ok := node["$ref"].(string)
	if !ok {
		return node
	}
	name := ref[strings.LastIndex(ref, "/")+1:]
	if s, ok := schemas[name].(map[string]any); ok {
		return s
	}
	return node
}

// WalkSchemaPath follows a fieldpath through the schema — descending object
// `properties` for named segments, `additionalProperties` for map-key segments,
// resolving `$ref` at each hop. Returns the terminal node's drift signature and
// whether the whole path exists.
func WalkSchemaPath(root, schemas map[string]any, segs []string) (sig string, ok bool) {
	cur := ResolveRef(root, schemas)
	for _, seg := range segs {
		cur = ResolveRef(cur, schemas)
		if props, _ := cur["properties"].(map[string]any); props != nil {
			if next, ok := props[seg].(map[string]any); ok {
				cur = next
				continue
			}
		}
		if ap, ok := cur["additionalProperties"].(map[string]any); ok {
			cur = ap // the segment is a map key; its value schema is additionalProperties
			continue
		}
		return "", false
	}
	return TypeSig(ResolveRef(cur, schemas)), true
}

// TypeSig is the drift-relevant signature of a schema node: type + format + sorted
// enum. Description and other doc churn are excluded — not semantic drift.
func TypeSig(node map[string]any) string {
	var enum []string
	if e, ok := node["enum"].([]any); ok {
		for _, x := range e {
			enum = append(enum, fmt.Sprintf("%v", x))
		}
		sort.Strings(enum)
	}
	return strOf(node["type"]) + "|" + strOf(node["format"]) + "|" + strings.Join(enum, ",")
}
