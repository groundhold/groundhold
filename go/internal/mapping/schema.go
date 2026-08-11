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
//
// Two encodings mean the same thing and both must resolve (D509). A bare
// {"$ref": ...} carries no annotations, because sibling keys next to $ref are
// ignored by definition; so an API server that wants to describe the property —
// give it a description, a default — has no choice but to wrap the reference:
//
//	{"description": "...", "default": {}, "allOf": [{"$ref": "..."}]}
//
// That is what kube-openapi emits for essentially every `metadata` and `spec`
// property, so refusing to unwrap it made every mapped path that traverses one
// read as ABSENT against a real API server, while fixtures written in the bare
// form passed. A SINGLE-member allOf whose member is a plain reference is that
// annotated form and nothing else; two members, or one that carries its own
// properties, is a genuine composition this walker does not model and must not
// flatten — the caller reports ABSENT and fails closed, which stays correct.
func ResolveRef(node, schemas map[string]any) map[string]any {
	if ref, ok := node["$ref"].(string); ok {
		return derefName(ref, node, schemas)
	}
	if all, ok := node["allOf"].([]any); ok && len(all) == 1 {
		if only, ok := all[0].(map[string]any); ok && len(only) == 1 {
			if ref, ok := only["$ref"].(string); ok {
				return derefName(ref, node, schemas)
			}
		}
	}
	return node
}

// derefName looks a reference target up by its trailing name, returning the
// original node untouched when the target is absent from the document.
func derefName(ref string, node map[string]any, schemas map[string]any) map[string]any {
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
// enum, and — when the node is a union — its members. Description and other doc
// churn are excluded, they are not semantic drift.
//
// The union component is appended ONLY when the node has one (D509). A union node
// carries no top-level `type`, so without it every `oneOf`/`anyOf` reduced to the
// same empty signature: indistinguishable from a typeless node and from any other
// union, on exactly the fields Kubernetes models this way (Quantity is
// oneOf[string,number]; IntOrString). The drift guard promises to catch "a mapped
// field changed type/enum", and on those fields it could not. Appending only when
// present keeps every union-free node signing byte-identically, so the pins
// authored across the mappings stay valid.
func TypeSig(node map[string]any) string {
	var enum []string
	if e, ok := node["enum"].([]any); ok {
		for _, x := range e {
			enum = append(enum, fmt.Sprintf("%v", x))
		}
		sort.Strings(enum)
	}
	sig := strOf(node["type"]) + "|" + strOf(node["format"]) + "|" + strings.Join(enum, ",")
	if u := unionSig(node); u != "" {
		sig += "|" + u
	}
	return sig
}

// unionSig signs a oneOf/anyOf node by its members' own signatures, sorted so the
// encoding's member ORDER is not mistaken for drift. Empty when the node is not a
// union.
func unionSig(node map[string]any) string {
	for _, kw := range []string{"oneOf", "anyOf"} { // deterministic, not map order
		members, ok := node[kw].([]any)
		if !ok || len(members) == 0 {
			continue
		}
		var sigs []string
		for _, m := range members {
			mm, ok := m.(map[string]any)
			if !ok {
				continue
			}
			sigs = append(sigs, TypeSig(mm))
		}
		sort.Strings(sigs)
		return kw + ":" + strings.Join(sigs, ",")
	}
	return ""
}
