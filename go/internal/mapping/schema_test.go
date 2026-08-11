package mapping

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// The OpenAPI drift-walker is the provider-agnostic algebra the drift fingerprint
// rests on (D175 mappedSurface, and the learn-from-API-contract direction). It is
// pinned here DIRECTLY rather than only through the k8s driver's golden fixtures:
// a shared layer that is exercised only via a consumer's fixtures loses coverage
// silently when those fixtures change. These assert the branches that decide
// whether the fingerprint sees drift — the exact places a false-alarm or a
// missed-drift hides.

// TypeSig reduces a node to type|format|sorted-enum. The enum MUST be canonical
// (sorted): a schema that reorders its enum is NOT semantic drift, so the two
// signatures must be identical. Description and unrelated keys are excluded.
func TestTypeSigCanonicalisesEnum(t *testing.T) {
	a := TypeSig(map[string]any{
		"type": "string", "format": "",
		"enum":        []any{"regional", "zonal", "multi-region"},
		"description": "some doc churn that must not affect the signature",
	})
	b := TypeSig(map[string]any{
		"type": "string",
		"enum": []any{"multi-region", "zonal", "regional"}, // reordered
	})
	if a != b {
		t.Errorf("enum reordering must not change the signature: %q != %q", a, b)
	}
	if want := "string||multi-region,regional,zonal"; a != want {
		t.Errorf("TypeSig = %q, want %q", a, want)
	}
}

func TestTypeSigTypeAndFormat(t *testing.T) {
	got := TypeSig(map[string]any{"type": "integer", "format": "int64"})
	if want := "integer|int64|"; got != want {
		t.Errorf("TypeSig = %q, want %q", got, want)
	}
	// A node with none of the three drift-relevant keys signs as empty separators —
	// stable, not a panic on missing keys.
	if got := TypeSig(map[string]any{"description": "x"}); got != "||" {
		t.Errorf("empty node TypeSig = %q, want %q", got, "||")
	}
}

// ResolveRef dereferences $ref against components.schemas; a $ref that names an
// absent schema returns the node UNCHANGED (fail-soft: the walker then finds no
// properties and reports the path absent, rather than following a phantom).
func TestResolveRef(t *testing.T) {
	schemas := map[string]any{
		"Quantity": map[string]any{"type": "string", "format": "quantity"},
	}
	resolved := ResolveRef(map[string]any{"$ref": "#/components/schemas/Quantity"}, schemas)
	if resolved["format"] != "quantity" {
		t.Errorf("ResolveRef did not dereference: %v", resolved)
	}
	// No $ref: returned unchanged.
	plain := map[string]any{"type": "boolean"}
	if got := ResolveRef(plain, schemas); got["type"] != "boolean" {
		t.Errorf("ResolveRef mangled a ref-less node: %v", got)
	}
	// $ref to a missing schema: node returned as-is (no phantom follow).
	dangling := map[string]any{"$ref": "#/components/schemas/DoesNotExist"}
	if got := ResolveRef(dangling, schemas); got["$ref"] == nil {
		t.Errorf("a dangling $ref must return the node unchanged, got %v", got)
	}
}

// WalkSchemaPath descends `properties` for named segments and
// `additionalProperties` for map-key segments, resolving $ref at each hop.
func TestWalkSchemaPath(t *testing.T) {
	schemas := map[string]any{
		"Quantity": map[string]any{"type": "string", "format": "quantity"},
	}
	root := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"spec": map[string]any{
				"type": "object",
				"properties": map[string]any{
					// a map whose values are a $ref — exercises additionalProperties + $ref
					"limits": map[string]any{
						"type":                 "object",
						"additionalProperties": map[string]any{"$ref": "#/components/schemas/Quantity"},
					},
					"replicas": map[string]any{"type": "integer", "format": "int32"},
				},
			},
		},
	}

	// Named descent to a leaf.
	if sig, ok := WalkSchemaPath(root, schemas, []string{"spec", "replicas"}); !ok || sig != "integer|int32|" {
		t.Errorf("replicas walk = (%q, %v)", sig, ok)
	}
	// Map-key descent (additionalProperties) then $ref resolution at the leaf.
	if sig, ok := WalkSchemaPath(root, schemas, []string{"spec", "limits", "cpu"}); !ok || sig != "string|quantity|" {
		t.Errorf("limits[cpu] walk = (%q, %v)", sig, ok)
	}
	// A segment that exists in neither properties nor additionalProperties: absent.
	if _, ok := WalkSchemaPath(root, schemas, []string{"spec", "nonexistent"}); ok {
		t.Errorf("a path through a missing property must report absent")
	}
}

// A real OpenAPI v3 server wraps a $ref in `allOf` whenever the property also
// carries a description or a default — an annotated reference cannot be spelled
// as a bare {"$ref": ...} because sibling keys next to $ref are ignored. This is
// what kube-openapi emits for essentially every `metadata` and `spec` property.
// Resolving only the bare form makes those paths read as ABSENT against every
// real server while hand-written fixtures using the bare form pass (D509).
func TestResolveRefUnwrapsAnAnnotatedReference(t *testing.T) {
	schemas := map[string]any{
		"ObjectMeta": map[string]any{
			"properties": map[string]any{
				"labels": map[string]any{
					"type":                 "object",
					"additionalProperties": map[string]any{"type": "string"},
				},
			},
		},
	}
	root := map[string]any{
		"properties": map[string]any{
			// exactly the shape a live API server emits
			"metadata": map[string]any{
				"description": "Standard object's metadata.",
				"default":     map[string]any{},
				"allOf":       []any{map[string]any{"$ref": "#/components/schemas/ObjectMeta"}},
			},
		},
	}
	segs, err := ParseFieldPath(`metadata.labels["pod-security.kubernetes.io/enforce"]`)
	if err != nil {
		t.Fatal(err)
	}
	sig, ok := WalkSchemaPath(root, schemas, segs)
	if !ok {
		t.Fatalf("annotated $ref did not resolve: the path reads as ABSENT, so every " +
			"mapping traversing a described `metadata`/`spec` drifts against a real server")
	}
	if sig == "" {
		t.Fatalf("resolved but produced an empty signature")
	}
}

// The composite case must NOT be silently flattened: an allOf with more than one
// member, or one that is not a plain reference, is a genuine composition this
// walker does not model — reporting ABSENT (fail closed) is the honest answer.
func TestResolveRefLeavesAGenuineCompositionAlone(t *testing.T) {
	schemas := map[string]any{"A": map[string]any{"properties": map[string]any{"x": map[string]any{"type": "string"}}}}
	node := map[string]any{"allOf": []any{
		map[string]any{"$ref": "#/components/schemas/A"},
		map[string]any{"properties": map[string]any{"y": map[string]any{"type": "string"}}},
	}}
	got := ResolveRef(node, schemas)
	if _, ok := got["properties"]; ok {
		t.Fatalf("a two-member allOf was flattened to one branch; composition is not modelled here")
	}
}

// A union type (`oneOf`/`anyOf`) carries no top-level `type`, so a signature
// built from type+format+enum alone reduces EVERY union to the same empty
// string — indistinguishable from a node with no type at all, and from any
// other union. Kubernetes uses unions for its most common scalars (Quantity is
// oneOf[string,number]; IntOrString), so the drift guard's whole promise — "a
// mapped field changed type/enum" — was unenforceable on exactly those fields
// (D509).
func TestTypeSigDistinguishesUnions(t *testing.T) {
	quantity := map[string]any{"oneOf": []any{
		map[string]any{"type": "string"}, map[string]any{"type": "number"}}}
	other := map[string]any{"oneOf": []any{
		map[string]any{"type": "string"}, map[string]any{"type": "boolean"}}}
	typeless := map[string]any{"description": "no type at all"}

	qs, os_, ts := TypeSig(quantity), TypeSig(other), TypeSig(typeless)
	if qs == ts {
		t.Errorf("a union signs identically to a typeless node (%q) — a field losing "+
			"its union entirely would not read as drift", qs)
	}
	if qs == os_ {
		t.Errorf("oneOf[string,number] and oneOf[string,boolean] share signature %q — "+
			"a union changing member types would not read as drift", qs)
	}
	// member order is an encoding detail, not drift
	swapped := map[string]any{"oneOf": []any{
		map[string]any{"type": "number"}, map[string]any{"type": "string"}}}
	if TypeSig(swapped) != qs {
		t.Errorf("member order changed the signature: %q vs %q", TypeSig(swapped), qs)
	}
}

// Pins are authored artefacts across every mapping; a signature change that
// touches non-union nodes would invalidate all of them at once. Nodes without a
// union must sign exactly as before.
func TestTypeSigIsUnchangedWithoutAUnion(t *testing.T) {
	for _, n := range []map[string]any{
		{"type": "string"},
		{"type": "string", "format": "date-time"},
		{"type": "string", "enum": []any{"b", "a"}},
		{},
	} {
		got := TypeSig(n)
		want := strOf(n["type"]) + "|" + strOf(n["format"]) + "|" + enumOfForTest(n)
		if got != want {
			t.Errorf("signature of a union-free node changed: got %q, want %q", got, want)
		}
	}
}

func enumOfForTest(n map[string]any) string {
	e, ok := n["enum"].([]any)
	if !ok {
		return ""
	}
	var out []string
	for _, x := range e {
		out = append(out, fmt.Sprintf("%v", x))
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}
