package mapping

import "testing"

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
