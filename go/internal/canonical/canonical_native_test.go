package canonical

import "testing"

// A driver returns concrete Go types (a []string of cert SANs / SG rules /
// Bedrock destinationRegions, a map[string]string of tags) whereas YAML decoding
// yields []any / map[string]any. Both MUST canonicalize identically, or the same
// observed reality would hash two ways depending on its source — and the Go
// runtime would diverge from the Python reference (which sees every list the
// same). This pins the reflection-normalization that fixed the first user's
// "cannot canonicalize value of type []string" on `discover --provider aws`.

func TestCanonConcreteSliceEqualsGeneric(t *testing.T) {
	native, err := Canon([]string{"eu-central-1", "eu-west-1"})
	if err != nil {
		t.Fatalf("[]string must canonicalize: %v", err)
	}
	generic, err := Canon([]any{"eu-central-1", "eu-west-1"})
	if err != nil {
		t.Fatal(err)
	}
	if native != generic {
		t.Errorf("[]string %q != []any %q", native, generic)
	}
	// order is preserved (not sorted), like the []any path
	if want := `["eu-central-1","eu-west-1"]`; native != want {
		t.Errorf("got %q, want %q", native, want)
	}
}

func TestCanonConcreteSlicePreservesOrder(t *testing.T) {
	// lists are order-significant; a driver's [b,a] must not become [a,b]
	a, _ := Canon([]string{"b", "a"})
	b, _ := Canon([]any{"b", "a"})
	if a != b || a != `["b","a"]` {
		t.Errorf("order not preserved: %q vs %q", a, b)
	}
}

func TestCanonConcreteIntSlice(t *testing.T) {
	native, err := Canon([]int{3, 1, 2})
	if err != nil {
		t.Fatalf("[]int must canonicalize: %v", err)
	}
	generic, _ := Canon([]any{3, 1, 2})
	if native != generic {
		t.Errorf("[]int %q != []any %q", native, generic)
	}
}

func TestCanonConcreteMapEqualsGeneric(t *testing.T) {
	native, err := Canon(map[string]string{"env": "prod", "team": "core"})
	if err != nil {
		t.Fatalf("map[string]string must canonicalize: %v", err)
	}
	generic, _ := Canon(map[string]any{"env": "prod", "team": "core"})
	if native != generic {
		t.Errorf("map[string]string %q != map[string]any %q", native, generic)
	}
	// keys sorted, like the map[string]any path
	if want := `{"env":"prod","team":"core"}`; native != want {
		t.Errorf("got %q, want %q", native, want)
	}
}

func TestCanonNestedConcrete(t *testing.T) {
	// a realistic observation: a map whose value is a []string
	native, err := Canon(map[string]any{"destinationRegions": []string{"eu-central-1", "eu-west-1"}})
	if err != nil {
		t.Fatalf("nested []string must canonicalize: %v", err)
	}
	generic, _ := Canon(map[string]any{"destinationRegions": []any{"eu-central-1", "eu-west-1"}})
	if native != generic {
		t.Errorf("nested: %q != %q", native, generic)
	}
}

func TestHashConcreteSliceMatchesGeneric(t *testing.T) {
	h1, err := Hash("test", []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := Hash("test", []any{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("hash diverges by source type: %s vs %s", h1, h2)
	}
}
