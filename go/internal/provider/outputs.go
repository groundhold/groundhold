// Typed-output helpers shared by the executor, observe and the compiler
// (D226/D275/D283). One kind-check, three consumers — the executor filtering a
// create result, observe recording a bound resource's outputs, the compiler
// folding a reference from an observation — so no two of them can drift on
// what a "list" output is.
package provider

import "fmt"

// OutputReader is the OPTIONAL read-side twin of OutputProducer (D283):
// re-read the DECLARED outputs of a BOUND resource by its provider id, so
// `observe` can record them and the compiler can FOLD a reference to an
// already-bound producer from a fresh observation instead of refusing.
// Strictly read-only. A driver without it simply yields no output
// observations, and a fold against it refuses observation-required.
type OutputReader interface {
	ReadOutputs(service, providerID string) (map[string]any, error)
}

// OutputValueOfKind normalizes an output value against its declared
// scalars.Kind — string and list-of-strings are the D226 v0 output surface.
// No coercion (invariant #2): a mismatch is an error, never a conversion. An
// empty list is a fact the consumer's driver may still refuse; an empty
// string is never a usable identity and fails here.
func OutputValueOfKind(v any, kind string) (any, string) {
	switch kind {
	case "string":
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, fmt.Sprintf("expected a non-empty string, got %T", v)
		}
		return s, ""
	case "list":
		var items []any
		switch t := v.(type) {
		case []any:
			items = t
		case []string:
			items = make([]any, len(t))
			for i, s := range t {
				items[i] = s
			}
		default:
			return nil, fmt.Sprintf("expected a list, got %T", v)
		}
		out := make([]any, len(items))
		for i, it := range items {
			s, ok := it.(string)
			if !ok || s == "" {
				return nil, fmt.Sprintf(
					"expected a list of non-empty strings, element %d is %T", i, it)
			}
			out[i] = s
		}
		return out, ""
	default:
		return nil, fmt.Sprintf("unsupported output kind %q", kind)
	}
}

// ReadOutputs (D283): the fake's outputs are a pure function of the provider
// id, exactly as its Create derives them from the idempotency key — so a
// bound fake resource re-reads the same set its create receipted.
func (f *Fake) ReadOutputs(service, providerID string) (map[string]any, error) {
	// "empty:" models a structurally BLIND capability: paired with Observe
	// returning nothing, it yields no outputs either, so a bound resource reads
	// cleanly yet empty — observe records it as observed-but-empty, the F16/F25
	// residual signal the compiler isolates on instead of freezing.
	if len(providerID) >= 6 && providerID[:6] == "empty:" {
		return map[string]any{}, nil
	}
	key := providerID
	if len(key) > 5 && key[:5] == "fake:" {
		key = key[5:]
	}
	if key == "" {
		return nil, fmt.Errorf("fake: providerId %q carries no key", providerID)
	}
	out := map[string]any{
		"id":               "fake:" + key,
		"selfLink":         "fake://net/" + key,
		"endpoint":         key + ".fake.internal",
		"privateSubnetIds": []any{"subnet-" + key + "-a", "subnet-" + key + "-b"},
	}
	for k, v := range fakeEdgeValues(service, key) {
		out[k] = v
	}
	return out, nil
}
