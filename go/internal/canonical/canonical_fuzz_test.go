package canonical

import "testing"

// The bug that shipped — "cannot canonicalize value of type []string" — existed
// because the whole test corpus (conformance + differential) feeds YAML, which
// decodes to []any/map[string]any; the native Go types drivers actually emit
// ([]string, []int, map[string]string) never crossed the canonicalizer. This
// fuzz closes that blind spot: it builds values in NATIVE Go types across the
// value domain a driver can produce and asserts Canon is TOTAL (never errors)
// and deterministic, and that a native value hashes identically to its generic
// ([]any/map[string]any) twin. A new driver returning a fresh concrete type is
// caught here, before release, not by the first user on real cloud.
func FuzzCanonTotalOverNativeTypes(f *testing.F) {
	for _, seed := range [][]byte{{}, {0}, {1, 2, 3}, {7, 3, 9, 1}, {255, 128, 64}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, seed []byte) {
		v := buildNative(seed, 0)
		s1, err := Canon(v)
		if err != nil {
			t.Fatalf("Canon must be total over driver-plausible values, failed on %#v: %v", v, err)
		}
		if s2, _ := Canon(v); s1 != s2 {
			t.Fatalf("Canon not deterministic for %#v", v)
		}
		// a native value must hash identically to its generic twin
		g := toGeneric(v)
		sg, err := Canon(g)
		if err != nil {
			t.Fatalf("generic twin failed: %v", err)
		}
		if s1 != sg {
			t.Fatalf("native/generic divergence: %q vs %q", s1, sg)
		}
	})
}

// buildNative deterministically constructs a value in native Go types from seed
// bytes, biased toward the concrete slices/maps drivers emit.
func buildNative(seed []byte, depth int) any {
	if len(seed) == 0 {
		return ""
	}
	b := seed[0]
	rest := seed[1:]
	if depth >= 3 {
		b %= 6 // stop descending into containers
	}
	switch b % 9 {
	case 0:
		return string(rune('a' + int(b%26)))
	case 1:
		return int(b)
	case 2:
		return int64(b) * 1000
	case 3:
		return b%2 == 0
	case 4:
		return float64(b) / 4
	case 5:
		return nil
	case 6:
		out := make([]string, 0, len(rest)%4)
		for i := 0; i < len(rest)%4; i++ {
			out = append(out, string(rune('a'+i)))
		}
		return out
	case 7:
		out := make([]int, 0, len(rest)%4)
		for i := 0; i < len(rest)%4; i++ {
			out = append(out, i)
		}
		return out
	default:
		out := map[string]any{}
		for i := 0; i < len(rest)%3; i++ {
			out[string(rune('k'+i))] = buildNative(rest[i:], depth+1)
		}
		return out
	}
}

// toGeneric converts native containers to []any/map[string]any — the shape YAML
// decoding would have produced — so we can prove the two hash the same.
func toGeneric(v any) any {
	switch x := v.(type) {
	case []string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = e
		}
		return out
	case []int:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = e
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = toGeneric(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = toGeneric(e)
		}
		return out
	default:
		return v
	}
}
