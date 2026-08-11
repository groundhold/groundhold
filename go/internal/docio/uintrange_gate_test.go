package docio

import (
	"strings"
	"testing"
)

// D684. `spec/canonicalization.md`: "Both implementations refuse such a value at
// LOAD ... as a structural error". The switch had arms for `int`, `int64` and
// `float64` — and yaml.v3 decodes an integer past int64 as **uint64**, which fell
// through every arm. Measured:
//
//	gh validate u2.yaml   OK  contract t v1: 1 capabilities, 0 constraints   exit 0
//	gh hash u2.yaml       document error: cannot canonicalize value of type uint64
//	ref                   REFUSED: integer 18446744073709551615 exceeds the
//	                      JSON-safe range (2^53)
//
// It failed closed downstream, so nothing unsafe shipped — but with the wrong
// error, from the wrong layer, naming a Go type instead of the operator's number,
// and without the remediation this gate's message carries. The reference refused it
// correctly all along, so the two implementations disagreed about WHERE a document
// is rejected.
func TestAnIntegerPastInt64IsRefusedAtLoad(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  any
	}{
		{"uint64 leaf", map[string]any{"x": uint64(18446744073709551615)}},
		{"uint64 in a list", map[string]any{"x": []any{uint64(9007199254740993)}}},
		{"uint leaf", map[string]any{"x": uint(9007199254740993)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckSafeNumbers(tc.doc)
			if err == nil {
				t.Fatal("an integer past the JSON-safe range passed the LOAD gate — " +
					"the spec says both implementations refuse it here, and the " +
					"refusal that does arrive later names a Go type")
			}
			if !strings.Contains(err.Error(), "JSON-safe range") {
				t.Errorf("the refusal does not carry this gate's message: %v", err)
			}
		})
	}

	// The control: values inside the safe range, and the boundary itself, still load.
	for _, ok := range []any{
		map[string]any{"x": uint64(9007199254740991)}, // 2^53 - 1
		map[string]any{"x": uint(42)},
		map[string]any{"x": 42},
		map[string]any{"x": 1.5},
	} {
		if err := CheckSafeNumbers(ok); err != nil {
			t.Errorf("a safe value was refused: %v (%v)", err, ok)
		}
	}
}
