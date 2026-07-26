// Package docio reads documents with a size cap. Oversized documents are
// refused before parsing; the YAML parser's own alias-expansion limits
// cover the rest.
package docio

import (
	"fmt"
	"os"
)

const MaxDocumentBytes = 1 << 20

func ReadDoc(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxDocumentBytes {
		return nil, fmt.Errorf("document exceeds %d bytes", MaxDocumentBytes)
	}
	return raw, nil
}

// maxSafeInteger is 2^53 — the largest integer an IEEE-754 double holds
// exactly. Beyond it a JSON round-trip is lossy, so such a value cannot
// canonicalize deterministically (D66).
const maxSafeInteger = 1 << 53

// CheckSafeNumbers refuses any raw numeric value outside the JSON-safe
// integer range anywhere in a decoded document tree (D66). The
// fail-closed point is LOAD: a non-canonicalizable document is a
// structural error in both implementations, never a verdict.
// String-encoded numbers are untouched — use them for bigger integers.
func CheckSafeNumbers(v any) error {
	switch x := v.(type) {
	case map[string]any:
		for _, val := range x {
			if err := CheckSafeNumbers(val); err != nil {
				return err
			}
		}
	case []any:
		for _, it := range x {
			if err := CheckSafeNumbers(it); err != nil {
				return err
			}
		}
	case int:
		return checkInt(int64(x))
	case int64:
		return checkInt(x)
	case float64:
		// any double with |x| >= 2^53 is necessarily integral (no
		// fractional bits remain at that magnitude) and lossy through
		// JSON — refuse without an int64 conversion that would overflow
		if x >= maxSafeInteger || x <= -maxSafeInteger {
			return numRangeErr(x)
		}
	}
	return nil
}

func checkInt(n int64) error {
	if n >= maxSafeInteger || n <= -maxSafeInteger {
		return numRangeErr(float64(n))
	}
	return nil
}

func numRangeErr(f float64) error {
	return fmt.Errorf("integer %.0f exceeds the JSON-safe range (2^53); "+
		"encode it as a string to canonicalize", f)
}
