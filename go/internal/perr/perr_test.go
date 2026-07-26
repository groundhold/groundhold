package perr

import (
	"sort"
	"testing"
)

// TestRegistryMirrorsExplain: the machine registry (D233) is exactly the Explain
// map, sorted — one source, no divergence. If a code is added to Explain, it
// appears in the registry automatically; this pins that completeness.
func TestRegistryMirrorsExplain(t *testing.T) {
	reg := Registry()
	if len(reg) != len(Explain) {
		t.Fatalf("registry has %d entries, Explain has %d — they must match", len(reg), len(Explain))
	}
	// sorted by code, deterministic
	codes := make([]string, len(reg))
	for i, e := range reg {
		codes[i] = e.Code
		ex, ok := Explain[Code(e.Code)]
		if !ok {
			t.Fatalf("registry code %q not in Explain", e.Code)
		}
		if e.Summary != ex.Summary || e.Remediation != ex.Remediation {
			t.Fatalf("registry entry %q diverges from Explain", e.Code)
		}
	}
	if !sort.StringsAreSorted(codes) {
		t.Fatalf("registry must be sorted by code: %v", codes)
	}
}
