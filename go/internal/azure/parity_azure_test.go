package azure

import (
	"sort"
	"testing"
)

// TestServiceCapabilitiesKeySet asserts the parity map keys equal
// azureCertifyServices exactly — no missing token, no surplus token, no empty
// value. This keeps the Azure parity column honest as the certified service set
// evolves.
func TestServiceCapabilitiesKeySet(t *testing.T) {
	got := NewDriver(testSub).ServiceCapabilities()

	want := make(map[string]bool, len(azureCertifyServices))
	for _, tok := range azureCertifyServices {
		want[tok] = true
		if _, ok := got[tok]; !ok {
			t.Errorf("ServiceCapabilities missing certified token %q", tok)
		}
		if got[tok] == "" {
			t.Errorf("ServiceCapabilities has empty capability for token %q", tok)
		}
	}
	for tok := range got {
		if !want[tok] {
			t.Errorf("ServiceCapabilities has surplus token %q not in azureCertifyServices", tok)
		}
	}

	if len(got) != len(azureCertifyServices) {
		gotKeys := make([]string, 0, len(got))
		for k := range got {
			gotKeys = append(gotKeys, k)
		}
		sort.Strings(gotKeys)
		t.Errorf("key count mismatch: got %d, want %d (%v)", len(got), len(azureCertifyServices), gotKeys)
	}
}
