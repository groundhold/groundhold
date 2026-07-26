package gcp

import (
	"sort"
	"testing"
)

// TestServiceCapabilitiesKeySet asserts the parity map keys equal
// gcpCertifyServices exactly — no missing token, no surplus token. This keeps
// the GCP parity column honest as the certified service set evolves.
func TestServiceCapabilitiesKeySet(t *testing.T) {
	got := NewDriver("proj").ServiceCapabilities()

	want := make(map[string]bool, len(gcpCertifyServices))
	for _, tok := range gcpCertifyServices {
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
			t.Errorf("ServiceCapabilities has surplus token %q not in gcpCertifyServices", tok)
		}
	}

	if len(got) != len(gcpCertifyServices) {
		gotKeys := make([]string, 0, len(got))
		for k := range got {
			gotKeys = append(gotKeys, k)
		}
		sort.Strings(gotKeys)
		t.Errorf("key count mismatch: got %d, want %d (%v)", len(got), len(gcpCertifyServices), gotKeys)
	}
}
