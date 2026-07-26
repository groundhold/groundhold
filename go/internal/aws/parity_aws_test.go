package aws

import (
	"sort"
	"testing"
)

// TestServiceCapabilitiesKeySet asserts the parity map keys equal
// awsCertifyServices exactly — no missing token, no surplus token. This keeps
// the AWS parity column honest as the certified service set evolves.
func TestServiceCapabilitiesKeySet(t *testing.T) {
	got := NewDriver("eu-central-1").ServiceCapabilities()

	want := make(map[string]bool, len(awsCertifyServices))
	for _, tok := range awsCertifyServices {
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
			t.Errorf("ServiceCapabilities has surplus token %q not in awsCertifyServices", tok)
		}
	}

	if len(got) != len(awsCertifyServices) {
		gotKeys := make([]string, 0, len(got))
		for k := range got {
			gotKeys = append(gotKeys, k)
		}
		sort.Strings(gotKeys)
		t.Errorf("key count mismatch: got %d, want %d (%v)", len(got), len(awsCertifyServices), gotKeys)
	}
}
