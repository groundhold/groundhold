package adopt

import "testing"

// TestProtocolConfirms pins F8: adoption confirms a protocol/version attribute at
// the DECLARED granularity — honest by construction (records only a statement true
// of reality), never strict equality that rejects a legitimate minor drift.
func TestProtocolConfirms(t *testing.T) {
	cases := []struct {
		declared, observed string
		want               bool
	}{
		{"postgresql/16", "postgresql/16.13", true},    // major-only declared, minor reality (Acme's F8)
		{"postgresql/16", "postgresql/16", true},       // exact
		{"postgresql/16.13", "postgresql/16.13", true}, // precise, exact
		{"postgresql/16", "postgresql/17", false},      // different major
		{"postgresql/16.5", "postgresql/16.13", false}, // precise declared, different minor — NOT a lie
		{"postgresql/16.13", "postgresql/16", false},   // declared more precise than reality
		{"postgresql/16", "mysql/16.13", false},        // different engine
		{"redis/7", "redis/7.2.4", true},               // patch reality confirms major-only
		{"redis/7.2", "redis/7.2.4", true},             // minor declared, patch reality
	}
	for _, c := range cases {
		if got := protocolConfirms(c.declared, c.observed); got != c.want {
			t.Errorf("protocolConfirms(%q, %q) = %v, want %v", c.declared, c.observed, got, c.want)
		}
	}
}
