package scalars

import "testing"

// TestProtocolSatisfiedBy pins F16-B: a bound-resource reconcile treats a MAJOR-only
// declaration as satisfied by any observed minor of that major, but a pinned minor must
// match. Precision-aware, closed, deterministic.
func TestProtocolSatisfiedBy(t *testing.T) {
	sat := func(desired, observed string) bool {
		d, err := Parse(desired)
		if err != nil {
			t.Fatalf("parse %q: %v", desired, err)
		}
		o, err := Parse(observed)
		if err != nil {
			t.Fatalf("parse %q: %v", observed, err)
		}
		ok, err := ProtocolSatisfiedBy(d, o)
		if err != nil {
			t.Fatalf("ProtocolSatisfiedBy(%q,%q): %v", desired, observed, err)
		}
		return ok
	}
	cases := []struct {
		desired, observed string
		want              bool
	}{
		{"postgresql/16", "postgresql/16.11", true},     // major-only accepts any minor
		{"postgresql/16", "postgresql/16", true},        // exact
		{"postgresql/16", "postgresql/17.2", false},     // different major
		{"postgresql/16", "mysql/16.1", false},          // different family
		{"postgresql/16.11", "postgresql/16.11", true},  // pinned minor matches
		{"postgresql/16.11", "postgresql/16.12", false}, // pinned minor differs
		{"postgresql/16.11", "postgresql/16", false},    // pinned minor vs bare major
	}
	for _, c := range cases {
		if got := sat(c.desired, c.observed); got != c.want {
			t.Errorf("ProtocolSatisfiedBy(%q,%q)=%v want %v", c.desired, c.observed, got, c.want)
		}
	}
}
