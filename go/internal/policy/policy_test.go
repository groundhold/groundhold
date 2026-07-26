package policy

import (
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/vocab"
)

// TestStatefulOf covers the fail-closed statefulness predicate (D47): an
// absent capability or absent vocabulary cannot PROVE statelessness, so it
// is treated as stateful; only a present vocabulary with Stateful==false is
// stateless.
func TestStatefulOf(t *testing.T) {
	vocabs := map[string]vocab.Vocabulary{
		"database":       {Capability: "database", Stateful: true},
		"container-work": {Capability: "container-work", Stateful: false},
	}
	statefulCap := map[string]map[string]any{
		"db": {"type": "database"},
	}
	statelessCap := map[string]map[string]any{
		"svc": {"type": "container-work"},
	}
	unknownTypeCap := map[string]map[string]any{
		"x": {"type": "no-such-vocab"},
	}
	noTypeCap := map[string]map[string]any{
		"x": {"foo": "bar"}, // no "type" key
	}

	tests := []struct {
		name  string
		caps  map[string]map[string]any
		capID string
		want  bool
	}{
		{"present stateful vocab -> stateful", statefulCap, "db", true},
		{"present stateless vocab -> stateless", statelessCap, "svc", false},
		{"absent capability -> fail closed stateful", statefulCap, "missing", true},
		{"capability type not in vocabs -> fail closed stateful", unknownTypeCap, "x", true},
		{"capability without type key -> fail closed stateful", noTypeCap, "x", true},
		{"nil capabilities map -> fail closed stateful", nil, "db", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &contract.Contract{Capabilities: tc.caps}
			if got := StatefulOf(c, tc.capID, vocabs); got != tc.want {
				t.Errorf("StatefulOf(%q) = %v, want %v", tc.capID, got, tc.want)
			}
		})
	}
}

// TestStatefulOf_NilVocabs pins that a nil vocabulary index also fails
// closed: no vocab means statelessness cannot be proven.
func TestStatefulOf_NilVocabs(t *testing.T) {
	c := &contract.Contract{Capabilities: map[string]map[string]any{
		"db": {"type": "database"},
	}}
	if got := StatefulOf(c, "db", nil); got != true {
		t.Errorf("StatefulOf with nil vocabs = %v, want true (fail closed)", got)
	}
}

// TestForbidsDeleteStateful covers the autonomy delete_stateful gate (D47).
func TestForbidsDeleteStateful(t *testing.T) {
	tests := []struct {
		name     string
		autonomy map[string]any
		want     bool
	}{
		{
			name: "delete_stateful true -> forbidden",
			autonomy: map[string]any{
				"forbidden": []any{
					map[string]any{"delete_stateful": true},
				},
			},
			want: true,
		},
		{
			name: "delete_stateful false -> not forbidden",
			autonomy: map[string]any{
				"forbidden": []any{
					map[string]any{"delete_stateful": false},
				},
			},
			want: false,
		},
		{
			name: "delete_stateful among several entries",
			autonomy: map[string]any{
				"forbidden": []any{
					map[string]any{"something_else": true},
					map[string]any{"delete_stateful": true},
				},
			},
			want: true,
		},
		{
			name:     "no forbidden key -> not forbidden",
			autonomy: map[string]any{},
			want:     false,
		},
		{
			name: "empty forbidden list -> not forbidden",
			autonomy: map[string]any{
				"forbidden": []any{},
			},
			want: false,
		},
		{
			name: "forbidden entry without delete_stateful key -> not forbidden",
			autonomy: map[string]any{
				"forbidden": []any{
					map[string]any{"delete_something": true},
				},
			},
			want: false,
		},
		{
			name: "delete_stateful with non-bool value -> not forbidden",
			autonomy: map[string]any{
				"forbidden": []any{
					map[string]any{"delete_stateful": "yes"},
				},
			},
			want: false,
		},
		{
			name: "forbidden not a list -> not forbidden",
			autonomy: map[string]any{
				"forbidden": "delete_stateful",
			},
			want: false,
		},
		{
			name:     "nil autonomy -> not forbidden",
			autonomy: nil,
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &contract.Contract{Autonomy: tc.autonomy}
			if got := ForbidsDeleteStateful(c); got != tc.want {
				t.Errorf("ForbidsDeleteStateful() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRequiresProvenHardBasis covers the D195 opt-in gate.
func TestRequiresProvenHardBasis(t *testing.T) {
	tests := []struct {
		name     string
		autonomy map[string]any
		want     bool
	}{
		{"flag true", map[string]any{"no_assumed_hard_basis": true}, true},
		{"flag false", map[string]any{"no_assumed_hard_basis": false}, false},
		{"flag absent", map[string]any{}, false},
		{"flag non-bool string", map[string]any{"no_assumed_hard_basis": "true"}, false},
		{"nil autonomy", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &contract.Contract{Autonomy: tc.autonomy}
			if got := RequiresProvenHardBasis(c); got != tc.want {
				t.Errorf("RequiresProvenHardBasis() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAllowsReplaceStateful covers the scoped replace-consent gate (D48):
// consent is per-capability; only an exact capability-id match in the
// allow_replace_stateful list grants it.
func TestAllowsReplaceStateful(t *testing.T) {
	tests := []struct {
		name     string
		autonomy map[string]any
		capID    string
		want     bool
	}{
		{
			name: "capability scoped in list -> allowed",
			autonomy: map[string]any{
				"allow_replace_stateful": []any{"db", "cache"},
			},
			capID: "db",
			want:  true,
		},
		{
			name: "capability not in list -> not allowed",
			autonomy: map[string]any{
				"allow_replace_stateful": []any{"db"},
			},
			capID: "cache",
			want:  false,
		},
		{
			name: "empty allow list -> not allowed",
			autonomy: map[string]any{
				"allow_replace_stateful": []any{},
			},
			capID: "db",
			want:  false,
		},
		{
			name: "list with non-string entry, no match -> not allowed",
			autonomy: map[string]any{
				"allow_replace_stateful": []any{42, "cache"},
			},
			capID: "db",
			want:  false,
		},
		{
			name: "allow_replace_stateful not a list -> not allowed",
			autonomy: map[string]any{
				"allow_replace_stateful": "db",
			},
			capID: "db",
			want:  false,
		},
		{
			name:     "key absent -> not allowed",
			autonomy: map[string]any{},
			capID:    "db",
			want:     false,
		},
		{
			name:     "nil autonomy -> not allowed",
			autonomy: nil,
			capID:    "db",
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &contract.Contract{Autonomy: tc.autonomy}
			if got := AllowsReplaceStateful(c, tc.capID); got != tc.want {
				t.Errorf("AllowsReplaceStateful(%q) = %v, want %v", tc.capID, got, tc.want)
			}
		})
	}
}
