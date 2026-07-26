package docio

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v3"
)

func TestReadDoc(t *testing.T) {
	dir := t.TempDir()

	write := func(name string, n int) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, make([]byte, n), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	// A file whose length is exactly at the cap must be accepted: the
	// refusal is strictly on len > MaxDocumentBytes.
	atCap := write("atcap.yaml", MaxDocumentBytes)
	// One byte over the cap must be refused before parsing.
	overCap := write("overcap.yaml", MaxDocumentBytes+1)
	// Empty files are valid documents at this layer (parsing is elsewhere).
	empty := write("empty.yaml", 0)

	small := filepath.Join(dir, "small.yaml")
	if err := os.WriteFile(small, []byte("kind: contract\n"), 0o600); err != nil {
		t.Fatalf("write small: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		wantLen int
		wantErr string // substring; "" means no error
	}{
		{"small file", small, len("kind: contract\n"), ""},
		{"empty file", empty, 0, ""},
		{"exactly at cap", atCap, MaxDocumentBytes, ""},
		{"one byte over cap", overCap, 0, "exceeds"},
		{"missing file", filepath.Join(dir, "nope.yaml"), 0, "no such file"},
		{"path is a directory", dir, 0, ""}, // see assertion below
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := ReadDoc(tc.path)

			// A directory read fails via os.ReadFile with a platform
			// error string we don't pin verbatim; just require an error.
			if tc.name == "path is a directory" {
				if err == nil {
					t.Fatalf("reading a directory: want error, got nil")
				}
				return
			}

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(raw) != tc.wantLen {
					t.Fatalf("len = %d, want %d", len(raw), tc.wantLen)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
			if raw != nil {
				t.Fatalf("raw = %v, want nil on error", raw)
			}
		})
	}
}

// TestReadDocMissingIsNotExist pins that ReadDoc surfaces os.ReadFile's
// error unwrapped, so callers can still classify it with os.IsNotExist.
func TestReadDocMissingIsNotExist(t *testing.T) {
	_, err := ReadDoc(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("want error for missing file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error %v is not os.ErrNotExist", err)
	}
}

const twoTo53 = 1 << 53 // 9007199254740992, the fail-closed boundary

func TestCheckSafeNumbers(t *testing.T) {
	tests := []struct {
		name    string
		v       any
		wantErr bool
	}{
		// scalars that are not numbers are always fine
		{"nil", nil, false},
		{"string", "hello", false},
		{"bool", true, false},
		{"safe int zero", 0, false},
		{"negative safe int", -42, false},

		// int boundary: refusal is >= 2^53 and <= -2^53
		{"int just under cap", int(twoTo53 - 1), false},
		{"int at cap", int(twoTo53), true},
		{"int negative just under cap", int(-(twoTo53 - 1)), false},
		{"int negative at cap", int(-twoTo53), true},

		// int64 boundary (distinct type branch)
		{"int64 just under cap", int64(twoTo53 - 1), false},
		{"int64 at cap", int64(twoTo53), true},
		{"int64 negative at cap", int64(-twoTo53), true},

		// float64 boundary: 2^53 and 2^53-1 are both exactly representable
		{"float just under cap", float64(twoTo53 - 1), false},
		{"float at cap", float64(twoTo53), true},
		{"float negative at cap", float64(-twoTo53), true},
		{"fractional safe float", 3.14, false},

		// string-encoded numbers are deliberately untouched (D66 escape hatch)
		{"huge number as string", "9007199254740993", false},

		// recursion through containers
		{"map with safe values", map[string]any{"a": 1, "b": "x"}, false},
		{"map with unsafe value", map[string]any{"a": int64(twoTo53)}, true},
		{"slice with safe values", []any{1, 2, 3}, false},
		{"slice with unsafe value", []any{1, float64(twoTo53)}, true},
		{"nested unsafe deep in tree",
			map[string]any{"outer": []any{map[string]any{"n": int(twoTo53)}}}, true},
		{"empty map", map[string]any{}, false},
		{"empty slice", []any{}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckSafeNumbers(tc.v)
			if tc.wantErr && err == nil {
				t.Fatalf("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil && !strings.Contains(err.Error(), "JSON-safe range") {
				t.Fatalf("error %q missing remediation hint", err.Error())
			}
		})
	}
}

// TestCheckSafeNumbersFromYAML exercises the realistic path: a document
// decoded by yaml.v3 (ints land as int) fed straight into the guard.
func TestCheckSafeNumbersFromYAML(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantErr bool
	}{
		{"safe doc", "count: 5\nname: db\n", false},
		{"unsafe int", "big: 9007199254740992\n", true},
		{"safe boundary int", "big: 9007199254740991\n", false},
		{"unsafe nested", "spec:\n  limits:\n    - 9007199254740993\n", true},
		{"big number quoted stays safe", "big: \"9007199254740993\"\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var v any
			if err := yaml.Unmarshal([]byte(tc.doc), &v); err != nil {
				t.Fatalf("yaml decode: %v", err)
			}
			err := CheckSafeNumbers(v)
			if tc.wantErr != (err != nil) {
				t.Fatalf("CheckSafeNumbers err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}
