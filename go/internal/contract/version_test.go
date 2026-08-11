package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D610. `meta.version` is an integer. Read as `meta["version"].(int)` with a silent
// fallback to 1, a contract declaring `version: "7"` validated OK and reported v1 —
// a declared input dropped without a word, which is D530's class in the loader rather
// than in a candidate operand. The reference coerced instead (`int("7")` -> 7), so the
// two implementations also disagreed about the document's hash.
func TestNonIntegerVersionIsRefused(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ name, version string }{
		{"a quoted integer", `"7"`},
		{"a fractional number", `3.0`},
		{"a list", `[]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-")+".yaml")
			doc := `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: v1, environment: test, version: ` + tc.version + ` }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - { id: c1, subject: db, path: service.managed, op: equals, value: true,
        verify: { method: static } }
`
			if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
				t.Fatal(err)
			}
			c, err := LoadContract(path)
			if err == nil {
				t.Fatalf("accepted version %s and read v%d — a declared version the "+
					"loader cannot read must be refused, never defaulted",
					tc.version, c.Version)
			}
			if !strings.Contains(err.Error(), "meta.version") {
				t.Errorf("the refusal does not name the field: %v", err)
			}
		})
	}

	// The ordinary form still loads, and the absent form still means 1.
	path := filepath.Join(dir, "ok.yaml")
	if err := os.WriteFile(path, []byte(`apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: v1, environment: test, version: 7 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - { id: c1, subject: db, path: service.managed, op: equals, value: true,
        verify: { method: static } }
`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := LoadContract(path)
	if err != nil {
		t.Fatalf("a plain integer version must load: %v", err)
	}
	if c.Version != 7 {
		t.Errorf("version = %d, want 7", c.Version)
	}
}
