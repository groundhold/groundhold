package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"groundhold/internal/scalars"
)

// The closed vocabulary sets are enumerated in BOTH implementations — Go here and
// the Python reference in ref/groundholdlib/ — as load-time validators that REFUSE
// a document whose value is not a member. D25 makes the two the same contract, so a
// member in one but not the other is a document one implementation loads and the
// other rejects. Event types already carried this gate (ledger's classification_gate
// reads scenario.py); these sets matched only by hand. D338 is the record of what a
// closed set enumerated twice and left untied does: the Go and Python event-type
// sets drifted to 21 vs 16 members and the reference REFUSED to load a ledger
// `converge` wrote — the D25 guarantee inverted in the evidence substrate.
//
// Operators and presence operators feed validOps in BOTH implementations (Go:
// range scalars.Operators | presenceOps; Python: set(OPERATORS) | PRESENCE_OPERATORS,
// D327). The derivation keeps validOps consistent WITHIN each implementation but
// says nothing ACROSS them, so those two sets are gated here too — an operator in
// one implementation but not the other makes validOps disagree and a contract valid
// in one panic-or-refused in the other.

func vocabParityRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "spec", "state-model.md")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("no spec/ above this directory — a partial tree has nothing to compare")
	return ""
}

func vocabParityRead(t *testing.T, root string, parts ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{root}, parts...)...))
	if err != nil {
		t.Fatalf("cannot read the Python reference this gate compares against — a gate "+
			"that loses its subject must fail, not pass (D565): %v", err)
	}
	return string(raw)
}

// pyStringSet extracts the quoted members of a Python `NAME = { ... }` set/dict
// literal. The literals it reads hold only string keys and no nested braces, so the
// first `}` after the opening closes it. The marker is newline-anchored so `OPERATORS`
// does not match inside `PRESENCE_OPERATORS`.
func pyStringSet(t *testing.T, src, name string) map[string]bool {
	t.Helper()
	marker := "\n" + name + " = {"
	i := strings.Index(src, marker)
	if i < 0 {
		t.Fatalf("Python set %q not found in the reference — a gate that loses its "+
			"subject must fail, not pass (D565)", name)
	}
	rest := src[i+len(marker):]
	j := strings.IndexByte(rest, '}')
	if j < 0 {
		t.Fatalf("Python set %q has no closing brace", name)
	}
	out := map[string]bool{}
	for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(rest[:j], -1) {
		out[m[1]] = true
	}
	if len(out) == 0 {
		t.Fatalf("parsed 0 members from Python set %q — the scan broke (D328)", name)
	}
	return out
}

func TestVocabularySetsMatchThePythonReference(t *testing.T) {
	root := vocabParityRoot(t)
	contractPy := vocabParityRead(t, root, "ref", "groundholdlib", "contract.py")
	scalarsPy := vocabParityRead(t, root, "ref", "groundholdlib", "scalars.py")

	operators := map[string]bool{}
	for k := range scalars.Operators {
		operators[k] = true
	}

	cases := []struct {
		label string
		goSet map[string]bool
		pySrc string
		pyKey string
	}{
		{"capability types", capabilityTypesV01, contractPy, "CAPABILITY_TYPES_V01"},
		{"verify methods", validMethods, contractPy, "VALID_METHODS"},
		{"provenance statuses", validStatuses, contractPy, "VALID_STATUSES"},
		{"scalar operators", operators, scalarsPy, "OPERATORS"},
		{"presence operators", presenceOps, scalarsPy, "PRESENCE_OPERATORS"},
	}
	for _, c := range cases {
		if len(c.goSet) == 0 {
			t.Fatalf("%s: the Go set is empty — the gate would be vacuous (D328)", c.label)
		}
		pySet := pyStringSet(t, c.pySrc, c.pyKey)
		for k := range c.goSet {
			if !pySet[k] {
				t.Errorf("%s: Go accepts %q but the Python reference does not — a document "+
					"valid in the runtime is REFUSED by the reference (D25 divergence)", c.label, k)
			}
		}
		for k := range pySet {
			if !c.goSet[k] {
				t.Errorf("%s: the Python reference accepts %q but Go does not — a document "+
					"valid in the reference is REFUSED by the runtime (D25 divergence)", c.label, k)
			}
		}
	}
}
