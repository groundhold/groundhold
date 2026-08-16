package collector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// D1149. `derivation` is the line between "this was read from the resource" and "the
// resource holds this value and does not itself enforce it". The audit ladder demotes
// config-intent and platform-invariant to the static bar for that reason, and demotes
// nothing else — so a class outside the closed set keeps its SOURCE's rank, which for a
// provider-api read is the strong one. A fabrication ranked as a measurement is the
// exact failure `spec/collector.md` says the whole witness-side design exists to prevent.
//
// The set is published in `spec/state.schema.json` as an enum, restated in this package
// as the map Certify consults, restated again as the audit ladder's demotion list, and
// once more as item 3 of the collector checklist. Nothing compared any two of them.
//
// What stood over this package's copy names three MEMBERS and three non-members and
// checks each verdict — a good test, and structurally unable to notice an ADDITION.
// Measured: adding a fourth key to the map leaves every one of those six cases correct.
// The three members still accept, the three invented ones still reject, and the set has
// grown. Naming what is outside a closed set cannot close it.
//
// So the set is NAMED here, and both copies are held to the name. Derived from the two
// sides it would agree with itself whatever either side did — the shape D1130 found in
// the checksums and D1141 in the platform list.
func TestTheDerivationSetIsExactlyTheThreePublishedClasses(t *testing.T) {
	// The closed set. Changing it is a decision about what counts as evidence, and it
	// has to be made here, in the schema, and in the audit ladder at the same time.
	want := []string{"config-intent", "measured", "platform-invariant"}

	var got []string
	for k := range okDerivation {
		got = append(got, k)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Certify accepts %v; the published set is %v.\nAn EXTRA class is the "+
			"dangerous direction: the audit ladder demotes only config-intent and "+
			"platform-invariant, so anything else keeps its source's rank and a "+
			"capsule's word is trusted as a measurement.", got, want)
	}

	// The schema is where the set is published for anyone writing a ledger by hand.
	root := repoRootFromHere(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "state.schema.json"))
	if err != nil {
		t.Skipf("no state schema in this tree: %v", err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("state schema does not parse: %v", err)
	}
	enums := derivationEnums(doc)
	if len(enums) != 1 {
		t.Fatalf("found %d `derivation` enums in the schema, want exactly 1 — the scan "+
			"broke, or the set moved somewhere this gate cannot see it (D328)", len(enums))
	}
	sort.Strings(enums[0])
	if strings.Join(enums[0], ",") != strings.Join(want, ",") {
		t.Errorf("the state schema publishes %v; the set is %v. A hand-written ledger "+
			"is validated against the schema, so the two copies disagreeing means one "+
			"path accepts a class the other refuses.", enums[0], want)
	}
}

// derivationEnums collects every `derivation` property's enum, anywhere in the schema.
func derivationEnums(node any) [][]string {
	var out [][]string
	switch n := node.(type) {
	case map[string]any:
		if d, ok := n["derivation"].(map[string]any); ok {
			if e, ok := d["enum"].([]any); ok {
				var vals []string
				for _, v := range e {
					if s, ok := v.(string); ok {
						vals = append(vals, s)
					}
				}
				out = append(out, vals)
			}
		}
		for _, v := range n {
			out = append(out, derivationEnums(v)...)
		}
	case []any:
		for _, v := range n {
			out = append(out, derivationEnums(v)...)
		}
	}
	return out
}

func repoRootFromHere(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "spec")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("no spec/ above this package")
	return ""
}
