package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D597. `autonomy` carries the consent lists, and a dangling capability name in one
// is a grant the operator believes they wrote and did not. The loader already refuses
// that — for `allow_replace_stateful`, by name. `allow_intrusive_probes` was not
// checked, so:
//
//	autonomy: { allow_replace_stateful: [does-not-exist] }  ->  INVALID
//	autonomy: { allow_intrusive_probes: [does-not-exist] }  ->  OK, exit 0
//
// The asymmetry runs the wrong way. Intrusive probes are the ones that SPEND — D59's
// restore-test restores a backup into a scratch instance and times it — and they are
// gated by a double consent precisely because they cost money and touch the estate.
// A typo there loads clean, grants nothing, and surfaces as a refusal later, quite
// possibly during the incident the probe was meant to measure.
//
// Both lists are checked now, from ONE list of consent keys rather than one `if` per
// key, so a third consent list added later is covered without anyone remembering
// (D583: the fix has to be the mechanism, or the next author repeats it).
func TestEveryConsentListRefusesAnUnknownCapability(t *testing.T) {
	for _, key := range []string{"allow_replace_stateful", "allow_intrusive_probes"} {
		_, err := loadContractText(t, `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: t, owner: o@e.test, environment: prod, version: 1 }
autonomy:
  `+key+`: [does-not-exist]
capabilities:
  - id: db
    type: capability.database.relational
`)
		if err == nil {
			t.Errorf("autonomy.%s named a capability that does not exist and the "+
				"contract loaded — the operator wrote a grant that grants nothing and "+
				"will not learn so until something refuses", key)
			continue
		}
		if !strings.Contains(err.Error(), key) {
			t.Errorf("the refusal does not name %s: %v", key, err)
		}
	}
}

// A real capability name must still load, or the check has eaten the feature.
func TestConsentListAcceptsARealCapability(t *testing.T) {
	for _, key := range []string{"allow_replace_stateful", "allow_intrusive_probes"} {
		if _, err := loadContractText(t, `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: t, owner: o@e.test, environment: prod, version: 1 }
autonomy:
  `+key+`: [db]
capabilities:
  - id: db
    type: capability.database.relational
`); err != nil {
			t.Errorf("autonomy.%s naming a real capability was refused: %v", key, err)
		}
	}
}

func loadContractText(t *testing.T, body string) (*Contract, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadContract(p)
}
