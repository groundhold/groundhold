package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"groundhold/internal/vocab"
)

// D311: an attribute's evidence class is DECLARED in the vocabulary, and a driver
// may not re-encode it.
//
// Before D311 the fact "cost.monthly is a forecast, not resource state" lived in
// the vocabulary as prose and was hand-copied into ~190 `case` arms across the
// drivers — a no-op arm in every builder (because a builder refuses any attribute
// it cannot map) plus a "nothing to patch" arm in every ClassifyChange. Adding a
// new attribute of that class meant editing ~50 Go files, the exact opposite of
// the zero-engine-changes property a declarative vocabulary exists to give
// (D23/D55).
//
// The engine now derives it, and the attribute never reaches a driver at all. This
// gate keeps it that way: no `case` arm in any provider package may name an
// attribute the vocabulary marks as not-resource-state.
//
// It does NOT forbid mentioning such a path outright — a probe legitimately EMITS
// recovery.rto, and the compiler legitimately READS cost.monthly for the risk
// projection. Producing and consuming are fine; re-deciding the class is not.
func TestNoDriverHardcodesAnEvidenceClass(t *testing.T) {
	vocabs, err := vocab.Embedded()
	if err != nil {
		t.Fatalf("embedded vocabularies: %v", err)
	}
	notState := map[string]bool{}
	for _, v := range vocabs {
		for path := range v.Attributes {
			if v.NotResourceState(path) {
				notState[path] = true
			}
		}
	}
	if len(notState) == 0 {
		t.Fatal("no attribute declares a non-resource evidence class — either the " +
			"vocabularies lost their `evidence:` markers or the loader stopped " +
			"reading them; this gate would then be vacuous")
	}

	caseArm := regexp.MustCompile(`^\s*case\s+"`)
	for _, pkg := range []string{"aws", "azure", "gcp", "k8s", "cloudflare", "hetzner", "upstash"} {
		dir := filepath.Join("..", pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // a provider package that does not exist is not a violation
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
				strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for i, line := range strings.Split(string(raw), "\n") {
				if !caseArm.MatchString(line) {
					continue
				}
				for attr := range notState {
					if strings.Contains(line, `"`+attr+`"`) {
						t.Errorf("%s:%d handles %q in a case arm. Its evidence class is "+
							"declared in the vocabulary and the attribute never reaches a "+
							"driver — delete the arm rather than re-deciding the class here.\n\t%s",
							path, i+1, attr, strings.TrimSpace(line))
					}
				}
			}
		}
	}
}

// The closed set is only closed if a typo is refused. An unrecognised `evidence:`
// silently means "resource state", so without this gate a misspelt `projektion`
// would quietly restore the pre-D311 behaviour for that attribute — a reconcile
// blocking forever on an observation that can never arrive.
func TestEveryDeclaredEvidenceClassIsInTheClosedSet(t *testing.T) {
	vocabs, err := vocab.Embedded()
	if err != nil {
		t.Fatalf("embedded vocabularies: %v", err)
	}
	for _, v := range vocabs {
		if err := v.ValidateEvidence(); err != nil {
			t.Error(err)
		}
	}
}
