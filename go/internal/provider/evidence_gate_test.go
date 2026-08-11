package provider_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	// D579: same floor, same reason — ValidateEvidence over an empty set is a green
	// check with no subject.
	if len(vocabs) < 20 {
		t.Fatalf("only %d embedded vocabularies — an empty set validates trivially and "+
			"would restore the pre-D311 behaviour everywhere without failing", len(vocabs))
	}
	for _, v := range vocabs {
		if err := v.ValidateEvidence(); err != nil {
			t.Error(err)
		}
	}
}

// One attribute path, one evidence class — across the WHOLE type system.
//
// The two gates above check that a driver does not re-decide a declared class and
// that a declared class is spelt correctly. Neither notices the failure that
// actually happened: an attribute that IS a projection simply not saying so. Four
// vocabularies landed with `cost.monthly` and no `evidence:` marker, so it
// defaulted to resource state (the deliberate fail-safe of EvidenceOf) and was
// carried into the builders, which refuse every attribute they cannot map.
//
// The shape of that bug is what makes it worth a gate: `plan` never calls a
// builder, so the contract SEALED and the refusal arrived at `apply` — past the
// gate, at the mutation boundary. A refusal is only useful before the resource
// exists.
//
// This needs no list of known projections, which is the point: it derives the
// expectation from the vocabularies themselves. If 36 of them call cost.monthly a
// projection and 3 say nothing, the 3 are the drift. A genuinely new attribute is
// unconstrained until a SECOND vocabulary declares it — from then on the type
// system holds itself to one meaning.
func TestAnAttributeMeansTheSameThingInEveryVocabulary(t *testing.T) {
	vocabs, err := vocab.Embedded()
	if err != nil {
		t.Fatalf("embedded vocabularies: %v", err)
	}
	// path -> evidence class -> the capabilities declaring it that way.
	seen := map[string]map[string][]string{}
	for capType, v := range vocabs {
		for path := range v.Attributes {
			class := v.EvidenceOf(path)
			if seen[path] == nil {
				seen[path] = map[string][]string{}
			}
			seen[path][class] = append(seen[path][class], capType)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no vocabulary declared any attribute — this gate would be vacuous")
	}
	for _, path := range sortedPaths(seen) {
		classes := seen[path]
		if len(classes) < 2 {
			continue
		}
		var parts []string
		for _, class := range sortedPaths(classes) {
			caps := append([]string(nil), classes[class]...)
			sort.Strings(caps)
			shown := caps
			if len(shown) > 4 {
				shown = append(append([]string{}, shown[:4]...),
					fmt.Sprintf("+%d more", len(caps)-4))
			}
			parts = append(parts, fmt.Sprintf("%s in %s", class, strings.Join(shown, ", ")))
		}
		t.Errorf("attribute %q carries %d different evidence classes: %s.\n"+
			"\tOne path must mean one thing. An attribute the majority calls a "+
			"projection but a few leave unmarked defaults to resource state, reaches "+
			"the builders, and refuses at apply instead of at the gate.",
			path, len(classes), strings.Join(parts, "; "))
	}
}

// sortedPaths keys a map deterministically, so a failure prints the same way twice.
func sortedPaths[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
