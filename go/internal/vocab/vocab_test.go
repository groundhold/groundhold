package vocab

import (
	"os"
	"path/filepath"
	"testing"
)

// D787. `TestEveryDeclaredEvidenceClassIsInTheClosedSet` runs ValidateEvidence over every
// embedded vocabulary — and no vocabulary violates it, so replacing the whole validator
// with `return nil` changes nothing and no mutant aimed at that gate can bite. The same
// empty-subject shape as D784's visibility sweep and D785's forbidden-import list.
//
// The validator itself had no test at all. It gets one here, against a synthetic
// vocabulary carrying an invented class — the only shape that proves the machinery works
// on the day a typo reaches a vocabulary file, which is the failure D311 named: "a closed
// set that silently tolerates a typo is not closed, and here the typo's consequence is a
// reconcile that gates on an observation which will never arrive".
func TestValidateEvidenceRejectsAnInventedClass(t *testing.T) {
	ok := Vocabulary{Capability: "capability.test", Attributes: map[string]map[string]any{
		"a.measured":   {"kind": "bool"},
		"a.projection": {"kind": "money", "evidence": "projection"},
		"a.probe":      {"kind": "bool", "evidence": "probe"},
		"a.resource":   {"kind": "bool", "evidence": "resource"},
	}}
	if err := ok.ValidateEvidence(); err != nil {
		t.Fatalf("every declared class is in the closed set: %v", err)
	}

	for _, bad := range []string{"projections", "Probe", "measured", ""} {
		v := Vocabulary{Capability: "capability.test", Attributes: map[string]map[string]any{
			"a.x": {"kind": "bool", "evidence": bad},
		}}
		if err := v.ValidateEvidence(); err == nil {
			t.Errorf("evidence %q was accepted — a near-miss is the whole point of a "+
				"closed set, and `measured` is a DERIVATION, not an evidence class (D787)", bad)
		}
	}
}

// D1091. A named vocabulary directory that supplies nothing used to load nothing and
// say nothing: `filepath.Glob` reports no error for a path that does not exist, and
// none for one holding no vocabularies, so both returned an empty map and a nil error.
//
// The harm is quiet and specific. `--vocab` is how an operator extends the type system
// with their own capability types, and a loaded vocabulary is what makes candidate
// values kind- and enum-checked AT LOAD (D19, fail-fast). Point the flag at a path that
// does not exist in this checkout — a typo, or a CI layout where the directory is
// somewhere else — and every custom attribute silently drops to free-form. The verdict
// stays honest in JSON (`pathInVocabulary: false`), but nothing tells the operator that
// the thing they asked for was not there.
//
// The shipped CI recipe makes it likely rather than hypothetical: it passes
// `--vocab spec/vocab`, a path that exists in THIS repository and not in the user's.
//
// Same rule as the paginated reads: "I found nothing" and "there is nothing to find"
// must not arrive as one value.
func TestANamedVocabularyDirectoryMustSupplySomething(t *testing.T) {
	if _, err := LoadDir(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("LoadDir accepted a directory that does not exist. An operator who " +
			"named it gets no vocabulary, no error, and no load-time type check.")
	}
	empty := t.TempDir()
	if _, err := LoadDir(empty); err == nil {
		t.Error("LoadDir accepted a directory holding no vocabularies. Naming a " +
			"directory is asking for it; --no-vocab is how you ask for the empty set.")
	}
	// The positive half: a directory that does supply one still loads. Without this
	// the two checks above would pass on a LoadDir that rejects everything.
	good := t.TempDir()
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "vocab",
		"capability.database.relational.yaml"))
	if err != nil {
		t.Skipf("no vocabulary to copy here: %v", err)
	}
	if err := os.WriteFile(filepath.Join(good, "v.yaml"), src, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadDir(good)
	if err != nil {
		t.Fatalf("a directory with one vocabulary must load: %v", err)
	}
	if len(got) == 0 {
		t.Error("loaded no vocabularies from a directory that holds one")
	}
}
