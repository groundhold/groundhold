package vocab

import (
	"os"
	"path/filepath"
	"testing"
)

// specVocabDir is the canonical vocabulary source, relative to this package.
const specVocabDir = "../../../spec/vocab"

// TestEmbeddedMatchesSpec is the anti-drift gate: the compiled-in vocabulary
// (embedded/) must be byte-identical to spec/vocab/ (canonical). If someone
// edits spec/vocab without re-running `make embed-vocab`, make check fails here
// rather than shipping a binary whose built-in types silently lag the spec.
func TestEmbeddedMatchesSpec(t *testing.T) {
	specPaths, err := filepath.Glob(filepath.Join(specVocabDir, "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(specPaths) == 0 {
		t.Fatalf("no vocab files under %s", specVocabDir)
	}
	specSet := map[string]bool{}
	for _, p := range specPaths {
		base := filepath.Base(p)
		specSet[base] = true
		want, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := embeddedFS.ReadFile("embedded/" + base)
		if err != nil {
			t.Errorf("%s in spec/vocab but not embedded — run `make embed-vocab`", base)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("%s drifted from spec/vocab — run `make embed-vocab`", base)
		}
	}
	// no embedded file without a spec source
	embEntries, err := embeddedFS.ReadDir("embedded")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range embEntries {
		if !specSet[e.Name()] {
			t.Errorf("embedded/%s has no spec/vocab source — stale, run `make embed-vocab`", e.Name())
		}
	}
}

// TestEmbeddedParses confirms every compiled-in document is a valid vocabulary
// (so a download can never carry a corrupt built-in type system).
func TestEmbeddedParses(t *testing.T) {
	v, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded(): %v", err)
	}
	if len(v) < 30 {
		t.Fatalf("expected the full breadth vocabulary, got %d capabilities", len(v))
	}
	for _, must := range []string{
		"capability.database.relational",
		"capability.storage.object",
		"capability.workload.container",
	} {
		if _, ok := v[must]; !ok {
			t.Errorf("embedded vocabulary missing %s", must)
		}
	}
}
