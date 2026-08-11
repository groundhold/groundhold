package vocab

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D698: every capability type in the closed v0.1 set must have a vocabulary.
//
// This is the premise that lets `policy.ProtectionOf` fail OPEN. A type whose
// vocabulary is missing has no `protection:` marker to read, so its retirement would
// skip the protection gate silently — and a type is added to the closed set in one
// file while its vocabulary is written in another, which is exactly the shape that
// drifts. Held here so the premise is checked rather than believed.
//
// It is also worth having on its own: a type with no vocabulary can be named by a
// contract and typed by nothing.
func TestEveryCapabilityTypeHasAVocabulary(t *testing.T) {
	root := repoRootFromVocab(t)
	src, err := os.ReadFile(filepath.Join(root, "go", "internal", "contract", "contract.go"))
	if err != nil {
		t.Skip("no contract.go in this tree")
	}
	block := string(src)
	i := strings.Index(block, "var capabilityTypesV01")
	if i < 0 {
		t.Fatal("capabilityTypesV01 not found — the closed set moved and this gate " +
			"would check nothing (D328)")
	}
	block = block[i:]
	if j := strings.Index(block, "\n}\n"); j > 0 {
		block = block[:j]
	}
	types := regexp.MustCompile(`"(capability\.[a-z.]+)"`).FindAllStringSubmatch(block, -1)
	if len(types) < 40 {
		t.Fatalf("parsed %d capability types — the scan broke (D328)", len(types))
	}

	vocabs, err := LoadDir(filepath.Join(root, "spec", "vocab"))
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for _, m := range types {
		if _, ok := vocabs[m[1]]; !ok {
			missing = append(missing, m[1])
		}
	}
	if len(missing) > 0 {
		t.Errorf("capability types with no vocabulary: %v\n"+
			"A type with no vocabulary is typed by nothing, and its `protection:` "+
			"marker cannot be read — so its retirement skips the D698 gate in silence.",
			missing)
	}
}

func repoRootFromVocab(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "Makefile")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("no Makefile above this directory")
	return ""
}

// D698: the shipped protection markers must survive the PARSER.
//
// The first version of this entry's mutant broke `LoadDir`'s reading of
// `protection:` and was caught by nothing, because the unit test beside the
// predicate builds a Vocabulary literal by hand and never parses a document. A test
// that constructs the value it is checking cannot see a parser that stopped
// producing it.
func TestShippedProtectionMarkersAreParsed(t *testing.T) {
	root := repoRootFromVocab(t)
	vocabs, err := LoadDir(filepath.Join(root, "spec", "vocab"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"capability.security.threatdetection",
		"capability.security.waf",
	}
	for _, typ := range want {
		v, ok := vocabs[typ]
		if !ok {
			t.Errorf("%s has no vocabulary", typ)
			continue
		}
		if !v.Protection {
			t.Errorf("%s ships `protection: true` and the loader did not read it — "+
				"its retirement would switch the control off with no consent (D698)", typ)
		}
	}
	// A control: not everything is a protection, or the marker says nothing.
	if v, ok := vocabs["capability.database.relational"]; ok && v.Protection {
		t.Error("a relational database is marked as a protection — the marker has " +
			"stopped distinguishing anything")
	}
}

// D701: every attribute this project SHIPS carries a description, because `explain`
// publishes it — and nine of 340 did not, so `explain` printed a kind, a mapping list
// and nothing that said what the attribute MEANS. An author reading that guesses.
//
// A gate rather than a loader rule: `--vocab` extends the built-in set with a reader's
// own types, and refusing to LOAD someone's undocumented-but-valid document would be a
// different and much heavier claim than the one this is making.
func TestEveryShippedAttributeIsDocumented(t *testing.T) {
	root := repoRootFromVocab(t)
	vocabs, err := LoadDir(filepath.Join(root, "spec", "vocab"))
	if err != nil {
		t.Fatal(err)
	}
	attrs := 0
	var bare []string
	for _, typ := range sortedVocabTypes(vocabs) {
		for _, path := range sortedAttrPaths(vocabs[typ].Attributes) {
			attrs++
			d, _ := vocabs[typ].Attributes[path]["description"].(string)
			if strings.TrimSpace(d) == "" {
				bare = append(bare, typ+"::"+path)
			}
		}
	}
	if attrs < 200 {
		t.Fatalf("walked %d attributes — the scan broke and this gate would pass over "+
			"an undocumented set (D328)", attrs)
	}
	if len(bare) > 0 {
		t.Errorf("shipped attributes with no description (%d of %d):\n  %s",
			len(bare), attrs, strings.Join(bare, "\n  "))
	}
}

func sortedVocabTypes(v map[string]Vocabulary) []string {
	out := make([]string, 0, len(v))
	for k := range v {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedAttrPaths(a map[string]map[string]any) []string {
	out := make([]string, 0, len(a))
	for k := range a {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// D701: a key nothing reads is refused, not dropped.
func TestUnknownVocabularyKeyIsRefused(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) error {
		if err := os.WriteFile(filepath.Join(dir, "v.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadDir(dir)
		return err
	}

	good := `capability: capability.database.relational
version: "0.1"
stateful: true
attributes:
  location.region:
    kind: string
    description: where it lives
`
	if err := write(good); err != nil {
		t.Fatalf("a well-formed vocabulary was refused: %v", err)
	}
	if err := write(good + "notes: a stray top-level key\n"); err == nil {
		t.Error("an unknown TOP-LEVEL key loaded clean — it is dropped in silence, which " +
			"is indistinguishable to its author from working")
	}
	badAttr := `capability: capability.database.relational
version: "0.1"
attributes:
  location.region:
    kind: string
    description: where it lives
    notes: a stray attribute key
`
	if err := write(badAttr); err == nil {
		t.Error("an unknown ATTRIBUTE key loaded clean — `note` was exactly this shape " +
			"and carried the best prose in the vocabulary to nobody")
	}
}
