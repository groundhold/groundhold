package render

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D329: the banner vocabulary is a PUBLISHED REGISTRY with registry rules —
// spec/presentation.md says "exactly one banner word from this closed set" and
// "additive-only; a published word never changes meaning". A closed set with no
// gate is the D311/D327 shape, and here it has an extra edge: the console is a
// SEPARATE repository that implements against this same glossary ("one glossary,
// no drift", CLAUDE.md), so a word that exists only in code reaches a consumer
// that never learned it.
//
// The gate asks the CODE for its set (exercising Pick across the verb/exit matrix
// — never scraping the source, D317) and compares it against the words published
// in the spec.
func TestBannerVocabularyMatchesTheSpec(t *testing.T) {
	got := implementedBanners(t)
	want := publishedBanners(t)

	var onlyCode, onlySpec []string
	for w := range got {
		if !want[w] {
			onlyCode = append(onlyCode, w)
		}
	}
	for w := range want {
		if !got[w] {
			onlySpec = append(onlySpec, w)
		}
	}
	sort.Strings(onlyCode)
	sort.Strings(onlySpec)

	if len(onlyCode) > 0 {
		t.Errorf("banner words emitted by the code but NOT published in "+
			"spec/presentation.md: %v\nA consumer built from the spec (the console "+
			"is a separate repo) would meet a word it never learned.", onlyCode)
	}
	if len(onlySpec) > 0 {
		t.Errorf("banner words published in spec/presentation.md that the code never "+
			"emits: %v\nEither the registry over-promises or a verb stopped speaking.",
			onlySpec)
	}
	if len(got) == 0 || len(want) == 0 {
		t.Fatal("one of the two sets is empty — the gate would be vacuous (D328)")
	}
}

// implementedBanners exercises Pick over the verb/exit/rollup matrix and collects
// every word it can produce. Asking the code, not reading it.
func implementedBanners(t *testing.T) map[string]bool {
	t.Helper()
	verbs := []string{"verify", "audit", "converge", "apply", "plan", "publish",
		"adopt", "unadopt", "resume", "repair", "anchor", "probe", "observe"}
	rollups := []Rollup{
		{},
		{Violated: []string{"c"}},
		{Unknown: []string{"c"}},
		{Unverifiable: []string{"c"}},
	}
	out := map[string]bool{}
	for _, v := range verbs {
		for _, exit := range []int{0, 1, 2, 3, 4, 5} {
			for _, r := range rollups {
				for _, code := range []string{"", "consent-required"} {
					w, _ := Pick(v, exit, code, r)
					if w == "" {
						continue
					}
					// REFUSED carries its code; the registry word is the stem
					if strings.HasPrefix(w, "REFUSED") {
						w = "REFUSED"
					}
					out[w] = true
				}
			}
		}
	}
	return out
}

// publishedBanners reads the words out of the REGISTRY table — the one that calls
// itself "this closed set" and that a consumer implements against. Deliberately NOT
// the union with the per-verb green table: a registry that is complete only when
// you also read a later section is not a registry, and the console (a separate
// repo) reads this one.
func publishedBanners(t *testing.T) map[string]bool {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "spec", "presentation.md"))
	if err != nil {
		t.Fatalf("read spec/presentation.md: %v", err)
	}
	out := map[string]bool{}
	// only the section that declares the closed set
	body := string(raw)
	if i := strings.Index(body, "## Banner vocabulary"); i >= 0 {
		body = body[i:]
		if j := strings.Index(body, "\n### "); j >= 0 {
			body = body[:j]
		}
	}
	cell := regexp.MustCompile("^\\|\\s*`([A-Z]+)(?: <code>)?`\\s*\\|")
	for _, line := range strings.Split(body, "\n") {
		if m := cell.FindStringSubmatch(line); m != nil {
			out[m[1]] = true
		}
	}
	return out
}
