package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"groundhold/internal/aws"
	"groundhold/internal/azure"
	"groundhold/internal/gcp"
	"groundhold/internal/provider"
)

// D324: a number written in prose drifts silently.
//
// CLAUDE.md claimed "153 conformance cases ... six vocabularies" when the suite
// was 471 and the vocabularies 52 — the file that shapes how every contributor
// understands the project, understating it threefold. The README claimed "~128
// service mappings across AWS (46), GCP (41), Azure (41)"; the drivers certify 133
// mappings (50/42/41), and the 46/41/41 were capability TYPES, a distinction this
// repo cares about (D76: one type, many services).
//
// Nobody lied. Prose has no gate, so it rots while the code moves. This is that
// gate for the counts that are cheap to check: the per-cloud service and
// capability-type totals, read from the drivers' own certified maps (D317 — never
// scrape the source) and compared against what the docs claim.
//
// It deliberately does NOT police every number in the docs. It covers the ones a
// reader uses to judge the size of the system, which are exactly the ones that
// drifted.
func TestDocServiceCountsMatchTheDrivers(t *testing.T) {
	type fact struct{ services, types int }
	got := map[string]fact{}
	for name, p := range map[string]any{
		"AWS":   aws.NewDriver("eu-central-1"),
		"GCP":   gcp.NewDriver("p"),
		"Azure": azure.NewDriver("s"),
	} {
		m, ok := p.(provider.CapabilityMapper)
		if !ok {
			t.Fatalf("%s driver is not a CapabilityMapper — the counts cannot be proven", name)
		}
		sc := m.ServiceCapabilities()
		types := map[string]bool{}
		for _, c := range sc {
			types[c] = true
		}
		got[name] = fact{services: len(sc), types: len(types)}
	}
	total := got["AWS"].services + got["GCP"].services + got["Azure"].services

	readme := mustReadRepo(t, "README.md")

	// "133 service mappings across AWS (50), GCP (42) and Azure (41)"
	m := regexp.MustCompile(`(\d+) service mappings across AWS \((\d+)\), GCP \((\d+)\) and Azure \((\d+)\)`).
		FindStringSubmatch(readme)
	if m == nil {
		t.Fatal("README.md no longer states the service-mapping counts in the form " +
			"this gate checks — update both, or the number is unguarded again")
	}
	check := func(what string, claimed string, actual int) {
		n, err := strconv.Atoi(claimed)
		if err != nil {
			t.Fatalf("%s: %q is not a number", what, claimed)
		}
		if n != actual {
			t.Errorf("README claims %s = %d, the drivers certify %d — a prose number "+
				"drifted (run this test's source for how to read the real one)",
				what, n, actual)
		}
	}
	check("total service mappings", m[1], total)
	check("AWS services", m[2], got["AWS"].services)
	check("GCP services", m[3], got["GCP"].services)
	check("Azure services", m[4], got["Azure"].services)

	// "fulfilling 46/41/41 distinct capability TYPES"
	tm := regexp.MustCompile(`(\d+)/(\d+)/(\d+) distinct capability TYPES`).FindStringSubmatch(readme)
	if tm == nil {
		t.Fatal("README.md no longer states the capability-type counts in the form " +
			"this gate checks")
	}
	check("AWS capability types", tm[1], got["AWS"].types)
	check("GCP capability types", tm[2], got["GCP"].types)
	check("Azure capability types", tm[3], got["Azure"].types)
}

// The vocabulary count in CLAUDE.md is the other number a reader uses to size the
// system, and it is one directory listing away from the truth.
func TestClaudeMdVocabularyCountMatchesDisk(t *testing.T) {
	root := repoRoot(t)
	files, err := filepath.Glob(filepath.Join(root, "spec", "vocab", "capability.*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	rawClaude, err := os.ReadFile(filepath.Join(root, "CLAUDE.md"))
	if os.IsNotExist(err) {
		t.Skip("CLAUDE.md not present (the public export tree omits it); the README-based count check still guards this number")
	}
	if err != nil {
		t.Fatalf("read CLAUDE.md: %v", err)
	}
	claude := strings.ReplaceAll(string(rawClaude), " ", " ")
	m := regexp.MustCompile(`(\d+) vocabularies wired into`).FindStringSubmatch(claude)
	if m == nil {
		t.Fatal("CLAUDE.md no longer states the vocabulary count in the form this gate checks")
	}
	n, _ := strconv.Atoi(m[1])
	if n != len(files) {
		t.Errorf("CLAUDE.md claims %d vocabularies, spec/vocab holds %d", n, len(files))
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// internal/provider -> go -> repo root
	abs, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func mustReadRepo(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return strings.ReplaceAll(string(raw), " ", " ")
}
