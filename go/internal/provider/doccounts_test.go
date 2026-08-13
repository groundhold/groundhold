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
	"groundhold/internal/k8s"
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
		// D562: the fourth driver's count was published in this very table and
		// gated nowhere, for the same reason D561 found in the mappings gate —
		// k8s had no CapabilityMapper, so every "ask all the drivers" loop
		// silently meant three. It has one now.
		"k8s": k8s.NewDriver("https://example.invalid", "t"),
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

// D352: MATURITY.md is the honesty document, and it was the only one carrying
// these numbers WITHOUT a gate. It had drifted three ways — a 446-case suite that
// is now 494, GCP at 41 services when the drivers certify 42, and AWS at "46
// services" when 46 is the capability-TYPE count and the service count is 50.
// That last one is precisely the services-versus-types confusion D324 was written
// about, reappearing in the file that judges the project's own honesty.
//
// The per-cloud service counts are read from the drivers' certified maps, exactly
// as the README gate reads them; the conformance total is counted from the case
// files, since the suite is the source of truth for its own size.
func TestMaturityCountsMatchReality(t *testing.T) {
	got := map[string]int{}
	for name, p := range map[string]any{
		"AWS":   aws.NewDriver("eu-central-1"),
		"GCP":   gcp.NewDriver("p"),
		"Azure": azure.NewDriver("s"),
		// D562: the fourth driver's count was published in this very table and
		// gated nowhere, for the same reason D561 found in the mappings gate —
		// k8s had no CapabilityMapper, so every "ask all the drivers" loop
		// silently meant three. It has one now.
		"k8s": k8s.NewDriver("https://example.invalid", "t"),
	} {
		m, ok := p.(provider.CapabilityMapper)
		if !ok {
			t.Fatalf("%s driver is not a CapabilityMapper", name)
		}
		got[name] = len(m.ServiceCapabilities())
	}

	maturity := mustReadRepo(t, "docs/MATURITY.md")
	claim := func(what, pattern string, actual int) {
		m := regexp.MustCompile(pattern).FindStringSubmatch(maturity)
		if m == nil {
			t.Fatalf("docs/MATURITY.md no longer states %s in the form this gate "+
				"checks — update both, or the number is unguarded again", what)
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("%s: %q is not a number", what, m[1])
		}
		if n != actual {
			t.Errorf("MATURITY.md claims %s = %d, reality is %d — the honesty "+
				"document drifted", what, n, actual)
		}
	}
	claim("AWS services", `AWS drivers \((\d+) services`, got["AWS"])
	claim("GCP services", `GCP drivers \((\d+) services`, got["GCP"])
	claim("Azure services", `Azure drivers \((\d+) services`, got["Azure"])
	claim("k8s mapped services", `k8s driver \((\d+) mapped services\)`, got["k8s"])

	// The conformance suite's own size, counted from the cases it runs.
	cases, err := filepath.Glob(filepath.Join(repoRoot(t), "conformance", "cases", "*.yaml"))
	if err != nil {
		t.Fatalf("glob conformance cases: %v", err)
	}
	total := 0
	for _, f := range cases {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		total += len(regexp.MustCompile(`(?m)^\s*- name:`).FindAllString(string(raw), -1))
	}
	claim("the conformance suite size", `one (\d+)-case conformance suite`, total)
	_, dual := suiteCounts(t)
	claim("the dual subset", `(\d+) of the \d+ run through both`, dual)
}

// D353: the docs site states the suite's size and its DUAL subset. Both were
// wrong — the site said 407 cases and described the whole suite as something
// "two independent implementations must pass identically", when 274 of 494 carry
// `impl: go`. The split is the honest claim, so it is the one that is gated.
func TestWebsiteConformanceCountsMatchTheSuite(t *testing.T) {
	total, dual := suiteCounts(t)

	check := func(doc, what, pattern string, actual int) {
		raw := mustReadRepo(t, doc)
		m := regexp.MustCompile(pattern).FindStringSubmatch(raw)
		if m == nil {
			t.Fatalf("%s no longer states %s in the form this gate checks — "+
				"update both, or the number is unguarded again", doc, what)
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("%s: %q is not a number", what, m[1])
		}
		if n != actual {
			t.Errorf("%s claims %s = %d, the suite holds %d", doc, what, n, actual)
		}
	}
	check("website/pages/conformance.md", "the suite size", `(\d+) cases, plus seeded`, total)
	check("website/pages/conformance.md", "the dual subset", `\*\*(\d+) run against BOTH`, dual)
	check("website/pages/quickstart.md", "the suite size", `conformance suite \((\d+) cases\)`, total)
	check("website/pages/quickstart.md", "the dual subset", `(\d+) run through both implementations`, dual)
}

// suiteCounts reads the suite's own size and its dual subset from the case files.
// A case is dual unless it carries `impl: go`; verified against both runners,
// which report exactly these totals.
func suiteCounts(t *testing.T) (total, dual int) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(repoRoot(t), "conformance", "cases", "*.yaml"))
	if err != nil {
		t.Fatalf("glob cases: %v", err)
	}
	nameRe := regexp.MustCompile(`^\s*-\s+name:\s*(\S+)`)
	implRe := regexp.MustCompile(`^\s+impl:\s*go\b`)
	isDual := map[string]bool{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		cur := ""
		for _, line := range strings.Split(string(raw), "\n") {
			if m := nameRe.FindStringSubmatch(line); m != nil {
				cur = m[1]
				isDual[cur] = true
				continue
			}
			if cur != "" && implRe.MatchString(line) {
				isDual[cur] = false
			}
		}
	}
	for _, d := range isDual {
		total++
		if d {
			dual++
		}
	}
	if total < 400 {
		t.Fatalf("only %d cases parsed — the parser broke, not the docs", total)
	}
	return total, dual
}

// D476: CLAUDE.md's suite counts, gated like its vocabulary count already was.
//
// The file said 514 cases / 232 dual; the suite holds 521 / 235. Nobody was misled into
// a wrong verdict by that — but CLAUDE.md is the document every agent working in this
// repository reads first, its header says the instructions OVERRIDE default behaviour,
// and three lines below the stale numbers it says "These numbers drift. Read them from
// the tools, never from this file." It was right, and the drift was sitting under the
// warning.
//
// The vocabulary count beside them has been gated since D324. The case counts were not,
// which is the whole difference between a number that stays true and a number that
// carries a disclaimer.
func TestClaudeMdSuiteCountsMatchTheSuite(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "CLAUDE.md"))
	if os.IsNotExist(err) {
		t.Skip("CLAUDE.md not present (the public export tree omits it); the website " +
			"conformance-count gate still guards these numbers")
	}
	if err != nil {
		t.Fatalf("read CLAUDE.md: %v", err)
	}
	total, dual := suiteCounts(t)
	claude := string(raw)

	for _, c := range []struct {
		what, pattern string
		actual        int
	}{
		{"the suite size", `(\d+) conformance cases through the Go binary`, total},
		{"the dual subset", `\((\d+) of them dual`, dual},
	} {
		m := regexp.MustCompile(c.pattern).FindStringSubmatch(claude)
		if m == nil {
			t.Fatalf("CLAUDE.md no longer states %s in the form this gate checks — "+
				"update both, or the number is unguarded again", c.what)
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("%s: %q is not a number", c.what, m[1])
		}
		if n != c.actual {
			t.Errorf("CLAUDE.md claims %s = %d, the suite holds %d", c.what, n, c.actual)
		}
	}
}
