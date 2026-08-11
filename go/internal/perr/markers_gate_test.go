package perr

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D623. README publishes `explain` as "the single place to ask about any noun the
// runtime emits — every machine error code and every vocabulary attribute". Four nouns
// the runtime emits were bare string literals, registered nowhere:
//
//	explain capsule-coupled             exit 1  "not an error code and not a vocabulary attribute"
//	explain capsule-trust-refused       exit 1
//	explain existence-not-witnessed     exit 1
//	explain logs-group-has-no-producer  exit 1
//
// Two are per-capability verdicts `restore --partial` hands a DR operator by design
// (`restore --help` says it "marks the rest unknown+code"), and two are compiler
// advisories. They are not process-exit codes, which is why they were never in
// spec/errors.md's table — and that absence was read as "nothing to register".
//
// This gate closes the class rather than the four: every `Code:` string literal the
// runtime emits must resolve in one registry or the other.
func TestEveryEmittedCodeIsExplainable(t *testing.T) {
	root := repoRoot(t)
	lit := regexp.MustCompile(`Code:\s*"([a-z][a-z0-9-]+)"`)
	assign := regexp.MustCompile(`code\s*=\s*"([a-z][a-z0-9-]+)"`)

	emitted := map[string]string{} // code -> where
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, "go", dir),
			func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
					strings.HasSuffix(path, "_test.go") {
					return err
				}
				body, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				rel, _ := filepath.Rel(root, path)
				for _, re := range []*regexp.Regexp{lit, assign} {
					for _, m := range re.FindAllStringSubmatch(string(body), -1) {
						if _, seen := emitted[m[1]]; !seen {
							emitted[m[1]] = rel
						}
					}
				}
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(emitted) == 0 {
		t.Fatal("no emitted codes found — the scan broke and this gate would pass " +
			"over anything (D328)")
	}
	// Positive control: the detector must match the shape it looks for (D603).
	if len(lit.FindAllString(`Code: "capsule-coupled"`, -1)) == 0 {
		t.Fatal("the detector cannot match its own example — it is not running")
	}

	var orphans []string
	for code, where := range emitted {
		if _, ok := Explain[Code(code)]; ok {
			continue
		}
		if _, ok := Markers[Code(code)]; ok {
			continue
		}
		orphans = append(orphans, code+" ("+where+")")
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Errorf("the runtime emits codes `explain` cannot answer about:\n  %s\n"+
			"README calls explain the single place to ask about any noun the runtime "+
			"emits. Register it in Explain (it carries an exit and belongs in "+
			"spec/errors.md) or in Markers (a per-item verdict or advisory).",
			strings.Join(orphans, "\n  "))
	}
}

// The two registries must stay disjoint: a code in both would explain differently
// depending on which lookup ran first.
func TestMarkersAndErrorCodesDoNotOverlap(t *testing.T) {
	if len(Markers) == 0 || len(Explain) == 0 {
		t.Fatal("a registry is empty — the gate would be vacuous (D328)")
	}
	for code := range Markers {
		if _, ok := Explain[code]; ok {
			t.Errorf("%s is registered as both an error code and a marker", code)
		}
	}
}
