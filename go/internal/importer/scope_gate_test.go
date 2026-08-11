package importer

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// D572. `spec/onboarding.md` describes `hints` at length — the translation rules, the
// allowlist, why `expected` carries no derivation claim, why the document is not
// hashed. It never says WHICH resource types are translated. A reader takes
// "terraform state v4 or a pulumi checkpoint into an AdoptionHints document" as
// general, and it maps ONE capability: `capability.database.relational`, from three
// terraform types and three pulumi URNs.
//
// Run against an ordinary AWS state — an S3 bucket, an RDS instance, an EC2 instance
// — every resource comes back skipped. The tool is honest at the moment of use (each
// skip is a named diagnostic, never a silent drop, which the spec does promise), so
// the harm is bounded: what is missing is the scope in the DOCUMENT, before anyone
// spends an afternoon on it.
//
// Gated rather than merely written down, because a scope stated in prose is exactly
// what falls behind the code that changes (D465, D552). Adding a type now forces the
// sentence to change with it.
func TestOnboardingDocStatesTheImporterScope(t *testing.T) {
	_, self, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(self), "..", "..", "..")
	src, err := os.ReadFile(filepath.Join(filepath.Dir(self), "importer.go"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join(root, "spec", "onboarding.md"))
	if err != nil {
		t.Fatal(err)
	}

	// what the CODE translates: every quoted token in a `case` arm of the two
	// dispatches, which is where a new type must be added.
	tok := regexp.MustCompile(`case ("(?:google|aws|azurerm|gcp:|aws:|azure:)[^"]*"(?:, "[^"]*")*):`)
	mapped := map[string]bool{}
	for _, m := range tok.FindAllStringSubmatch(string(src), -1) {
		for _, q := range strings.Split(m[1], ", ") {
			mapped[strings.Trim(q, `"`)] = true
		}
	}
	if len(mapped) < 3 {
		t.Fatalf("found %d mapped types in the importer — the probe broke, and this "+
			"gate would pass on anything", len(mapped))
	}
	var missing []string
	for typ := range mapped {
		if !strings.Contains(string(doc), typ) {
			missing = append(missing, typ)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("spec/onboarding.md never names %d of the types `hints` translates:\n  %s\n"+
			"The document explains the mechanism in full and leaves its SCOPE to be "+
			"inferred, so a reader with an AWS state learns it the hard way.",
			len(missing), strings.Join(missing, "\n  "))
	}
}
