package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D689. The quickstart's only real-cloud instruction told a newcomer to
// authenticate with `gcloud auth application-default login`. The GCP driver does
// not read ADC — the README says so in those words ("Not ADC") — so the documented
// setup cannot work, and the two published documents contradicted each other on a
// credential boundary.
//
// The driver's source is the authority. This gate reads the environment variables
// the auth path actually consults and requires every document that tells a reader
// how to authenticate to name them, and none to send the reader to ADC as if it
// were enough.
func TestCredentialDocsNameWhatTheDriverReads(t *testing.T) {
	skipIfExported(t, "the driver sources")
	root := repoRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, "go", "internal", "gcp", "auth.go"))
	if err != nil {
		t.Fatal(err)
	}
	envs := map[string]bool{}
	for _, m := range regexp.MustCompile(`os\.Getenv\("([A-Z0-9_]+)"\)`).
		FindAllStringSubmatch(string(raw), -1) {
		envs[m[1]] = true
	}
	if len(envs) < 2 {
		t.Fatalf("found %d credential env vars in the gcp auth path — the probe "+
			"broke and this gate would pass on anything", len(envs))
	}

	for _, doc := range []string{
		filepath.Join(root, "README.md"),
		filepath.Join(root, "website", "pages", "quickstart.md"),
	} {
		body, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		name := filepath.Base(doc)
		if !strings.Contains(text, "application-default") &&
			!strings.Contains(text, "GROUNDHOLD_GCP") {
			continue // this document does not discuss GCP credentials
		}
		var missing []string
		for env := range envs {
			if !strings.Contains(text, env) {
				missing = append(missing, env)
			}
		}
		if len(missing) > 0 {
			t.Errorf("%s explains GCP credentials without naming %s — the driver "+
				"reads those and nothing else", name, strings.Join(missing, ", "))
		}
		// ADC may be MENTIONED (to say it is not used); it may not be offered as
		// the way in. Whitespace is normalised first: these documents wrap, and a
		// line-based check let a claim split across a newline escape — the same
		// shape D659's first gate had, where the pipe sat two continuation lines
		// below the command.
		// Markdown emphasis and code ticks are removed before matching: the
		// negation in these documents is written `**not**`, and a substring check
		// for "not application default" does not see through the asterisks. The
		// first version of this gate missed exactly that and its mutant survived.
		flat := strings.Join(strings.Fields(
			strings.NewReplacer("*", "", "`", "", "_", "").Replace(text)), " ")
		for _, at := range indexesOf(flat, "application-default login") {
			lo, hi := at-220, at+220
			if lo < 0 {
				lo = 0
			}
			if hi > len(flat) {
				hi = len(flat)
			}
			window := flat[lo:hi]
			// Only an explicit NEGATION excuses the mention. Accepting a nearby
			// `print-access-token` as the excuse let the mutant survive: the
			// corrected example sits inside the same window as the claim it
			// corrects, so its presence says nothing about whether the sentence
			// above it is true.
			lower := strings.ToLower(window)
			if !strings.Contains(lower, "not application default") &&
				!strings.Contains(lower, "not adc") {
				t.Errorf("%s sends the reader to ADC without saying the driver does "+
					"not read it:\n\t…%s…", name, window)
			}
		}
	}
}

func indexesOf(s, sub string) []int {
	var out []int
	for i := 0; ; {
		j := strings.Index(s[i:], sub)
		if j < 0 {
			return out
		}
		out = append(out, i+j)
		i += j + len(sub)
	}
}
