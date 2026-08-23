package provider_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// D1250. D1242 found that `converged` was claimed in three places and only one of them
// said what had been compared — "the world already matches ON EVERY ATTRIBUTE THIS RUN
// CAN COMPARE" rather than the unqualified "the world already matches the candidate".
// The runtime was corrected and gated.
//
// The published side was not. Four documents still showed the retracted sentence as the
// output a reader should expect:
//
//	README.md                      the two-run demonstration
//	examples/laptop/README.md      the same run, in the example's own README
//	website/pages/quickstart.md    twice — the two-minute path and the laptop example
//
// Found by executing the quickstart literally rather than reading it: the page promises
// `✓ converged — the world already matches the candidate` and the binary prints that
// sentence with its scope attached. So the over-claim D1242 removed from the runtime went
// on being published, for exactly the readers who have not run it yet — the ones who have
// only the document.
//
// The gate is the rule itself rather than a list of the four files: an unqualified
// "already matches" in published prose is the claim D1242 retracted.

// The scoping words that make the claim honest. Any one of them, close to the claim.
var scopeWords = []string{"can compare", "could compare", "this run"}

func TestNoPublishedProseRepublishesTheUnscopedConvergedClaim(t *testing.T) {
	root := repoRoot(t)
	// Markdown only. `examples/check.sh` matches the same phrase as a shell GLOB against
	// the binary's output — a matcher against reality, not a claim about it, and a
	// substring pattern stays correct when the sentence grows. Restricting the scan is
	// the deliberate part; widening it would fail a file that is doing the right thing.
	var claims, unscoped []string
	for _, rel := range takeoverProofDocs(t, root) {
		if !strings.HasSuffix(rel, ".md") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		body := string(raw)
		for i := 0; ; {
			j := strings.Index(body[i:], "already matches")
			if j < 0 {
				break
			}
			at := i + j
			i = at + len("already matches")
			claims = append(claims, rel)
			window := near(body, at)
			var scoped bool
			for _, w := range scopeWords {
				if strings.Contains(window, w) {
					scoped = true
				}
			}
			if !scoped {
				unscoped = append(unscoped, rel+" ("+excerpt(body, at)+")")
			}
		}
	}

	// D328: the subject must exist. The demonstration that convergence is PROVEN rather
	// than assumed is the project's central claim; if no published document shows it any
	// more, that is a change to notice deliberately, not a gate quietly passing.
	if len(claims) < 3 {
		t.Fatalf("only %d published documents show the converged banner (%v) — the scan is "+
			"broken, or the demonstration has gone unpublished", len(claims), claims)
	}
	sort.Strings(unscoped)
	if len(unscoped) > 0 {
		t.Errorf("published prose shows the converged banner without the scope the runtime "+
			"attaches:\n  %s\n\n"+
			"D1242 removed the unqualified \"the world already matches the candidate\" "+
			"because it claims more than the run compared. A document that keeps printing "+
			"it re-publishes the retracted claim to the readers who have only the "+
			"document — and it no longer matches what the binary says.",
			strings.Join(unscoped, "\n  "))
	}
}

// The other direction: a quoted banner must be something the runtime actually prints.
// Go splits these literals across lines, so the source is normalised by removing the
// concatenation joins before looking — the quote-naive shape that produced false results
// twice in this codebase.
func TestTheQuotedConvergedBannerIsWhatTheBinaryPrints(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "go", "internal", "converge", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	// Rejoin `"... " +\n\t\t\t"..."` into one literal.
	for _, join := range []string{"\" +\n\t\t\t\t\"", "\" +\n\t\t\t\"", "\" +\n\t\t\"", "\" +\n\t\""} {
		src = strings.ReplaceAll(src, join, "")
	}
	if !strings.Contains(src, "already matches the candidate on every attribute this run can compare") {
		t.Fatal("the converged banner no longer reads as the documents quote it — either " +
			"the banner changed and the published examples must change with it, or this " +
			"normalisation broke and the gate is reading half a string")
	}
	for _, rel := range []string{"README.md", "examples/laptop/README.md"} {
		blob, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for _, line := range strings.Split(string(blob), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "✓ converged") {
				continue
			}
			quoted := strings.TrimPrefix(line, "✓ converged — ")
			if !strings.Contains(src, quoted) {
				t.Errorf("%s shows a converged banner the binary does not print:\n  %s\n\n"+
					"A reader compares their real output against this line.", rel, quoted)
			}
		}
	}
}
