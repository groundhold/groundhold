package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The README leads with a maturity sentence — public, experimental, an RFC you can
// run, not GA. The site's landing page carried no such sentence at all. Both are
// front doors, and only one of them told the truth about what this is.
//
// The asymmetry matters more than the omission. A reader who arrives at the
// repository is warned before the first heading; a reader who arrives at the site
// reads the whole pitch, follows the download line, and learns the maturity only if
// they happen to click through to a secondary page. The claim was not wrong
// anywhere — it was absent exactly where the audience is least equipped to guess it.
//
// So bind them: the site's landing page must carry the README's status sentence
// verbatim. One direction only — the README is the source, the site follows — which
// means editing the README to soften or sharpen the claim breaks this gate until the
// site says the same thing.
func TestSiteLandingPageCarriesTheReadmeStatus(t *testing.T) {
	root := repoRoot(t)

	rawReadme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatalf("no README to take the status from: %v", err)
	}

	status := regexp.MustCompile(`(?m)^\*\*Status:[^\n]*$`).FindString(string(rawReadme))
	if status == "" {
		t.Fatal("README states no **Status:** line — this gate has nothing to bind " +
			"the site to, and would pass over an unmarked pre-1.0 project")
	}
	if !strings.Contains(status, "experimental") {
		t.Fatalf("README status line does not name the maturity: %q\n"+
			"If the project genuinely reached GA, say so here AND on the landing "+
			"page, and rewrite this gate deliberately.", status)
	}

	// Resolve the landing page the way mkdocs does, so moving docs_dir cannot leave
	// this gate reading a file the published site no longer builds from.
	site := filepath.Join(root, "website")
	rawCfg, err := os.ReadFile(filepath.Join(site, "mkdocs.yml"))
	if err != nil {
		t.Skipf("no site config here: %v", err)
	}
	dm := regexp.MustCompile(`(?m)^docs_dir:\s*(\S+)`).FindStringSubmatch(string(rawCfg))
	if dm == nil {
		t.Fatal("mkdocs.yml declares no docs_dir — this gate cannot resolve the landing page")
	}

	landing := filepath.Join(site, dm[1], "index.md")
	rawLanding, err := os.ReadFile(landing)
	if err != nil {
		t.Fatalf("no landing page under docs_dir %q: %v", dm[1], err)
	}

	if !strings.Contains(string(rawLanding), status) {
		rel, _ := filepath.Rel(root, landing)
		t.Errorf("%s does not carry the README's status sentence.\nREADME says:\n  %s\n"+
			"The landing page is the front door for everyone who arrives from a link "+
			"rather than from the repository; it must say the same thing, verbatim.",
			rel, status)
	}
}
