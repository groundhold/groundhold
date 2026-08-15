package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// D1097. The site config names assets — a logo, a favicon, the Open Graph card the
// link-preview meta points at — and mkdocs resolves every one of them against
// `docs_dir`. Put them anywhere else in the repository and the build says nothing:
// the config is valid, the files exist, the tags render with correct absolute URLs,
// and the published site serves 404 for all of them.
//
// That is what happened. The card, the mark and the favicon were committed to a
// directory beside `docs_dir` rather than inside it. The merge was green, the deploy
// succeeded, `og:image` carried exactly the right URL, and every asset it named was
// missing — caught by fetching the live URLs, which is the only thing that could have
// caught it.
//
// A card nobody can fetch is worse than no card: a platform falls back to whatever it
// guesses while the page insists it has one.
func TestSiteAssetsResolveUnderTheDocsDirectory(t *testing.T) {
	root := repoRoot(t)
	site := filepath.Join(root, "website")

	rawCfg, err := os.ReadFile(filepath.Join(site, "mkdocs.yml"))
	if err != nil {
		t.Skipf("no site config here: %v", err)
	}
	cfg := string(rawCfg)

	// docs_dir is what everything below is relative to; assuming it would defeat the
	// point of the gate.
	dm := regexp.MustCompile(`(?m)^docs_dir:\s*(\S+)`).FindStringSubmatch(cfg)
	if dm == nil {
		t.Fatal("mkdocs.yml declares no docs_dir — this gate cannot resolve anything")
	}
	docs := filepath.Join(site, dm[1])

	refs := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^\s*(logo|favicon):\s*(\S+)`).
		FindAllStringSubmatch(cfg, -1) {
		refs[m[2]] = "mkdocs.yml " + m[1]
	}
	// Anything the override template builds from site_url is a URL the site promises
	// to serve, which makes it the same class as the two above.
	if rawTpl, err := os.ReadFile(filepath.Join(site, "overrides", "main.html")); err == nil {
		for _, m := range regexp.MustCompile(`config\.site_url\s*~\s*'([^']+)'`).
			FindAllStringSubmatch(string(rawTpl), -1) {
			refs[m[1]] = "overrides/main.html"
		}
	}

	// D328: with no references parsed this would pass over an empty set forever. The
	// site has a logo and a favicon today; if it stops having them, that is a decision
	// worth failing on rather than passing silently.
	if len(refs) < 2 {
		t.Fatalf("parsed %d site asset references — the probe broke, and an empty set "+
			"passes whatever the site actually serves", len(refs))
	}

	for ref, where := range refs {
		if _, err := os.Stat(filepath.Join(docs, ref)); err != nil {
			t.Errorf("%s names %q, which does not exist under %s.\n"+
				"mkdocs resolves assets against docs_dir, so the build stays green, the "+
				"tags render with correct URLs, and the published site serves 404. Move "+
				"the file under docs_dir rather than adjusting the reference.",
				where, ref, dm[1])
		}
	}
}
