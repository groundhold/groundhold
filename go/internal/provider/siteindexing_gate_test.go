package provider_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Two things a documentation site gets wrong quietly, because nothing in the build
// notices and the published pages look correct either way.
//
// The first is `robots.txt`. Its absence is survivable — a crawler that gets a 404
// assumes it may read everything — but its CONTENTS are not: one stray `Disallow: /`
// removes the whole site from every search engine, and the only symptom is traffic
// that never arrives. There is no error, no warning, and no page that looks wrong.
// A file with that much destructive reach should not be unattended.
//
// The second is the landing page's title. Material renders "<page title> - <site
// name>" everywhere except the homepage, where it renders the site name alone. Every
// sub-page therefore said what it was and the front door said "Groundhold" — the one
// line a search result shows, spent on a word nobody has heard yet.
//
// This gate holds both, and holds the second one honestly: it is not enough for the
// title to be configured, the template must actually read it. A configuration key
// nothing consumes is the same defect in a different costume.
func TestSiteIsIndexableAndTheLandingPageSaysWhatItIs(t *testing.T) {
	root := repoRoot(t)
	site := filepath.Join(root, "website")

	raw, err := os.ReadFile(filepath.Join(site, "mkdocs.yml"))
	if err != nil {
		t.Skipf("no site config here: %v", err)
	}

	var cfg struct {
		SiteName string `yaml:"site_name"`
		SiteURL  string `yaml:"site_url"`
		DocsDir  string `yaml:"docs_dir"`
		Extra    struct {
			HomepageTitle string `yaml:"homepage_title"`
		} `yaml:"extra"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("site config does not parse: %v", err)
	}
	if cfg.SiteURL == "" || cfg.DocsDir == "" || cfg.SiteName == "" {
		t.Fatalf("site config is missing site_url/docs_dir/site_name (%q/%q/%q) — "+
			"this gate would have nothing to check", cfg.SiteURL, cfg.DocsDir, cfg.SiteName)
	}

	// --- robots.txt: present, permissive, and pointing at the sitemap we publish ---

	robots := filepath.Join(site, cfg.DocsDir, "robots.txt")
	rawRobots, err := os.ReadFile(robots)
	if err != nil {
		t.Fatalf("no robots.txt under docs_dir %q: %v\n"+
			"Its absence is tolerable to crawlers but leaves the sitemap unannounced, "+
			"and leaves the file's contents unattended the day someone does add one.",
			cfg.DocsDir, err)
	}
	body := string(rawRobots)

	for _, line := range strings.Split(body, "\n") {
		if strings.EqualFold(strings.TrimSpace(line), "Disallow: /") {
			t.Errorf("robots.txt contains a blanket %q.\n"+
				"That removes the entire site from every search engine, and nothing "+
				"else in this repository would notice: the pages build, deploy and "+
				"render exactly as before. If this is deliberate, say so here and "+
				"rewrite this gate.", strings.TrimSpace(line))
		}
	}

	wantSitemap := strings.TrimSuffix(cfg.SiteURL, "/") + "/sitemap.xml"
	if !strings.Contains(body, wantSitemap) {
		t.Errorf("robots.txt does not name the sitemap %s.\n"+
			"The URL is derived from site_url, so moving the site to another domain "+
			"breaks this until robots.txt follows.", wantSitemap)
	}

	// --- the landing page title: configured, distinct, and actually consumed ---

	title := strings.TrimSpace(cfg.Extra.HomepageTitle)
	if title == "" {
		t.Fatal("extra.homepage_title is unset — the landing page falls back to the " +
			"site name alone, which is what this gate exists to prevent")
	}
	if title == cfg.SiteName {
		t.Errorf("extra.homepage_title is just the site name (%q) — that is the "+
			"fallback this replaces, restated", cfg.SiteName)
	}
	if len(title) > 70 {
		t.Errorf("extra.homepage_title is %d characters; search results truncate "+
			"around 60-70, so the tail is written for nobody: %q", len(title), title)
	}

	tpl, err := os.ReadFile(filepath.Join(site, "overrides", "main.html"))
	if err != nil {
		t.Fatalf("no template override to read the title: %v", err)
	}
	if !strings.Contains(string(tpl), "config.extra.homepage_title") {
		t.Error("overrides/main.html never reads config.extra.homepage_title — the " +
			"title is configured and inert, which renders exactly as the bug did")
	}
}
