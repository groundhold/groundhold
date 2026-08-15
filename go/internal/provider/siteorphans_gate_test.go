package provider_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// mkdocs builds every markdown file under `docs_dir`, whether or not anything links
// to it. A file put there to sit beside the assets it describes becomes a published
// page at a guessable URL, listed in the sitemap and offered to search engines, and
// nothing in the build says so: the deploy is green, the navigation looks right, and
// the page is simply there.
//
// That is how internal brand-asset notes came to be served at /img/ — reachable, in
// the sitemap, and never once decided upon. Benign content, but the decision was made
// by a directory layout rather than by a person, and the next file dropped in that
// directory gets published on the same terms.
//
// So the rule is: every page is either in the navigation or explicitly withheld.
// `exclude_docs` is the place to say "not a page", and saying it is deliberate — which
// is the whole difference between withholding something and forgetting it exists.
func TestEveryBuiltPageIsNavigatedOrDeliberatelyExcluded(t *testing.T) {
	root := repoRoot(t)
	site := filepath.Join(root, "website")

	raw, err := os.ReadFile(filepath.Join(site, "mkdocs.yml"))
	if err != nil {
		t.Skipf("no site config here: %v", err)
	}

	var cfg struct {
		DocsDir     string    `yaml:"docs_dir"`
		Nav         yaml.Node `yaml:"nav"`
		ExcludeDocs string    `yaml:"exclude_docs"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("site config does not parse: %v", err)
	}
	if cfg.DocsDir == "" {
		t.Fatal("site config declares no docs_dir — this gate cannot resolve anything")
	}

	// Every scalar in the nav tree that looks like a page, however deeply nested.
	navigated := map[string]bool{}
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		if n.Kind == yaml.ScalarNode && strings.HasSuffix(n.Value, ".md") {
			navigated[filepath.Clean(n.Value)] = true
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(&cfg.Nav)
	if len(navigated) == 0 {
		t.Fatal("nav names no pages — this gate would call every page an orphan, or " +
			"nothing an orphan, depending on which way it failed. Neither is a check.")
	}

	withheld := map[string]bool{}
	for _, line := range strings.Split(cfg.ExcludeDocs, "\n") {
		if p := strings.TrimSpace(line); p != "" && !strings.HasPrefix(p, "#") {
			withheld[filepath.Clean(p)] = true
		}
	}

	docs := filepath.Join(site, cfg.DocsDir)
	var found, orphans []string
	err = filepath.Walk(docs, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".md") {
			return err
		}
		rel, relErr := filepath.Rel(docs, path)
		if relErr != nil {
			return relErr
		}
		found = append(found, rel)
		if !navigated[rel] && !withheld[rel] {
			orphans = append(orphans, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("cannot walk docs_dir %q: %v", cfg.DocsDir, err)
	}
	if len(found) == 0 {
		t.Fatalf("no markdown under docs_dir %q — a gate that finds nothing must not "+
			"report success", cfg.DocsDir)
	}

	if len(orphans) > 0 {
		sort.Strings(orphans)
		t.Errorf("these files under %s build into published pages but appear in "+
			"neither nav nor exclude_docs:\n  %s\n\n"+
			"mkdocs publishes them because of where they sit, not because anyone "+
			"chose to. Put each in nav (it is a page) or in exclude_docs (it is not).",
			cfg.DocsDir, strings.Join(orphans, "\n  "))
	}
}
