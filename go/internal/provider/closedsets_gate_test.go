package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// D690. `addon.name` declares no `enum`, and the three drivers enforce three
// DISJOINT closed sets — an EKS addon is a versioned package, a GKE addon is a
// cluster flag, an AKS addon is an addonProfile key. Pairwise intersection: empty.
// The vocabulary's description listed only the AWS names, so a "portable"
// capability attribute was portable to exactly one cloud, and AUTHORING.md §3's
// promise ("the loader rejects a candidate value outside it") bought nothing.
//
// No enum is added, deliberately: the union of three disjoint sets is not a set any
// single candidate can draw from, and declaring it would make the loader accept a
// name the chosen cloud refuses while implying portability. The sets are published
// per provider instead — and this gate checks the publication against the DRIVERS,
// so the vocabulary cannot fall behind the code that enforces them.
func TestPublishedAddonSetsMatchTheDrivers(t *testing.T) {
	skipIfExported(t, "the driver sources")
	root := repoRoot(t)

	// The drivers' own maps, read as source because they are package-private tables
	// rather than an exported API. Asserted non-empty so a rename cannot empty the
	// subject and pass.
	sets := map[string][]string{}
	for prov, file := range map[string]string{
		"gcp":   filepath.Join(root, "go", "internal", "gcp", "gke_addon.go"),
		"azure": filepath.Join(root, "go", "internal", "azure", "aks_addon.go"),
	} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range regexp.MustCompile(`(?m)^\t"([a-z0-9-]+)":`).
			FindAllStringSubmatch(string(raw), -1) {
			sets[prov] = append(sets[prov], m[1])
		}
		sort.Strings(sets[prov])
		if len(sets[prov]) < 5 {
			t.Fatalf("%s: found %d canonical addon names — the probe broke and this "+
				"gate would pass on anything", prov, len(sets[prov]))
		}
	}

	raw, err := os.ReadFile(filepath.Join(root, "spec", "vocab",
		"capability.cluster.addon.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Attributes map[string]map[string]any `yaml:"attributes"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	spec := doc.Attributes["addon.name"]
	if spec == nil {
		t.Fatal("addon.name is gone from the vocabulary")
	}
	if _, has := spec["enum"]; has {
		t.Error("addon.name declares an enum — the three driver sets are disjoint, " +
			"so any single list is either wrong for two clouds or a union no " +
			"candidate can draw from (D690)")
	}
	maps, _ := spec["mappings"].(map[string]any)
	if len(maps) < 3 {
		t.Fatalf("addon.name publishes %d mappings — expected one per cloud", len(maps))
	}
	for prov, names := range sets {
		text := ""
		for k, v := range maps {
			if strings.HasPrefix(k, prov+".") {
				text = strings.ToLower(strings.Join(strings.Fields(
					strings.TrimSpace(v.(string))), " "))
			}
		}
		if text == "" {
			t.Errorf("no %s mapping to check", prov)
			continue
		}
		var missing []string
		for _, n := range names {
			if !strings.Contains(text, n) {
				missing = append(missing, n)
			}
		}
		if len(missing) > 0 {
			t.Errorf("the %s mapping does not publish the names its driver accepts: "+
				"%s — an author reading the vocabulary cannot tell which names this "+
				"cloud takes", prov, strings.Join(missing, ", "))
		}
	}
}
