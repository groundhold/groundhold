package azure

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// D553, the third instance of D552's class. Container Apps is Azure's only
// implementation of capability.workload.container, so nothing here is a sibling
// mix-up — but the vocabulary named `azure.containerapps` on one attribute of nine
// while the driver measures four. A reader asking what groundhold checks on Azure
// found silence for three of them, next to detailed lines for AWS and GCP, which
// reads as "not supported on Azure" rather than "documented nowhere".
//
// Same instrument as D552: run the driver, compare against what is published.
func TestContainerAppsNamesItsOwnMappings(t *testing.T) {
	srv := acaArmFake(t, "api")
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	res := d.createContainerApp("prod", "api", acaAttrs(), acaImpl(), 1)
	if res.Status != "succeeded" || res.ProviderID == "" {
		t.Fatalf("setup create: %+v", res)
	}
	obs, _, err := d.observeContainerApp("api", res.ProviderID)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(obs) < 3 {
		t.Fatalf("observe emitted %d observations — the fixture stopped exercising it", len(obs))
	}

	doc := readVocabACA(t, "capability.workload.container.yaml")
	if len(doc) == 0 {
		t.Fatal("no attributes read from the vocabulary — this gate would be vacuous")
	}
	var missing []string
	for _, o := range obs {
		if o.Path == "resource.absent" || o.Path == "service.managed" {
			continue
		}
		spec, ok := doc[o.Path]
		if !ok {
			missing = append(missing, "emits "+o.Path+" — the vocabulary has no such attribute")
			continue
		}
		if !spec["azure.containerapps"] {
			named := make([]string, 0, len(spec))
			for k := range spec {
				named = append(named, k)
			}
			sort.Strings(named)
			missing = append(missing, "measures "+o.Path+" but the mappings name only ["+
				strings.Join(named, " ")+"]")
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("azure.containerapps measures %d attributes the vocabulary does not credit "+
			"to it:\n  %s\nAn attribute documented for the other clouds and silent for this "+
			"one reads as unsupported.", len(missing), strings.Join(missing, "\n  "))
	}
}

func readVocabACA(t *testing.T, file string) map[string]map[string]bool {
	_, self, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(self), "..", "..", "..", "spec", "vocab", file))
	if err != nil {
		t.Fatalf("read vocabulary: %v", err)
	}
	var doc struct {
		Attributes map[string]struct {
			Mappings map[string]any `yaml:"mappings"`
		} `yaml:"attributes"`
	}
	// A parse failure must not read as "declares no mappings" (D552).
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("vocabulary %s is unparseable: %v", file, err)
	}
	out := map[string]map[string]bool{}
	for p, a := range doc.Attributes {
		set := map[string]bool{}
		for k := range a.Mappings {
			set[k] = true
		}
		out[p] = set
	}
	return out
}
