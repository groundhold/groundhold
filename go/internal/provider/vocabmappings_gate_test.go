package provider_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"groundhold/internal/aws"
	"groundhold/internal/azure"
	"groundhold/internal/gcp"
	"groundhold/internal/k8s"
)

// D538. Three findings this week turned on the vocabulary's `mappings:` list, and
// the sharpest of them settled a live production dispute with it: the driver
// observed `network.publicExposure: true` for an IAM-fronted Function URL, and
// the mapping — "AuthType NONE PLUS a resource-based grant to principal * (both,
// or the function stays private)" — is what proved the driver wrong (D534).
//
// So the list is load-bearing: it is the published statement of WHAT a driver must
// measure. This asks the drivers which capabilities they actually serve and
// compares that against which providers the list names. A pair the drivers serve
// and the list never mentions is a capability whose realisation on that cloud is
// documented nowhere — and the next dispute about it has nothing to appeal to.
//
// A ratchet, not a wall: writing 29 accurate mappings needs per-service knowledge,
// and a WRONG mapping is worse than an absent one precisely because D534 treated
// it as authoritative. The number may only fall.
const vocabMappingGapBaseline = 0 // COMPLETE (D545): every provider the drivers serve is named

func TestVocabularyMappingsNameEveryProviderTheDriversServe(t *testing.T) {
	root := repoRoot(t)

	// what the vocabulary PUBLISHES: capability -> the provider prefixes any of its
	// attributes name in `mappings:`
	listed := map[string]map[string]bool{}
	files, err := filepath.Glob(filepath.Join(root, "spec", "vocab", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no vocabulary files read (%v) — this gate would be vacuous", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Capability string                            `yaml:"capability"`
			Attributes map[string]map[string]interface{} `yaml:"attributes"`
		}
		// D561: a parse failure must NOT read as "this file declares no mappings".
		// Seen first-hand while writing the k8s entries: a broken document made the
		// gate report MORE undocumented pairs instead of failing, so the one input
		// most likely to be wrong was the one it went quiet on (D552's shape).
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("vocabulary %s is unparseable: %v", filepath.Base(f), err)
		}
		if doc.Capability == "" {
			continue
		}
		for _, spec := range doc.Attributes {
			m, _ := spec["mappings"].(map[string]interface{})
			for k := range m {
				if listed[doc.Capability] == nil {
					listed[doc.Capability] = map[string]bool{}
				}
				listed[doc.Capability][strings.SplitN(k, ".", 2)[0]] = true
			}
		}
	}

	// what the DRIVERS say (D317: ask them, never scrape)
	served := map[string]map[string]bool{}
	asked := map[string]bool{}
	add := func(prov string, m map[string]string) {
		asked[prov] = true
		for _, capType := range m {
			if served[capType] == nil {
				served[capType] = map[string]bool{}
			}
			served[capType][prov] = true
		}
	}
	add("aws", aws.NewDriver("eu-central-1").ServiceCapabilities())
	add("gcp", gcp.NewDriver("p").ServiceCapabilities())
	add("azure", azure.NewDriver("00000000-0000-0000-0000-000000000001").ServiceCapabilities())
	// D561: the fourth driver. It was absent because it did not implement
	// ServiceCapabilities, so the gate could not ask it — and the baseline's comment
	// said "every provider the drivers serve is named" anyway.
	add("k8s", k8s.NewDriver("https://example.invalid", "t").ServiceCapabilities())
	if len(served) < 20 {
		t.Fatalf("only %d capabilities reported by the drivers — the probe is broken "+
			"and this gate would pass on anything", len(served))
	}
	// D561: assert WHO was asked, not only that the gap is zero. Dropping a driver
	// SHRINKS the set that needs documenting, so the gate went green on exactly the
	// defect it exists to catch — for four months, while its constant read "every
	// provider the drivers serve is named". A floor on the subject, not the
	// container (D328/D488).
	for _, prov := range []string{"aws", "gcp", "azure", "k8s"} {
		if !asked[prov] {
			t.Fatalf("the %s driver was never asked — removing a driver shrinks the set "+
				"this gate checks, so its silence is not evidence of coverage", prov)
		}
	}

	var gaps []string
	for capType, provs := range served {
		for prov := range provs {
			if !listed[capType][prov] {
				gaps = append(gaps, capType+"|"+prov)
			}
		}
	}
	sort.Strings(gaps)

	if len(gaps) > vocabMappingGapBaseline {
		t.Errorf("the vocabulary's mappings fell FURTHER behind the drivers: %d pairs "+
			"undocumented, baseline %d. A capability realised on a cloud the vocabulary "+
			"never mentions has nothing to appeal to when a driver and an operator "+
			"disagree about what it measures (D534).\n  %s",
			len(gaps), vocabMappingGapBaseline, strings.Join(gaps, "\n  "))
	}
	if len(gaps) < vocabMappingGapBaseline {
		t.Errorf("%d undocumented pairs remain but the baseline still says %d — lower "+
			"the constant so the ratchet cannot slip back", len(gaps), vocabMappingGapBaseline)
	}
}
