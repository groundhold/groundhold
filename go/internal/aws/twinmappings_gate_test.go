package aws

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"groundhold/internal/provider"
)

// D552. One capability can be served by two services on the SAME cloud —
// workload.container by both ECS and App Runner, gitops.application by both ArgoCD
// and Flux. The vocabulary's `mappings:` block is the published statement of what a
// driver measures (D538), and it is what settles disputes: D534 was decided against
// the driver by reading it.
//
// D538's gate collects provider prefixes per CAPABILITY — "does any attribute name
// aws?" — so naming `aws` once covered every AWS service under it. Measured here by
// RUNNING the drivers: ECS emits five attribute paths and the vocabulary names
// `aws.ecs` on one. On the other four a reader finds only `aws.apprunner`, its
// sibling, and takes a different service's mapping for their own — worse than an
// absent line, which at least reads as absent.
//
// Twin services are where that misreads, so that is what this gate covers. It is
// deliberately NOT the general claim ("every service names its every path"), which
// would need happy-path truth for all ~145 services; the limit is stated rather
// than implied by a green check.
func TestTwinServicesNameTheirOwnMappings(t *testing.T) {
	type twin struct {
		vocabKey string // the key the vocabulary uses, e.g. "aws.ecs"
		observe  func(t *testing.T) []string
	}
	twins := []twin{
		{"aws.ecs", func(t *testing.T) []string {
			srv := ecsServer(t, "app")
			defer srv.Close()
			obs, _, err := ecsTestDriver(t, srv).observeECS("app", "ecs:eu-central-1:app-abcd1234")
			if err != nil {
				t.Fatalf("ecs observe: %v", err)
			}
			return paths(obs)
		}},
		{"aws.apprunner", func(t *testing.T) []string {
			f := &apprunnerFake{}
			srv := f.handler(t)
			defer srv.Close()
			obs, _, err := apprunnerTestDriver(t, srv).observeAppRunner("app", "apprunner:eu-central-1:app-abcd1234")
			if err != nil {
				t.Fatalf("apprunner observe: %v", err)
			}
			return paths(obs)
		}},
	}

	doc := readVocab(t, "capability.workload.container.yaml")
	if len(doc) == 0 {
		t.Fatal("no attributes read from the vocabulary — this gate would be vacuous")
	}
	var missing []string
	for _, tw := range twins {
		emitted := tw.observe(t)
		if len(emitted) == 0 {
			t.Fatalf("%s emitted nothing — the fixture stopped exercising observe", tw.vocabKey)
		}
		for _, p := range emitted {
			if crossCutting[p] {
				continue // resource.absent / service.managed are not per-service semantics
			}
			spec, ok := doc[p]
			if !ok {
				missing = append(missing, tw.vocabKey+" emits "+p+" — the vocabulary has no such attribute")
				continue
			}
			if !spec[tw.vocabKey] {
				named := make([]string, 0, len(spec))
				for k := range spec {
					named = append(named, k)
				}
				sort.Strings(named)
				missing = append(missing, tw.vocabKey+" measures "+p+
					" but the mappings name only ["+strings.Join(named, " ")+"]")
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("a twin service measures an attribute the vocabulary credits to its sibling "+
			"(%d):\n  %s\nA reader checking what groundhold measures on this service finds "+
			"another service's mapping and has no way to tell.", len(missing), strings.Join(missing, "\n  "))
	}
}

var crossCutting = map[string]bool{"resource.absent": true, "service.managed": true}

func paths(obs []provider.Observation) []string {
	out := make([]string, 0, len(obs))
	for _, o := range obs {
		out = append(out, o.Path)
	}
	return out
}

// readVocab returns attribute path -> set of mapping keys.
func readVocab(t *testing.T, file string) map[string]map[string]bool {
	_, self, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(self), "..", "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "spec", "vocab", file))
	if err != nil {
		t.Fatalf("read vocabulary: %v", err)
	}
	var doc struct {
		Attributes map[string]struct {
			Mappings map[string]any `yaml:"mappings"`
		} `yaml:"attributes"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vocabulary: %v", err)
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
