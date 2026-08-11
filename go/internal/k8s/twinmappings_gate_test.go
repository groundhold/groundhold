package k8s

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// D553. The k8s half of D552's class, and the one that started it: ArgoCD and Flux
// are equal implementations of capability.gitops.application, so an attribute
// credited to one and measured by both sends a reader to the wrong controller's
// semantics — which is exactly how D551's name-instead-of-URL survived review.
//
// Measured by running both mappings against a fixture, not by reading them (D317).
func TestGitOpsTwinsNameTheirOwnMappings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "gitrepositories"):
			_, _ = w.Write([]byte(`{"spec":{"url":"https://github.com/acme/platform.git"}}`))
		case strings.Contains(r.URL.Path, "kustomizations"):
			_, _ = w.Write([]byte(`{"metadata":{"name":"p","namespace":"default"},` +
				`"spec":{"sourceRef":{"kind":"GitRepository","name":"platform"}},` +
				`"status":{"conditions":[{"type":"Ready","status":"True"}]}}`))
		default:
			_, _ = w.Write([]byte(`{"metadata":{"name":"p","namespace":"default"},` +
				`"spec":{"source":{"repoURL":"https://github.com/acme/platform.git"}},` +
				`"status":{"sync":{"status":"Synced"},"health":{"status":"Healthy"}}}`))
		}
	}))
	defer srv.Close()
	d := NewDriver(srv.URL, "t")

	doc := readVocabK8s(t, "capability.gitops.application.yaml")
	if len(doc) == 0 {
		t.Fatal("no attributes read from the vocabulary — this gate would be vacuous")
	}
	var missing []string
	for _, tc := range []struct{ service, vocabKey string }{
		{"argocd-application", "k8s.argocd"},
		{"flux-kustomization", "k8s.flux"},
	} {
		m := d.mappingFor(tc.service)
		if m == nil {
			t.Fatalf("%s is not mapped — the fixture is wrong", tc.service)
		}
		obs, _, err := d.Observe(tc.service, m.Capability, m.buildProviderID("default", "p"))
		if err != nil {
			t.Fatalf("%s observe: %v", tc.service, err)
		}
		if len(obs) < 3 {
			t.Fatalf("%s emitted %d observations — the fixture stopped exercising it", tc.service, len(obs))
		}
		for _, o := range obs {
			if o.Path == "resource.absent" || o.Path == "service.managed" {
				continue
			}
			spec, ok := doc[o.Path]
			if !ok {
				missing = append(missing, tc.vocabKey+" emits "+o.Path+" — the vocabulary has no such attribute")
				continue
			}
			if !spec[tc.vocabKey] {
				named := make([]string, 0, len(spec))
				for k := range spec {
					named = append(named, k)
				}
				sort.Strings(named)
				missing = append(missing, tc.vocabKey+" measures "+o.Path+
					" but the mappings name only ["+strings.Join(named, " ")+"]")
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("a GitOps twin measures an attribute the vocabulary credits elsewhere (%d):\n  %s\n"+
			"The two controllers have different semantics for the same neutral path, so "+
			"reading the wrong line is worse than reading none.", len(missing), strings.Join(missing, "\n  "))
	}
}

func readVocabK8s(t *testing.T, file string) map[string]map[string]bool {
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
	if err := yaml.Unmarshal(raw, &doc); err != nil { // D552: never read a parse failure as "no mappings"
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

// D557, where the defect actually happened. `discover` asked the mapping registry
// and `observe` asked the registry AND writeSafe, so a live k3d cluster enumerated
// argoproj.io/v1alpha1/Application/default/root-app with measured values while
// observe refused `argocd-application` as unknown — one run, one object, two answers.
// The cloud drivers got the same gate; this is the one that would have caught it.
func TestEverythingK8sDiscoveryEnumeratesCanBeObserved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"metadata":{"name":"p","namespace":"default"},"spec":{},"status":{}}`))
	}))
	defer srv.Close()
	d := NewDriver(srv.URL, "t")

	tokens := d.MappedServiceTokens()
	if len(tokens) < 5 {
		t.Fatalf("only %d mapped services — this gate would be near-vacuous", len(tokens))
	}
	var bad []string
	for _, s := range tokens {
		m := d.mappingFor(s)
		if _, _, err := d.Observe(s, m.Capability, m.buildProviderID("default", "p")); err != nil {
			bad = append(bad, s+" ("+err.Error()+")")
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("%d services the discovery sweep enumerates cannot be observed:\n  %s",
			len(bad), strings.Join(bad, "\n  "))
	}
}
