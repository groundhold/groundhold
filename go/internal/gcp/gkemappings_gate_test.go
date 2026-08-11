package gcp

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// D552, the other direction. The AWS half of this finding was UNDERSTATEMENT: a
// service measured an attribute the vocabulary credited to its sibling. This is
// OVERSTATEMENT, which is worse, because a reader cannot tell an unbacked line from
// a backed one.
//
// capability.workload.container named `gcp.gke` on seven attributes — "HPA
// minReplicas", "Binary Authorization", "Ingress TLS + redirect". Measured by
// running observeGKE against its own fixture, the driver emits five paths and every
// one of them is a CLUSTER attribute (location.region, availability.class,
// cluster.version, encryption.secrets, network.apiExposure). Nothing anywhere emits
// a workload.container path for GKE — there is no such service. Two of the seven
// lines also restated, more vaguely, what capability.cluster.kubernetes already says
// precisely about the same fields.
//
// The mappings block is the published statement of what a driver MEASURES (D538). A
// line for a service that measures nothing there is a claim with nothing behind it,
// and it is the kind a reader trusts most, because it looks exactly like the six
// accurate ones next to it.
func TestGKEIsNamedOnlyWhereItMeasures(t *testing.T) {
	name := gkePlanName(t)
	f := newFakeGKE(name, "europe-west1")
	f.exists = true
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)

	emitted := map[string]bool{}
	for p := range gkeObsMap(t, d, gkeProviderID("test-proj", "europe-west1", name)) {
		emitted[p] = true
	}
	if len(emitted) < 3 {
		t.Fatalf("observeGKE emitted %d paths — the fixture stopped exercising it", len(emitted))
	}

	// The driver states which capability each service serves, so the check is scoped
	// by capability and not merely by path: `location.region` and `availability.class`
	// ARE emitted by GKE, but for capability.cluster.kubernetes — naming gcp.gke on
	// the same-named attributes of workload.container still claims an implementation
	// that does not exist. Asking the driver keeps the two apart.
	serves := map[string]bool{}
	for svc, cap := range NewDriver("p").ServiceCapabilities() {
		if svc == "gke" {
			serves[cap] = true
		}
	}
	if len(serves) == 0 {
		t.Fatal("the driver reports no capability for gke — this gate would be vacuous")
	}
	files, err := filepath.Glob(filepath.Join(vocabDir(t), "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no vocabulary files read (%v) — this gate would be vacuous", err)
	}
	var unbacked []string
	for _, file := range files {
		capName := vocabCapability(t, file)
		for path, keys := range vocabMappings(t, file) {
			if !keys["gcp.gke"] || crossCuttingGCP[path] {
				continue
			}
			if serves[capName] && emitted[path] {
				continue
			}
			why := "the driver does not serve " + capName
			if serves[capName] {
				why = "observeGKE does not emit it"
			}
			unbacked = append(unbacked, filepath.Base(file)+" "+path+" ("+why+")")
		}
	}
	if len(unbacked) > 0 {
		sort.Strings(unbacked)
		t.Errorf("the vocabulary names gcp.gke on %d attributes it does not measure:\n  %s\n"+
			"An unbacked mapping line is indistinguishable from a backed one, and a reader "+
			"trusts it for exactly that reason.", len(unbacked), strings.Join(unbacked, "\n  "))
	}
}

var crossCuttingGCP = map[string]bool{"resource.absent": true, "service.managed": true}

func vocabCapability(t *testing.T, file string) string {
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	var doc struct {
		Capability string `yaml:"capability"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("vocabulary %s is unparseable: %v", filepath.Base(file), err)
	}
	return doc.Capability
}

func vocabDir(t *testing.T) string {
	_, self, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(self), "..", "..", "..", "spec", "vocab")
}

func vocabMappings(t *testing.T, file string) map[string]map[string]bool {
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	var doc struct {
		Attributes map[string]struct {
			Mappings map[string]any `yaml:"mappings"`
		} `yaml:"attributes"`
	}
	// A parse failure must NOT read as "this file declares no mappings" — that is
	// the gate going quiet on exactly the input most likely to be wrong. Caught by
	// the mutation meter: an injected duplicate key made the document unparseable
	// and the check passed.
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("vocabulary %s is unparseable: %v", filepath.Base(file), err)
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
