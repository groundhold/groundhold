package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	caseVocabBlock = regexp.MustCompile(
		`- capability:\s*(\S+)\s*\n(?:\s+\w[^\n]*\n)*?\s+stateful:\s*(\S+)`)
	specCapability = regexp.MustCompile(`(?m)^capability:\s*(\S+)`)
	specStateful   = regexp.MustCompile(`(?m)^stateful:\s*(\S+)`)
)

// TestCaseSuppliedVocabulariesAgreeWithTheSpec (D836).
//
// A conformance case may carry its own vocabulary inline, which is what lets a case pin
// engine behaviour without depending on the shipped spec. The freedom has an edge: when the
// case names a capability the spec ALSO defines, two published copies of one closed set
// exist, and nothing was comparing them. Three had drifted — `capability.ai.speech`,
// `capability.cluster.namespace` and `capability.network.private` all said `stateful: false`
// in a case while the spec said true.
//
// `stateful` is the one field where the divergence is not cosmetic. It decides whether a
// delete is refused without consent and whether a plan annotates DataLoss as certain, so a
// case testing the false version proves the engine's behaviour for a vocabulary nobody
// ships. This is the D329/D330/D338 shape — a closed set published in several places, no two
// agreeing — and the answer is the same one: gate every copy.
func TestCaseSuppliedVocabulariesAgreeWithTheSpec(t *testing.T) {
	root := repoRoot(t)

	spec := map[string]string{}
	specDir := filepath.Join(root, "spec", "vocab")
	entries, err := os.ReadDir(specDir)
	if err != nil {
		t.Fatalf("read %s: %v", specDir, err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		blob, err := os.ReadFile(filepath.Join(specDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		cap := specCapability.FindSubmatch(blob)
		st := specStateful.FindSubmatch(blob)
		if cap != nil && st != nil {
			spec[string(cap[1])] = string(st[1])
		}
	}

	casesDir := filepath.Join(root, "conformance", "cases")
	caseFiles, err := os.ReadDir(casesDir)
	if err != nil {
		t.Fatalf("read %s: %v", casesDir, err)
	}
	var disagree []string
	checked := 0
	for _, e := range caseFiles {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		blob, err := os.ReadFile(filepath.Join(casesDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range caseVocabBlock.FindAllSubmatch(blob, -1) {
			cap, got := string(m[1]), string(m[2])
			want, ok := spec[cap]
			if !ok {
				continue // a case may invent a capability the spec does not define
			}
			checked++
			if got != want {
				disagree = append(disagree,
					e.Name()+": "+cap+" case="+got+" spec="+want)
			}
		}
	}

	// D328: assert the subject. If the block pattern stopped matching, this would report a
	// clean sweep over nothing.
	if len(spec) < 40 {
		t.Fatalf("only %d spec vocabularies read — the scan is broken", len(spec))
	}
	if checked < 100 {
		t.Fatalf("only %d case-supplied vocabulary blocks matched a spec capability — the "+
			"pattern stopped finding them", checked)
	}
	sort.Strings(disagree)

	if len(disagree) > 0 {
		t.Errorf("%d case-supplied vocabular(ies) disagree with spec/vocab on `stateful`:\n"+
			"  %s\n\n`stateful` decides whether a delete is refused without consent and "+
			"whether a plan calls DataLoss certain — a case carrying the other value proves "+
			"the engine's behaviour for a vocabulary nobody ships (D836).",
			len(disagree), strings.Join(disagree, "\n  "))
	}
}
