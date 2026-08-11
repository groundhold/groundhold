package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D622. `groundhold parity` is published as "the capability map: EVERY type, and which
// cloud fulfils it", and the help text and the bake-off skill send readers to it. It
// listed 51 of the 57 types the generated matrix carries, and printed three `unbuilt`
// rows for eight capabilities the k8s driver ships.
//
// Both halves came from the same place: the verb derived its world from the three CLOUD
// drivers, while `spec/parity.yaml` is generated from the vocabulary plus a
// `fulfilledOutsideTheClouds` marker computed in the matrix generator's TEST. So the
// non-cloud knowledge existed only where no runtime path could reach it —
// and spec/parity.yaml's own header names the misreading that marker exists to
// prevent: "this stops unbuilt from being read as 'groundhold has not built this' when
// it has".
//
// Same defect in `example candidate`, which wrote `provider: aws` for every capability
// including types this same data calls a structural gap on aws — a default that reads
// as a recommendation, followed by a next-step line pointing at `verify`, which is a
// pure document check and says PROVEN.
func TestParityVerbCoversEveryPublishedType(t *testing.T) {
	root := repoRootFromCmd(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "parity.yaml"))
	if err != nil {
		t.Skipf("no published matrix here: %v", err)
	}
	published := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^  (capability\.[a-z0-9.-]+):`).
		FindAllStringSubmatch(string(raw), -1) {
		published[m[1]] = true
	}
	if len(published) < 20 {
		t.Fatalf("parsed %d types from spec/parity.yaml — the probe broke (D328)",
			len(published))
	}

	out := captureStdout(t, func() {
		if code := run([]string{"parity"}); code != 0 {
			t.Fatalf("parity exited %d", code)
		}
	})
	listed := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "capability.") {
			listed[strings.TrimSpace(line)] = true
		}
	}

	var missing []string
	for typ := range published {
		if !listed[typ] {
			missing = append(missing, typ)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the parity VERB does not list %d type(s) the published matrix "+
			"carries: %v\nThe verb says 'every type'; a type it omits is one a reader "+
			"cannot ask about.", len(missing), missing)
	}
}

// A type only the k8s driver fulfils must not read as three `unbuilt` rows.
func TestParityNamesWhatIsFulfilledOutsideTheClouds(t *testing.T) {
	out := captureStdout(t, func() {
		if code := run([]string{"parity", "capability.cluster.namespace"}); code != 0 {
			t.Fatal("parity exited non-zero")
		}
	})
	if !strings.Contains(out, "k8s") {
		t.Errorf("a capability the k8s driver ships reads as unbuilt everywhere:\n%s\n"+
			"That is the exact misreading spec/parity.yaml's header says the "+
			"fulfilledOutsideTheClouds marker exists to prevent.", out)
	}
}

// The scaffold must not pre-select a cloud that structurally cannot do the job.
func TestCandidateScaffoldSuggestsAProviderThatCanFulfilTheType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(`apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: jobs, environment: test, version: 1 }
capabilities:
  - id: batch
    type: capability.container.job
constraints:
  hard:
    - { id: c1, subject: batch, path: service.managed, op: equals, value: true,
        verify: { method: static } }
`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if code := run([]string{"example", "candidate", path}); code != 0 {
			t.Fatalf("example exited %d", code)
		}
	})
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "provider:") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatalf("the scaffold has no provider line:\n%s", out)
	}
	if strings.Contains(line, "provider: aws") {
		t.Errorf("the scaffold pre-selects aws for capability.container.job, which "+
			"`groundhold parity` itself calls a structural gap on aws:\n  %s\n"+
			"The next step it names is `verify`, a pure document check that says "+
			"PROVEN — so the advice green-lights an impossible pair.", line)
	}
}
