package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D608. The reference implementation carries `yamlcompat`, a loader whose entire
// purpose is to resolve scalars the way go-yaml v3 does — YAML 1.2 core, not PyYAML's
// 1.1. Two call sites in `ref/groundhold.py` used plain `yaml.safe_load` instead:
// `hash` (which hashes a DiscoveryDocument straight from that dict) and `scenario`.
//
// So two of the six document kinds were read by a DIFFERENT loader than the four
// around them. `note: yes` hashed as a bool in the reference and a string in the
// runtime; a scenario step keyed `yes:` resolved to True on one side and "yes" on the
// other, turning the same file into stale on one implementation and fresh on the
// other. Neither showed up in the differential, whose generator builds Python objects
// and writes them with safe_dump — so no ambiguous token ever reaches a parser except
// in the one place the harness injects them by hand.
//
// The rule is simple enough to hold as an invariant: inside the reference, nothing but
// yamlcompat may load YAML. A second loader is a second answer to "what does this
// document say", and the two must never both be reachable.
func TestReferenceLoadsYAMLOnlyThroughItsCompatLoader(t *testing.T) {
	root := repoRoot(t)
	refDir := filepath.Join(root, "ref")
	if _, err := os.Stat(refDir); err != nil {
		t.Skipf("no reference implementation here: %v", err)
	}

	call := regexp.MustCompile(`\byaml\.(safe_load|load|full_load|unsafe_load)\b`)
	imports := regexp.MustCompile(`(?m)^\s*import yaml\b`)

	var offenders []string
	scanned := 0
	err := filepath.Walk(refDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".py") {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if strings.HasSuffix(path, "yamlcompat.py") {
			return nil // the one place allowed to know PyYAML exists
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		body := stripComments(string(raw))
		for _, m := range call.FindAllString(body, -1) {
			offenders = append(offenders, rel+": calls "+m)
		}
		if imports.MatchString(body) {
			offenders = append(offenders, rel+": imports yaml directly")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned == 0 {
		t.Fatal("no reference sources were scanned — the gate would be vacuous (D328)")
	}
	// Positive control: the detector must fire on the shape it looks for (D603).
	if len(call.FindAllString("x = yaml.safe_load(f)", -1)) == 0 {
		t.Fatal("the detector does not match a plain yaml.safe_load call — it is not " +
			"running, and a clean report means nothing")
	}

	if len(offenders) > 0 {
		t.Errorf("the reference implementation reaches PyYAML directly:\n  %s\n"+
			"Only ref/groundholdlib/yamlcompat.py may — it is the loader matched to "+
			"go-yaml's scalar resolution. Any other path gives YAML 1.1 answers, and "+
			"the two implementations then disagree about what a document SAYS before "+
			"either of them gets to canonicalize it.", strings.Join(offenders, "\n  "))
	}
}

// stripComments removes whole-line and trailing `#` comments so a rule QUOTED in a
// comment (this file's own fix quotes `yaml.safe_load` in one) does not read as a
// violation. Crude on purpose: no Python string-literal parsing, because a loader call
// inside a string would deserve flagging anyway.
func stripComments(src string) string {
	var out []string
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
