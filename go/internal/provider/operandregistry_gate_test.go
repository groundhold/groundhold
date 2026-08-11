package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D763. The silent-ignore guard refuses any `implementation:` key a driver does not
// declare consuming — fail-closed, and right. Its input is a HAND-ENUMERATED registry,
// and each registry's own header says how it was built: "enumerated by reading every
// impl[...] read on the create, update and ClassifyChange paths of each service".
//
// A hand enumeration of what the code does is a copy of the code, and copies drift. The
// GKE driver read two operands the registry never listed, so the compiler refused them
// with the sentence "X is not an operand the gcp/gke driver reads" — which was FALSE, and
// which the driver's own refusals contradicted in the same breath: `network.apiExposure:
// mixed` refused unless you supply `masterAuthorizedCidrs`, and supplying it refused
// because nothing consumes it. Two refusals pointing at each other, and no way through.
//
// This gate closes the loop the only way that survives: it reads the CODE, not the
// register, and demands every operand key a driver reads be declared.
func TestEveryOperandADriverReadsIsRegistered(t *testing.T) {
	root := repoRoot(t)
	// k8s is excluded and the reason is structural, not convenience: its registry is
	// DERIVED (lens operands keyed by lens name, scope taken from the mapping registry)
	// precisely so nothing has to be restated twice, which is the drift this gate hunts.
	// A flat-map comparison would report its four keys as missing and teach nobody.
	packages := []string{"aws", "gcp", "azure"}

	// impl["key"] and helper(impl, "key") — the two shapes every driver uses.
	read := regexp.MustCompile(`impl\w*\[\s*"([a-zA-Z_][a-zA-Z0-9_]*)"\s*\]` +
		`|\(\s*impl\w*\s*,\s*"([a-zA-Z_][a-zA-Z0-9_]*)"`)
	quoted := regexp.MustCompile(`"([a-zA-Z_][a-zA-Z0-9_]*)"`)

	checked := 0
	for _, pkg := range packages {
		dir := filepath.Join(root, "go", "internal", pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", pkg, err)
		}
		declared := map[string]bool{}
		reads := map[string][]string{} // key -> files that read it
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				continue
			}
			if strings.HasPrefix(name, "operands_") {
				for _, m := range quoted.FindAllStringSubmatch(string(raw), -1) {
					declared[m[1]] = true
				}
				continue
			}
			for _, m := range read.FindAllStringSubmatch(string(raw), -1) {
				k := m[1]
				if k == "" {
					k = m[2]
				}
				reads[k] = append(reads[k], name)
				checked++
			}
		}
		var missing []string
		for k, files := range reads {
			if !declared[k] {
				missing = append(missing, k+" (read in "+strings.Join(files, ", ")+")")
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			t.Errorf("%s reads %d operand key(s) its registry does not declare:\n  %s\n\n"+
				"The compiler refuses an undeclared key with \"is not an operand the "+
				"%s/<svc> driver reads\" — a sentence that is false when the driver reads "+
				"it, and a dead end when another refusal demands it (D763).",
				pkg, len(missing), strings.Join(missing, "\n  "), pkg)
		}
	}
	if checked < 200 {
		t.Fatalf("the sweep found only %d operand reads — it has lost its subject and "+
			"would pass over drivers that read nothing (D328)", checked)
	}
	t.Logf("%d operand reads checked across %v", checked, packages)
}
