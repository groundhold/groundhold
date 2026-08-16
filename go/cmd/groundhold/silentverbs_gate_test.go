package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D1113. spec/presentation.md publishes the verbs that stay silent on success, and the
// reason is a claim about honesty: "a green word after `probe` or `observe` would claim
// the world is HEALTHY, when the verb only claims the measurement was recorded".
//
// The runtime has that set too — `silentOnSuccess`, consulted by the banner emitter.
// Nothing bound them. The published list held eleven verbs; the runtime held eighteen.
// Seven verbs (`survey`, `suggest`, `keygen`, `capsule`, `snapshot`, `attest`,
// `apiver`) were silent in the tool and absent from the document that says which verbs
// are silent — the closed-set-published-in-two-places shape, where neither copy is
// wrong on its own and they do not agree.
//
// The drift direction that matters is a verb LEAVING the runtime set: it starts
// printing `OK` on success, and for a measuring verb that reads as a verdict it never
// made. So the sets are pinned to each other, both ways.
func TestSilentVerbsMatchTheSpec(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "spec", "presentation.md"))
	if err != nil {
		t.Skipf("no presentation spec here: %v", err)
	}

	row := regexp.MustCompile(`(?m)^\|([^|]*)\|\s*—\s*silent\s*\|`).FindStringSubmatch(string(raw))
	if row == nil {
		t.Fatal("spec/presentation.md no longer carries a '— silent' row in the green-word " +
			"table — this gate cannot find the published set, and would otherwise pass " +
			"over any drift at all (D328)")
	}
	published := map[string]bool{}
	for _, m := range regexp.MustCompile("`([a-z][a-z-]*)`").FindAllStringSubmatch(row[1], -1) {
		published[m[1]] = true
	}
	if len(published) < 10 {
		t.Fatalf("parsed %d silent verbs from the spec — the row changed shape", len(published))
	}

	var missingFromSpec, missingFromRuntime []string
	for v := range silentOnSuccess {
		if !published[v] {
			missingFromSpec = append(missingFromSpec, v)
		}
	}
	for v := range published {
		if !silentOnSuccess[v] {
			missingFromRuntime = append(missingFromRuntime, v)
		}
	}
	sort.Strings(missingFromSpec)
	sort.Strings(missingFromRuntime)

	if len(missingFromSpec) > 0 {
		t.Errorf("the runtime keeps these verbs silent and the spec does not list them:\n  %s\n"+
			"The published list is what a reader takes as the closed set; a verb missing "+
			"from it is undocumented behaviour, however benign.",
			strings.Join(missingFromSpec, ", "))
	}
	if len(missingFromRuntime) > 0 {
		t.Errorf("the spec promises these verbs are silent and the runtime banners them:\n  %s\n"+
			"This is the dangerous direction: a measuring verb printing OK on success "+
			"reads as a verdict it never made.",
			strings.Join(missingFromRuntime, ", "))
	}
}
