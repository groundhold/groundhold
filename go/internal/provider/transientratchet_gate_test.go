package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D507: the D237 transient invariant — a 429, 503 or 403 on a MUTATION is `unknown`
// with the providerId, never a terminal `failed` — was migrated driver by driver, with
// `AssertTransient: true` as the per-driver readiness flag and un-migrated drivers left
// "a tracked TODO, never a silent claim of coverage".
//
// It was tracked by comments. Eighteen files carried "AssertTransient left false — D237
// TODO" directly above `AssertTransient: true`: the migration had happened and the
// comment had not been removed. Anyone auditing the debt by reading found eighteen open
// items, seventeen of which were done, and the ONE genuinely open driver was invisible
// among them.
//
// So it is counted instead. The failure this guards is not theoretical: a driver that
// maps a throttle to `failed` tells the executor a mutation definitively did not happen
// when it may well have, which is the orphan D29 exists to prevent.
const transientUnmigratedBaseline = 1 // gcp/gke

func TestTransientInvariantRatchet(t *testing.T) {
	root := repoRoot(t)
	probe := regexp.MustCompile(`(?s)certifynet\.Probe\{(.*?)\n\t\}`)
	name := regexp.MustCompile(`Name:\s*"([^"]+)"`)
	asserts := regexp.MustCompile(`AssertTransient:\s*true`)

	var total int
	var unmigrated []string
	for _, dir := range []string{"aws", "gcp", "azure", "k8s"} {
		files, err := filepath.Glob(filepath.Join(root, "go", "internal", dir, "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			raw, rerr := os.ReadFile(f)
			if rerr != nil {
				continue
			}
			for _, m := range probe.FindAllStringSubmatch(string(raw), -1) {
				total++
				if asserts.MatchString(m[1]) {
					continue
				}
				n := "(unnamed in " + filepath.Base(f) + ")"
				if nm := name.FindStringSubmatch(m[1]); nm != nil {
					n = nm[1]
				}
				unmigrated = append(unmigrated, n)
			}
		}
	}
	if total < 50 {
		t.Fatalf("only %d certification probes found — the gate would be vacuous (D328)",
			total)
	}
	sort.Strings(unmigrated)

	if len(unmigrated) > transientUnmigratedBaseline {
		t.Errorf("drivers not asserting the D237 transient invariant rose to %d (baseline "+
			"%d): %v\nA driver that maps 429/503/403 on a mutation to terminal `failed` "+
			"tells the executor the write definitively did not happen when it may have — "+
			"the orphan D29 exists to prevent. Route the ladder through "+
			"provider.MutationResult and set AssertTransient.",
			len(unmigrated), transientUnmigratedBaseline, unmigrated)
	}
	if len(unmigrated) < transientUnmigratedBaseline {
		t.Errorf("unmigrated is down to %d %v — lower transientUnmigratedBaseline to %d "+
			"(this failure is the good kind)", len(unmigrated), unmigrated, len(unmigrated))
	}

	// The comment that used to track this must not come back: it drifted from the code
	// in eighteen files at once, and a stale TODO hides the real one.
	var stale []string
	for _, dir := range []string{"aws", "gcp", "azure", "k8s"} {
		files, _ := filepath.Glob(filepath.Join(root, "go", "internal", dir, "*_test.go"))
		for _, f := range files {
			raw, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			if strings.Contains(string(raw), "AssertTransient left false") {
				rel, _ := filepath.Rel(root, f)
				stale = append(stale, rel)
			}
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("files tracking the D237 debt in a comment again: %v — the count above "+
			"is the tracker; a comment beside `AssertTransient: true` is how seventeen "+
			"finished migrations went on reading as open (D507)", stale)
	}
}
