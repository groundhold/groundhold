package provider_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D715: the DCO promise must have a mechanism behind it.
//
// CONTRIBUTING has said, to every prospective contributor, "A PR whose commits are not
// signed off cannot be merged." Nothing read a commit trailer. The only thing standing
// between an unsigned commit and `main` was a maintainer remembering — and the DCO is
// what stands in for a CLA here, under a never-relicense promise, so it is the single
// contributor obligation that cannot rest on memory.
//
// The gate is the same one this record applies to every other published claim: the
// document says it, so something must check it.
func TestTheDCOPromiseHasAWorkflowBehindIt(t *testing.T) {
	root := repoRoot(t)
	contributing, err := os.ReadFile(filepath.Join(root, "CONTRIBUTING.md"))
	if err != nil {
		t.Skip("no CONTRIBUTING.md in this tree")
	}
	claims := strings.Contains(string(contributing), "Signed-off-by")
	if !claims {
		t.Skip("CONTRIBUTING no longer asks for a sign-off — nothing to enforce")
	}

	wf, werr := os.ReadFile(filepath.Join(root, ".github", "workflows", "dco.yml"))
	if werr != nil {
		t.Fatalf("CONTRIBUTING requires a Signed-off-by on every commit and no workflow "+
			"checks it: %v. A rule enforced by memory is enforced by nobody on the day "+
			"it matters.", werr)
	}
	body := string(wf)
	for _, need := range []string{"pull_request", "Signed-off-by", "rev-list"} {
		if !strings.Contains(body, need) {
			t.Errorf("dco.yml does not mention %q — it cannot be reading the commits of "+
				"a pull request", need)
		}
	}
	// It must fail the run, not merely print. A check that reports and exits 0 is a
	// green tick over an unsigned commit.
	if !strings.Contains(body, "exit 1") {
		t.Error("dco.yml never exits non-zero — an unsigned commit would pass the check " +
			"that exists to stop it")
	}
}
