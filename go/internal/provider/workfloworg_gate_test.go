package provider_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D492: the org an `if:` names must be the org the repository is in.
//
// The three cloud canaries — the only real-cloud evidence CI produces — are gated on
// `github.repository_owner == '<private org>'`. Move the repository to the public org
// and the condition is false: the jobs skip, the run is green, and nothing says the
// most valuable check in the pipeline has gone silent. That is a landmine armed by the
// exact event the project is working towards.
//
// D491 wrote it into the flip runbook. A runbook is a document, and this session has
// spent itself finding out what documents are worth: `preship.sh` was mandatory in a
// design entry nobody read, the mutation gate called itself THE METER and ran nowhere.
// So the condition is checked against the git remote instead. At the flip the remote
// changes, this fails, and the person doing the flip is told which conditions to move
// — in the same commit, which is the only moment it is cheap.
//
// The one exception is DELIBERATE and named below: a job may reference the FUTURE org
// if it is documented as dormant-until-flip.
var (
	ownerCond  = regexp.MustCompile(`repository_owner\s*==\s*'([a-z0-9-]+)'`)
	remoteOrg  = regexp.MustCompile(`[:/]([A-Za-z0-9_.-]+)/[A-Za-z0-9_.-]+?(?:\.git)?$`)
	dormantOrg = "groundhold" // portability-darwin: never run, starts at the flip (D480)
)

func TestWorkflowOwnerConditionsMatchTheRemote(t *testing.T) {
	root := repoRoot(t)
	// The canaries this gate counts are stripped on export (private-estate evidence), so
	// on the published mirror the count is vacuous BY CONSTRUCTION. The flip happens in the
	// working repository. Skip on the POSITIVE export marker, not on a missing remote: the
	// CI checkout of the mirror HAS a remote, which is exactly how this ran — and failed —
	// where the no-remote skip was meant to keep it silent (D661: infer from the marker).
	skipIfExported(t, "the workflow owner-condition flip-safety check (D492)")
	out, err := exec.Command("git", "-C", root, "remote", "get-url", "origin").Output()
	if err != nil {
		t.Skip("no git remote (an exported tree or a tarball); the flip happens in the " +
			"working repository, which has one")
	}
	m := remoteOrg.FindStringSubmatch(strings.TrimSpace(string(out)))
	if m == nil {
		t.Fatalf("cannot read the org from remote %q", strings.TrimSpace(string(out)))
	}
	org := m[1]

	files, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var conditions int
	var wrong []string
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(root, f)
		for i, line := range strings.Split(string(raw), "\n") {
			c := ownerCond.FindStringSubmatch(line)
			if c == nil {
				continue
			}
			conditions++
			if c[1] != org && c[1] != dormantOrg {
				wrong = append(wrong, fmt.Sprintf("%s:%d names %s", rel, i+1, c[1]))
			}
		}
	}
	if conditions < 3 {
		t.Fatalf("only %d owner condition(s) found — the gate would be vacuous (D328)",
			conditions)
	}
	sort.Strings(wrong)
	if len(wrong) > 0 {
		t.Errorf("workflow jobs gated on an org this repository is NOT in (%q): %v\n"+
			"A condition naming the wrong owner does not fail — the job SKIPS, green, "+
			"silently. The canaries are the only real-cloud evidence CI produces; move "+
			"the conditions in the same commit as the move itself (D491/D492).",
			org, wrong)
	}
}
