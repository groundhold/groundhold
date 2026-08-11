package gcp

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D466: the project boundary, asserted as a class.
//
// 39 of 44 GCP deletes already called sameProject before this gate existed. The
// convention was real, near-universal and unwritten, so the five families outside it
// looked exactly like the ones inside — the shape that produced nine defects on the
// delete sweep, one level up: not a missing check where nothing claimed one, but a
// missing check where every neighbour had one.
//
// The ownership labels are NOT a substitute, which is the part worth stating. A
// groundhold-capability/environment pair is identical in every project we manage, so a
// providerId naming another project passes the label check with room to spare. The
// labels answer "is this the right capability?"; only the project check answers "is this
// the right ESTATE?" — the D445 rule again (a claim about the whole state is not the
// same as a claim about the resource).
//
// sameProject is a no-op when nothing is pinned (observe/discover run with no project),
// so the guard costs the read paths nothing and protects apply/converge, where the D75
// preflight was checked against the pinned project.

// boundVarFromSplit matches a function that binds a variable literally named `project`
// out of a providerId splitter. Functions binding poolProject (workload identity, where
// a cross-project pool is the point) or a billing account do not match and need no
// exemption — the gate is exact rather than curated, so there is no list to rot.
var boundVarFromSplit = regexp.MustCompile(`\n\tproject, [^\n]*= split\w*ProviderID\(providerID\)`)

func TestProjectBearingPathsGuardTheBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fnDecl := regexp.MustCompile(`func \(d \*Driver\) ((?:observe|delete|update|create)\w+)\(`)

	var checked int
	var unguarded []string
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(n)
		if err != nil {
			continue
		}
		src := string(raw)
		locs := fnDecl.FindAllStringSubmatchIndex(src, -1)
		for i, loc := range locs {
			end := len(src)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			body := src[loc[0]:end]
			if !boundVarFromSplit.MatchString(body) {
				continue
			}
			checked++
			if !strings.Contains(body, "d.sameProject(project)") {
				unguarded = append(unguarded, src[loc[2]:loc[3]])
			}
		}
	}
	if checked == 0 {
		t.Fatal("no project-bearing driver paths found — the gate would be vacuous (D328)")
	}
	if checked < 30 {
		t.Errorf("only %d project-bearing paths found — the detector is under-counting "+
			"what it guards (D463's lesson)", checked)
	}
	sort.Strings(unguarded)
	if len(unguarded) > 0 {
		t.Errorf("driver paths that take a PROJECT from the providerId and do not check "+
			"it against the pinned one: %v\nThe ownership labels do not cover this: a "+
			"groundhold-capability/environment pair is identical in every project we "+
			"manage, so a providerId naming another project passes the label check.",
			unguarded)
	}
}
