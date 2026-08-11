package provider_test

import (
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D548: the CHANGELOG is a published artefact with no gate at all, and this session
// has spent a week finding published artefacts that drifted (D464 counts, D473 the
// denylist, D497 the doc list, D526 a naming claim, D538 the vocabulary mappings).
// It was also the artefact that nearly shipped wrong once already: v0.1.4 was tagged
// from a RED commit and superseded by v0.1.5.
//
// The checkable property is narrow on purpose. "Is the CHANGELOG complete?" is not
// mechanical — not every decision deserves a line. "Does every RELEASED version
// appear?" is: a tag is an artefact someone can download, and a downloader reading
// the CHANGELOG must find it or an explicit statement about it.
func TestEveryReleaseTagAppearsInTheChangelog(t *testing.T) {
	root := repoRoot(t)

	out, err := exec.Command("git", "-C", root, "tag", "-l", "v*").Output()
	if err != nil {
		t.Skipf("no git tag listing available: %v", err)
	}
	var tags []string
	for _, line := range strings.Split(string(out), "\n") {
		if v := strings.TrimSpace(line); v != "" {
			tags = append(tags, v)
		}
	}
	if len(tags) < 3 {
		t.Skipf("only %d tags visible — a shallow clone cannot check this", len(tags))
	}

	body := mustReadRepo(t, "CHANGELOG.md")
	headings := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^## \[(v[0-9.]+)\]`).FindAllStringSubmatch(body, -1) {
		headings[m[1]] = true
	}
	if len(headings) == 0 {
		t.Fatal("no version headings parsed from CHANGELOG.md — this gate would be vacuous")
	}

	var missing []string
	for _, tag := range tags {
		if headings[tag] {
			continue
		}
		reason, ok := changelogExemptTags[tag]
		if !ok {
			missing = append(missing, tag)
			continue
		}
		// The exemption RE-DERIVES its evidence: the reason must actually appear in
		// the document, so an exemption cannot outlive the sentence that justifies it.
		if !strings.Contains(body, reason) {
			t.Errorf("%s is exempt because the CHANGELOG explains it, but %q is no longer "+
				"in the document — the exemption outlived its reason", tag, reason)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("released tags absent from CHANGELOG.md and unexplained: %v\n"+
			"A tag is something a person can download. Either give it a section or say "+
			"in the document why it has none.", missing)
	}
}

// changelogExemptTags names releases with no section of their own, and the SENTENCE
// in the CHANGELOG that accounts for them. Value = a substring that must still be
// present, so the list cannot rot into unexplained absences.
var changelogExemptTags = map[string]string{
	// The first three tags predate the CHANGELOG, whose earliest section is v0.1.3.
	// The document's own header scopes them: internal builds, not a release line.
	"v0.1.0": "the tags below are internal builds, not",
	"v0.1.1": "the tags below are internal builds, not",
	"v0.1.2": "the tags below are internal builds, not",
	// Tagged from a RED commit and replaced; v0.1.5's section says so rather than
	// the tag being quietly deleted (a deleted tag hides the mistake).
	"v0.1.4": "Supersedes **v0.1.4**",
}
