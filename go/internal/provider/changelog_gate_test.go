package provider_test

import (
	"os/exec"
	"regexp"
	"sort"
	"strconv"
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
// mechanical — not every decision deserves a line. "Does every version-tagged build
// appear?" is: the tag is how the entry is found, and a reader holding one must land
// on it or on an explicit statement about it.
//
// D1132 corrects what this used to claim. "A tag is an artefact someone can download"
// was true when written and D1080 ended it: in THIS repository a `v*` tag is a build
// marker from the development line, no new one may be minted, and what a person
// downloads is tagged on the mirror instead. So the subject is the development line's
// eighteen historical tags against the build headings — which is a real property, and
// not the one the sentence advertised.
//
// It also skips DELIBERATELY in the export now. It always skipped there, by accident:
// the publication checkout is shallow, no tags come with it, and the run landed on the
// "too few tags" branch — a skip that reads exactly like a pass. Fetching the tags
// would be worse than leaving it. Measured on the mirror with tags visible, the gate
// PASSES, and it passes on the collision D1078 exists to warn about: release `v0.1.8`
// and heading `[v0.1.8]` are different artefacts under one string, so the coverage it
// would report is a coincidence of names. A green earned that way is worth less than
// an honest skip.
func TestEveryReleaseTagAppearsInTheChangelog(t *testing.T) {
	skipIfExported(t, "the development line's build tags")
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
	// D1132: not a Skipf. Its sibling below already refuses here for the D328 reason —
	// over a repository whose tags failed to list, this check passes while proving
	// nothing — and the export, the one place tags legitimately do not come along, is
	// handled above by name. What is left is a shallow clone of the source, which
	// should say so rather than quietly stand down.
	if len(tags) <= devLineHighWaterMark {
		t.Fatalf("only %d v* tags visible, expected more than %d historical ones — a "+
			"shallow clone or a broken listing, and this gate would pass on anything",
			len(tags), devLineHighWaterMark)
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
		t.Errorf("version-tagged builds absent from CHANGELOG.md and unexplained: %v\n"+
			"The tag is how a reader finds the entry. Either give it a section or say "+
			"in the document why it has none.", missing)
	}
}

// changelogExemptTags names releases with no section of their own, and the SENTENCE
// in the CHANGELOG that accounts for them. Value = a substring that must still be
// present, so the list cannot rot into unexplained absences.
var changelogExemptTags = map[string]string{
	// The first three tags predate the CHANGELOG, whose earliest section is v0.1.3,
	// and the document says so in as many words.
	//
	// D1078: this anchored on "the tags below are public prereleases, not" — a
	// sentence that was FALSE (those headings are build versions; the published
	// releases are a separate sequence) and was removed for that reason. The gate
	// caught its own anchor going away, which is the re-derivation working. The
	// lesson is narrower than it looks: an exemption anchored to a sentence inherits
	// that sentence's truth, so the anchor should be the claim that actually accounts
	// for the exemption — here, that the file starts at v0.1.3 — and not whatever
	// nearby prose happened to be quotable.
	"v0.1.0": "The entries below begin at `[v0.1.3]`",
	"v0.1.1": "The entries below begin at `[v0.1.3]`",
	"v0.1.2": "The entries below begin at `[v0.1.3]`",
	// Tagged from a RED commit and replaced; v0.1.5's section says so rather than
	// the tag being quietly deleted (a deleted tag hides the mistake).
	"v0.1.4": "Supersedes **v0.1.4**",
}

// devLineHighWaterMark is the last build number the development line ever minted as a
// `v*` tag. It is a closed historical fact, not a setting: nothing may be added above
// it, which is what makes the constant safe to hardcode.
const devLineHighWaterMark = 17

// D1080. Two sequences shared the `v0.1.x` namespace — the development build line and
// the published release tags — and D1078 recorded what that cost a reader: entry
// `[v0.1.8]` (a CloudWatch change, 2026-08-02) and release `v0.1.8` (a toolchain
// rebuild, 2026-08-14) are different artefacts under one string, on the page you open
// to find out what you downloaded.
//
// The owner's decision (2026-08-14) ends it at the source rather than by convention:
// `v*` means a PUBLISHED RELEASE and nothing else, so the development line stops using
// version-shaped names (build markers are `build-<n>`). The historical tags stay — the
// record is not rewritten — which is precisely why this gate exists: the rule is one
// sentence in a document, and a document does not stop anyone from typing `git tag
// v0.1.18` here out of habit.
//
// A new `v*` tag in THIS repository would do two things, both silent: it would re-open
// the collision the decision just closed, and it would trip the release workflow, whose
// trigger is `v*` and which is meant to fire on the mirror.
func TestTheSourceRepositoryMintsNoNewVersionTags(t *testing.T) {
	skipIfExported(t, "the development line's tagging convention")
	root := repoRoot(t)

	out, err := exec.Command("git", "-C", root, "tag", "-l", "v*").Output()
	if err != nil {
		t.Skipf("no git tag listing available: %v", err)
	}
	num := regexp.MustCompile(`^v0\.1\.(\d+)$`)
	var above []string
	var seen int
	for _, line := range strings.Split(string(out), "\n") {
		tag := strings.TrimSpace(line)
		if tag == "" {
			continue
		}
		seen++
		m := num.FindStringSubmatch(tag)
		if m == nil {
			// A shape neither line uses. Flag it rather than pass: an unrecognised
			// version-shaped tag is exactly the thing this gate is here to notice.
			above = append(above, tag+" (unrecognised shape)")
			continue
		}
		n, _ := strconv.Atoi(m[1])
		if n > devLineHighWaterMark {
			above = append(above, tag)
		}
	}
	// D328: over a repository whose tags failed to list, an absence check passes while
	// proving nothing. The historical tags are known to exist, so demand them.
	if seen <= devLineHighWaterMark {
		t.Fatalf("only %d v* tags visible, expected more than %d historical ones — a "+
			"shallow clone or a broken listing, and this gate would pass on anything",
			seen, devLineHighWaterMark)
	}
	if len(above) > 0 {
		sort.Strings(above)
		t.Errorf("this repository has minted version tags above the development line's "+
			"high-water mark (v0.1.%d): %v\n"+
			"`v*` now means a PUBLISHED RELEASE, cut on the public mirror — a v* tag here "+
			"re-opens the version collision D1078 closed AND matches the release "+
			"workflow's trigger. Build markers are `build-<n>`.",
			devLineHighWaterMark, above)
	}
}
