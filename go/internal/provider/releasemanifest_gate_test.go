package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D1130. The release publishes a checksum file and the README calls it coverage:
// "the checksums cover all three". Which artefacts get summed, and which get
// uploaded, were two lists somebody wrote out by hand in the same workflow, and
// the step that looked like it checked the first one compared it against ITSELF —
// it summed a glob, then asserted that every member of the same glob appeared in
// the file it had just built from that glob. It could not fail unless sha256sum
// misbehaved.
//
// The direction of the harm is the bad one. An artefact uploaded but not summed
// is not caught by the reader either: the published verification line is
// `sha256sum -c SHA256SUMS --ignore-missing`, which SKIPS a file it has no entry
// for and prints OK. The reader is told they verified the release. They did not.
//
// So the checksum file IS the manifest now: the summed set comes from the
// directory, and the upload set is read back out of the checksum file. An asset
// cannot ship without a checksum because the checksum is what names it. This gate
// keeps a hand-written list from growing back — in either place.
func TestReleaseUploadsExactlyWhatItSummed(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Skipf("no release workflow here: %v", err)
	}
	body := string(raw)

	// The artefact filenames a hand-written list would name. Named here rather than
	// derived, because a derived set would go empty exactly when the workflow stops
	// producing artefacts and the gate would then pass on anything.
	artefactLiterals := []string{"sbom.cdx.json", "BUILDINFO.txt", "groundhold_"}

	// --- the invocation that PUBLISHES ------------------------------------
	// Aim at the invocation, not the step: the step also writes release notes,
	// and those name the artefact kinds in prose on purpose.
	create := invocation(body, "gh release create")
	if create == "" {
		t.Fatal("no `gh release create` invocation found in release.yml — the scan " +
			"broke and this gate would pass on anything (D328)")
	}
	if !strings.Contains(create, "${ASSETS[@]}") {
		t.Errorf("`gh release create` does not upload the asset list read back from "+
			"SHA256SUMS; it publishes:\n%s", create)
	}
	for _, lit := range artefactLiterals {
		if strings.Contains(create, lit) {
			t.Errorf("`gh release create` names the artefact %q literally. That is the "+
				"second hand-written list D1130 removed: it can drift from the summed "+
				"set, and a reader running the published `--ignore-missing` line is told "+
				"OK for a file nobody checksummed. Upload what SHA256SUMS names.\n%s",
				lit, create)
		}
	}

	// --- the invocation that SUMS -----------------------------------------
	sum := invocation(body, "sha256sum \"${ARTEFACTS[@]}\"")
	if sum == "" {
		t.Fatal("no `sha256sum \"${ARTEFACTS[@]}\"` invocation found — the summed set " +
			"is no longer derived from the directory, or the scan broke (D328)")
	}
	for _, lit := range artefactLiterals {
		if strings.Contains(sum, lit) {
			t.Errorf("the checksum invocation names the artefact %q literally: %s", lit, sum)
		}
	}

	// The set being summed must come from the directory. A `find` over dist is what
	// makes coverage hold by construction rather than by somebody remembering.
	find := regexp.MustCompile(`mapfile -t ARTEFACTS < <\(find [^)]*\)`).FindString(body)
	if find == "" {
		t.Error("the artefact set is no longer read from the directory — without that, " +
			"coverage is a list to be kept in step by hand, which is what D1130 found broken")
	}
	// D1136: reading the directory is not enough if the read is filtered. `find` with a
	// positive `-name` is a hand-written list wearing a different syntax, and it re-opens
	// the D680 hole exactly: sum the binaries, leave the SBOM and the build info out, and
	// the reader's `--ignore-missing` prints OK over the two files nobody checksummed.
	// The set is every file EXCEPT the checksum file itself, and nothing narrower.
	if find != "" {
		if !strings.Contains(find, "! -name SHA256SUMS") {
			t.Errorf("the artefact scan does not exclude the checksum file by name, so it "+
				"is not 'everything except SHA256SUMS': %s", find)
		}
		if regexp.MustCompile(`[^!] -name `).MatchString(find) {
			t.Errorf("the artefact scan filters by name, so it sums a SUBSET of what ships "+
				"— the shape D680 found, where two of four asset kinds could not be "+
				"covered by construction: %s", find)
		}
	}

	// Vacuity, the other way round: a checksum file covering nothing satisfies
	// every containment check above, so the workflow must refuse an empty set.
	if !strings.Contains(body, `[ "${#ARTEFACTS[@]}" -gt 0 ]`) {
		t.Error("nothing refuses an EMPTY artefact set — a release with no assets would " +
			"publish a checksum file that covers everything it names, vacuously")
	}
}

// invocation returns the full multi-line shell command whose first line STARTS
// with needle, following `\` continuations to its end. Starting-with is what
// makes it the command rather than a mention of it: `gh release create` also
// appears in a comment explaining why the job needs `contents: write`, and a
// plain substring search returns that comment — which is how the first draft of
// this gate came to report on a permissions note. Returns "" if not found.
func invocation(body, needle string) string {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), needle) {
			continue
		}
		var out []string
		for _, l := range lines[i:] {
			out = append(out, l)
			if !strings.HasSuffix(strings.TrimRight(l, " \t"), `\`) {
				break
			}
		}
		return strings.Join(out, "\n")
	}
	return ""
}
