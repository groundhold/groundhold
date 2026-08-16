package provider_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D1139. The README told the reader to run `gh attestation verify <asset>`. Measured
// against the last release, asset by asset: the binary passes, and SHA256SUMS, the SBOM
// and BUILDINFO all return 404. Three of the four published asset kinds, including the
// checksum file a careful reader reaches for first.
//
// The attestation now covers everything that ships, which is worth more than narrowing
// the sentence would have been: an attested SHA256SUMS binds the whole list to this
// build, so one attestation check plus `sha256sum -c` reaches every artefact. Without
// it, that list is the single link in the chain resting on nothing but the release page.
//
// Three things have to hold together, and each has its own way of quietly failing.
func TestTheAttestationCoversEveryAssetThatShips(t *testing.T) {
	skipIfExported(t, "the release workflow")
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)

	// (1) The subject is the DIRECTORY. A narrower glob is a hand-written list of what
	// ships, kept beside the thing that actually ships, and it was already wrong once.
	const subject = "subject-path: 'dist/*'"
	if !strings.Contains(body, subject) {
		got := "none found"
		if i := strings.Index(body, "subject-path:"); i >= 0 {
			line := body[i:]
			if nl := strings.IndexByte(line, '\n'); nl >= 0 {
				line = line[:nl]
			}
			got = strings.TrimSpace(line)
		}
		t.Errorf("the attestation subject is not the whole build directory (%s). A "+
			"filtered subject leaves some published assets unattested while the README "+
			"tells the reader to verify any of them.", got)
	}

	// (2) The confirmation must include a NON-binary. Widening the subject and then
	// confirming only the artefact kind that already worked extends the claim without
	// checking the part that was extended — D354 with one more step of indirection.
	iConfirm := strings.Index(body, "- name: Confirm the attestation is actually retrievable")
	if iConfirm < 0 {
		t.Fatal("no confirmation step — the notes would claim an attestation on the " +
			"strength of a step's green tick, which D354 established is not evidence (D328)")
	}
	confirm := body[iConfirm:]
	if j := strings.Index(confirm[1:], "\n      - name:"); j >= 0 {
		confirm = confirm[:j+1]
	}
	if !strings.Contains(confirm, "dist/SHA256SUMS") {
		t.Error("the confirmation checks no non-binary asset. SHA256SUMS is the one to " +
			"name: it is what a reader reaches for first, and it is what was 404.")
	}

	// (3) Order. NOTES.md is written into the same directory at publish time; attesting
	// after that would make the release notes a subject of their own attestation.
	iAttest := strings.Index(body, "- name: Attest build provenance")
	iNotes := strings.Index(body, "> dist/NOTES.md")
	if iAttest < 0 || iNotes < 0 {
		t.Fatal("the attest step or the notes write is gone — this gate is measuring nothing (D328)")
	}
	if iAttest > iNotes {
		t.Error("the attestation runs AFTER the release notes are written into the build " +
			"directory, so the notes become one of its subjects — the subject set is the " +
			"directory, and what is in the directory depends on when you look")
	}
}
