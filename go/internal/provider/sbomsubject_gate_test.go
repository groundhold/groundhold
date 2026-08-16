package provider_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D1138. Every release publishes a CycloneDX SBOM and the security page tells a reader
// it is there. Measured against the last release, the document named its own subject
// `{"type":"file","name":"."}` — a directory called dot — and every binary in it carried
// the version UNKNOWN.
//
// The UNKNOWN is the scanner being honest: the version is injected at link time and Go's
// build info does not record it, so it cannot know. The subject is a different matter.
// An SBOM exists to answer "which version is this, and what is in it", and read on its
// own — which is how a machine reads it — this one could not answer the first half.
//
// Two things must stay true together, and the second is what makes the first worth
// anything: the release identity is stamped into the document, and it is stamped BEFORE
// the checksums are taken. Altering a published artefact after it has been hashed ships
// a checksum for a version nobody holds.
func TestTheSBOMNamesTheReleaseAndIsStampedBeforeTheChecksums(t *testing.T) {
	skipIfExported(t, "the release workflow")
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)

	// Named steps, in the order the artefacts depend on. Positions, not presence:
	// each of these already exists, and what this gate is for is their ORDER.
	steps := []struct{ label, name string }{
		{"the SBOM is generated", "- name: Generate SBOM"},
		{"the release is stamped into it", "- name: Name the release as the SBOM's subject"},
		{"the checksums are taken", "- name: Checksums"},
	}
	at := make([]int, len(steps))
	for i, s := range steps {
		at[i] = strings.Index(body, s.name)
		if at[i] < 0 {
			t.Fatalf("no step %q in release.yml — %s no longer happens, or was renamed "+
				"and this gate is measuring nothing (D328)", s.name, s.label)
		}
	}
	for i := 1; i < len(steps); i++ {
		if at[i] < at[i-1] {
			t.Errorf("%s happens BEFORE %s. The order is the property: a document stamped "+
				"after it is hashed ships a checksum for a version nobody has, and a "+
				"document hashed before it is stamped is published unstamped.",
				steps[i].label, steps[i-1].label)
		}
	}

	// The stamp must carry the TAG. A subject naming the project without the version
	// answers half the question an SBOM is read to answer.
	stamp := body[at[1]:at[2]]
	if !strings.Contains(stamp, "GITHUB_REF_NAME") {
		t.Error("the SBOM stamp does not read the tag, so the subject it writes cannot " +
			"name the release this document belongs to")
	}
	// Vacuity in the other direction: an empty component list satisfies every check a
	// consumer might run and reads as a release that depends on nothing.
	if !strings.Contains(stamp, `doc.get("components")`) {
		t.Error("nothing refuses an SBOM with no components — an empty document would be " +
			"stamped with the release name and published as if it described it")
	}
}
