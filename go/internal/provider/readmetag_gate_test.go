package provider_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// D1144. Every build here is a prerelease, and GitHub excludes those from
// `/releases/latest` — so the README's install line names an exact tag rather than
// pretending a permanent link works. The cost of naming one is that it goes stale the
// moment the next release succeeds, and it did: after v0.1.8 was cut to replace binaries
// built with a toolchain that had since been patched, the README still handed a newcomer
// the v0.1.7 line, which is precisely the artefact the release existed to supersede
// (D1073).
//
// The step added then is release-blocking and has real logic in it — a regex over the
// README, an empty check, a comparison against the tag. Nothing ran it. It cannot be
// run by a repository gate in the ordinary way either, because only at release time is
// the tag known; that is exactly the argument the step's own comment makes, and it is
// also what left it unexercised.
//
// The way out is the one this project has now used three times: extract the step's shell
// and run it against inputs built here, with the tag supplied as the environment supplies
// it. What cannot be checked without a release is which tag is real. What CAN be checked
// is that the script agrees, refuses and refuses-loudly on the three shapes that matter.
func TestTheREADMETagStepRunsAndRefuses(t *testing.T) {
	skipIfExported(t, "the release workflow")
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Skip("no release workflow here")
	}
	script := stepScript(string(raw), "The README's download line names THIS tag")
	if !strings.Contains(script, "README.md") || !strings.Contains(script, "GITHUB_REF_NAME") {
		t.Fatalf("could not extract the README-tag step's shell — renamed, or the check "+
			"moved, and this gate is measuring nothing (D328).\ngot:\n%s", script)
	}

	run := func(readme, tag string) int {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", "-c", script)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GITHUB_REF_NAME="+tag)
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode()
			}
			t.Fatalf("running the step: %v", err)
		}
		return 0
	}

	const line = "gh release download %s --repo groundhold/groundhold \\\n"

	for _, tc := range []struct {
		name     string
		readme   string
		tag      string
		wantPass bool
		why      string
	}{
		{"README names the tag being released",
			"# groundhold\n\n```sh\n" + strings.Replace(line, "%s", "v0.1.8", 1) + "```\n",
			"v0.1.8", true,
			"the step refused a README that names exactly the tag being released — it " +
				"would block every correct release"},
		{"README still names the previous tag",
			"# groundhold\n\n```sh\n" + strings.Replace(line, "%s", "v0.1.7", 1) + "```\n",
			"v0.1.8", false,
			"a stale README PASSED. This is D1073 exactly: the copy-paste path would " +
				"hand a newcomer the artefact this release exists to supersede"},
		{"README has no download line at all",
			"# groundhold\n\nno install instructions here\n",
			"v0.1.8", false,
			"a README with no download line PASSED. An empty extraction must refuse: " +
				"treated as agreement it would pass forever, on nothing"},
		// The regex reads a version-shaped tag. A tag of another shape must not be
		// silently read as "no line found" and then compared to nothing.
		{"README names a differently-shaped tag",
			"# groundhold\n\n```sh\ngh release download v0.1.8-rc1 --repo x \\\n```\n",
			"v0.1.8-rc1", false,
			"the step accepted a tag its own regex cannot read. Whatever it extracted, " +
				"it was not what the README tells a reader to type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := run(tc.readme, tc.tag)
			if tc.wantPass && code != 0 {
				t.Errorf("exit %d: %s", code, tc.why)
			}
			if !tc.wantPass && code == 0 {
				t.Errorf("exit 0: %s", tc.why)
			}
		})
	}
}
