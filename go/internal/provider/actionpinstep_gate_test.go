package provider_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// D1145. "Actions are pinned to commit SHAs" is a supply-chain control the threat model
// names, and it is two halves. `make check` holds the SHAPE — every `uses:` pinned, the
// same action pinned identically everywhere, and a `# vX` comment on each pin so the
// second half has something to work with (D474, D479). The second half re-resolves each
// tag against the provider and compares. It is twenty-seven lines of shell with a
// vacuity floor, an annotated-tag indirection and a failure flag, and nothing had ever
// executed it.
//
// Its own comment records the bug the first draft had: the loop read from a PIPE, so it
// ran in a subshell and the failure flag could not escape — a job that reports success
// whatever it finds. Nothing stopped that from coming back. The case below where the
// LAST pin is the moved one is the one that would notice.
//
// The provider is stubbed. This gate is about the script's logic, not about the network:
// a test that reached GitHub would be slow, flaky and dependent on a token, and the
// question here — does a moved pin fail the job — does not need a real answer from a
// real API, only a consistent one.
func TestThePinReResolutionStepFailsOnAMovedPin(t *testing.T) {
	skipIfExported(t, "the CI recipes")
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "security.yml"))
	if err != nil {
		t.Skip("no security workflow here")
	}
	script := stepScript(string(raw), "Re-resolve every pinned tag and compare")
	if !strings.Contains(script, "gh api") || !strings.Contains(script, "uses:") {
		t.Fatalf("could not extract the pin step's shell — renamed or restructured, and "+
			"this gate is measuring nothing (D328).\ngot:\n%s", script)
	}

	const pinned = "1111111111111111111111111111111111111111"
	const moved = "2222222222222222222222222222222222222222"

	// run builds a workspace of `count` pins, makes the stubbed provider answer `answer`
	// for the LAST one, and returns the step's exit code.
	run := func(t *testing.T, count int, lastAnswer string) int {
		t.Helper()
		dir := t.TempDir()
		wf := filepath.Join(dir, ".github", "workflows")
		if err := os.MkdirAll(wf, 0o755); err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		b.WriteString("name: synthetic\njobs:\n  j:\n    steps:\n")
		for i := 0; i < count; i++ {
			fmt.Fprintf(&b, "      - uses: acme/act%d@%s # v%d.0.0\n", i, pinned, i+1)
		}
		if err := os.WriteFile(filepath.Join(wf, "a.yml"), []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}

		// The stub answers every repo with the pinned sha, except the last, which
		// answers whatever the case is about. `--jq` selects which field is wanted.
		bin := filepath.Join(dir, "bin")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		stub := fmt.Sprintf(`#!/usr/bin/env bash
# args: api <path> --jq <expr>
path="$2"; jq="$4"
case "$path" in
  *acme/act%d/*) sha=%q ;;
  *)             sha=%q ;;
esac
case "$jq" in
  *type*) [ -n "$sha" ] && echo commit ;;
  *)      [ -n "$sha" ] && echo "$sha" ;;
esac
exit 0
`, count-1, lastAnswer, pinned)
		if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command("bash", "-c", script)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"RUNNER_TEMP="+dir, "GH_TOKEN=stub")
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode()
			}
			t.Fatalf("running the pin step: %v", err)
		}
		return 0
	}

	for _, tc := range []struct {
		name       string
		count      int
		lastAnswer string
		wantPass   bool
		why        string
	}{
		{"every pin still resolves to what it says", 8, pinned, true,
			"the step refused a workspace whose pins all match — it would fail every " +
				"honest run and be switched off"},
		{"the LAST pin has moved", 8, moved, false,
			"a pin whose tag now points somewhere else PASSED. This is the case the " +
				"step's own comment is about: read the list from a pipe and the loop " +
				"runs in a subshell, so a failure on the last line cannot escape it"},
		{"the LAST pin no longer resolves", 8, "", false,
			"a tag that is gone or renamed PASSED — an unresolvable pin is not a " +
				"verified one, and treating silence as agreement is what makes a " +
				"supply-chain check decorative"},
		{"too few pins to be meaningful", 3, pinned, false,
			"a workspace with almost no pins PASSED. A check that found nothing to " +
				"check must not report that everything checked out (D328)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := run(t, tc.count, tc.lastAnswer)
			if tc.wantPass && code != 0 {
				t.Errorf("exit %d: %s", code, tc.why)
			}
			if !tc.wantPass && code == 0 {
				t.Errorf("exit 0: %s", tc.why)
			}
		})
	}
}
