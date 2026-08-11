package provider_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D604. `scripts/preship.sh` is the gate a binary passes before it goes to a client.
// Its own header says every other step now runs in release.yml and that the script
// survives for ONE reason: the SigV4-signed request, the only check that sees a
// signing regression.
//
// That check skips itself when there are no AWS credentials in the environment — a
// `t.Log` and a `return`, which is a PASS to `go test` and therefore to the script —
// and the script then printed:
//
//	== PRESHIP OK — safe to build + ship ==
//
// So the gate reported success having not run the one thing it exists for. Three
// delivery manifests carried that gap as hand-written prose; the tool said OK.
//
// The guard is exercised here rather than described: the credential block is taken
// out of the real script and run, so a change to its wording or its exit codes shows
// up as a failure and not as a stale comment.
func TestPreshipRefusesToPassWithoutTheSignedCheck(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "scripts", "preship.sh"))
	if err != nil {
		t.Skipf("no preship script here: %v", err)
	}
	src := string(raw)

	const marker = "# D604: the script existed FOR the signed request"
	i := strings.Index(src, marker)
	if i < 0 {
		t.Fatal("scripts/preship.sh no longer carries the credential guard — the gate " +
			"would go back to printing PRESHIP OK over a skipped signed check")
	}
	guard := "set -euo pipefail\n" + src[i:]

	run := func(env []string, args ...string) (string, int) {
		cmd := exec.Command("bash", append([]string{"-c", guard, "preship.sh"}, args...)...)
		cmd.Env = append(os.Environ(), "AWS_ACCESS_KEY_ID=", "AWS_PROFILE=")
		cmd.Env = append(cmd.Env, env...)
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("running the guard: %v", err)
		}
		return string(out), code
	}

	t.Run("no credentials: refuse", func(t *testing.T) {
		out, code := run(nil)
		if code == 0 {
			t.Errorf("the guard passed with no credentials — exit %d, output:\n%s", code, out)
		}
		if !strings.Contains(out, "PRESHIP REFUSED") {
			t.Errorf("the refusal does not name itself:\n%s", out)
		}
		if strings.Contains(out, "PRESHIP OK") {
			t.Errorf("the gate still claims OK:\n%s", out)
		}
	})

	t.Run("no credentials, gap accepted explicitly: pass, and say so", func(t *testing.T) {
		out, code := run(nil, "--without-signed-check")
		if code != 0 {
			t.Errorf("an explicitly accepted gap must not block the build: exit %d\n%s", code, out)
		}
		if !strings.Contains(out, "PRESHIP INCOMPLETE") {
			t.Errorf("shipping without the signed check must not read as a clean pass:\n%s", out)
		}
		if strings.Contains(out, "safe to build + ship") {
			t.Errorf("an incomplete run must not borrow the clean verdict's words:\n%s", out)
		}
	})

	t.Run("credentials present: the clean verdict", func(t *testing.T) {
		out, code := run([]string{"AWS_ACCESS_KEY_ID=AKIAEXAMPLE"})
		if code != 0 {
			t.Errorf("exit %d with credentials present:\n%s", code, out)
		}
		if !strings.Contains(out, "PRESHIP OK") {
			t.Errorf("the clean verdict did not print:\n%s", out)
		}
	})
}

// D663. Two gates that could not fail by being EMPTY.
//
// The mutation meter had no floor: strip every `mutate` invocation and it printed
// "every re-injected bug was caught" and exited 0. Measured with all 151 removed.
// That is the meter every other gate in this repository is trusted against.
//
// The release's live-endpoint step had the same shape from the other direction:
// `go test -run` over a name that matches nothing exits 0, so a rename would leave
// the step green with the two live checks never running.
func TestTheVacuityFloorsExist(t *testing.T) {
	skipIfExported(t, "the meter and the release workflow")
	root := repoRoot(t)

	meter, err := os.ReadFile(filepath.Join(root, "scripts", "mutation-gate.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(meter), "MIN_MUTANTS") {
		t.Error("the mutation meter has no floor on how many mutants ran — ask what " +
			"it would print with every mutant deleted, and the answer must not be " +
			"the same thing it prints now")
	}
	// The floor must be a real number, not a token.
	if !regexp.MustCompile(`MIN_MUTANTS=\d{2,}`).Match(meter) {
		t.Error("MIN_MUTANTS is not a two-digit-or-larger count")
	}

	rel, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rel), "go test -list") {
		t.Error("the release's live-endpoint step runs `go test -run` without first " +
			"proving the named tests EXIST — a rename leaves it green and silent")
	}
}
