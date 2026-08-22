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

	// D1155. The case that was missing, and the only one where the guard's question
	// differs from the driver's. A profile is the ORDINARY way to hold AWS
	// credentials and the one thing this driver cannot read: it takes
	// AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN and never
	// ~/.aws. So `AWS_PROFILE` set with no key is not "credentials present" — it is
	// the case where the signed request provably did not happen.
	//
	// The three cases above all pass with the old predicate, which is why it
	// survived: they only ever set both variables together or neither.
	t.Run("a profile is not a credential this driver can use", func(t *testing.T) {
		out, code := run([]string{"AWS_PROFILE=some-profile"})
		if code == 0 {
			t.Errorf("the guard passed on AWS_PROFILE alone (exit %d). The driver "+
				"cannot sign with a profile, so the SIGNED check did not run — and "+
				"this script exists to refuse exactly that (D604). A gate that "+
				"reads the operator's INTENT instead of what happened is not a "+
				"gate.\n%s", code, out)
		}
		if strings.Contains(out, "PRESHIP OK") || strings.Contains(out, "safe to build + ship") {
			t.Errorf("the clean verdict printed over a signed check that could not "+
				"have run:\n%s", out)
		}
		// A refusal that does not say how to fix it sends the operator looking for a
		// credential problem they do not have — they are holding the credentials.
		if !strings.Contains(out, "export-credentials") {
			t.Errorf("the refusal does not name the bridge from the profile the "+
				"operator already has, which the driver's own refusal does name "+
				"(D730):\n%s", out)
		}
	})

	// The sibling: bridging the profile must actually satisfy the guard, or the
	// advice above is a dead end.
	t.Run("a bridged profile is a credential", func(t *testing.T) {
		out, code := run([]string{"AWS_PROFILE=some-profile", "AWS_ACCESS_KEY_ID=AKIAEXAMPLE"})
		if code != 0 {
			t.Errorf("exit %d with a profile AND exported keys — the guard must "+
				"accept what its own remediation produces:\n%s", code, out)
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

	// D1196: the receipt must name the commit the run STARTED on, and the run must
	// refuse to write one at all if HEAD moved underneath it. Writing
	// `rev-parse HEAD` at the end attests whatever landed during the run — including
	// a commit no mutant ever touched. `sync-public.sh` cannot catch that: its check
	// refuses a receipt from an EARLIER commit, and this is the mirror image.
	//
	// Structural, and named as such: exercising it would mean landing a commit in the
	// middle of a seventeen-minute run. What it holds is that the guard exists and
	// that the receipt is not written from a fresh `rev-parse`.
	if !strings.Contains(string(meter), "START_HEAD") {
		t.Error("the meter does not capture the commit it started on, so its receipt " +
			"names whatever HEAD is when it finishes — attesting work it never measured")
	}
	if regexp.MustCompile(`rev-parse HEAD > \S*\.mutation-pass`).Match(meter) {
		t.Error("the receipt is written from a fresh `rev-parse HEAD` — that is the " +
			"end-of-run commit, not the one the mutants ran against")
	}
	// The COMPARISON, not the message. The first draft of this check looked for the
	// refusal's wording and a mutant that replaced the condition with `if false`
	// survived it — the sentence stays in the file while the guard stops guarding.
	// Rule: pin the thing that decides, not the thing that is printed.
	if !strings.Contains(string(meter), `"$END_HEAD" != "$START_HEAD"`) {
		t.Error("nothing COMPARES the end-of-run commit with the one the run started " +
			"on, so a tree that moved mid-run still produces a receipt " +
			"sync-public.sh accepts")
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
