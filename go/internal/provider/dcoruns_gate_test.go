package provider_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// D1143. The DCO check is the only contributor obligation that cannot rest on memory,
// and what stood over it was a token search: `dco.yml` must contain "Signed-off-by",
// "rev-list" and "exit 1" somewhere. Every one of those is satisfiable by a comment, and
// none of them says the script WORKS.
//
// It has two rules, and the second had no test of any kind. The first refuses a commit
// with no sign-off trailer. The second refuses a sign-off in somebody ELSE's name —
// which is the whole point of the DCO, a statement about who wrote this, not a string
// that has to be present. A regex that drifted on the second rule would go on passing
// the first, and the token search cannot tell those apart.
//
// So the step's shell is extracted and RUN, against three commits built here. This is
// the pattern D626 arrived at for the version stamp, and for the same reason recorded
// there: a gate over a script that matches tokens lets a mutant through, because the
// tokens survive the mutation.
func TestTheDCOScriptRefusesWhatItSaysItRefuses(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "dco.yml"))
	if err != nil {
		t.Skip("no dco.yml in this tree")
	}

	script := stepScript(string(raw), "Every commit carries a real Signed-off-by")
	if !strings.Contains(script, "rev-list") || !strings.Contains(script, "Signed-off-by") {
		t.Fatalf("could not extract the DCO step's shell — the step was renamed, or the "+
			"check moved into an action, and this gate is measuring nothing (D328).\ngot:\n%s",
			script)
	}

	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}

	// One author, used for the commits and for the sign-off that must be accepted.
	const name, email = "Ada Lovelace", "ada@example.com"
	dir := t.TempDir()
	git(dir, "init", "-q", "-b", "main")
	git(dir, "config", "user.name", name)
	git(dir, "config", "user.email", email)
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(dir, "add", "f")
	git(dir, "commit", "-q", "-m", "base")
	base := git(dir, "rev-parse", "HEAD")

	commit := func(msg string) string {
		if err := os.WriteFile(filepath.Join(dir, "f"), []byte(msg), 0o644); err != nil {
			t.Fatal(err)
		}
		git(dir, "add", "f")
		git(dir, "commit", "-q", "-m", msg)
		head := git(dir, "rev-parse", "HEAD")
		git(dir, "reset", "-q", "--hard", base) // each case is its own one-commit range
		return head
	}

	signedByAuthor := commit("work\n\nSigned-off-by: " + name + " <" + email + ">")
	unsigned := commit("work with no trailer at all")
	signedByOther := commit("work\n\nSigned-off-by: Grace Hopper <grace@example.com>")
	// The trailer must be its OWN line. Quoted inside prose it is a mention, not a
	// certification — and it is the only input that tells the two rules apart: the
	// first anchors the line, the second matches a fixed substring anywhere, so
	// without this case a mutant gutting the first rule survives on the second
	// (the D1134 shape, found here by the mutant that would not die).
	quotedInProse := commit("work\n\nsomebody wrote Signed-off-by: " + name +
		" <" + email + "> in a review comment")

	run := func(head string) int {
		cmd := exec.Command("bash", "-c", script)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "BASE="+base, "HEAD="+head)
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode()
			}
			t.Fatalf("running the DCO step: %v", err)
		}
		return 0
	}

	for _, tc := range []struct {
		name     string
		head     string
		wantPass bool
		why      string
	}{
		{"signed off by its author", signedByAuthor, true,
			"a correctly signed commit was refused — the check would block every " +
				"contribution, including the ones that followed the instructions"},
		{"no sign-off at all", unsigned, false,
			"an unsigned commit PASSED the check that exists to stop it, and " +
				"CONTRIBUTING tells every contributor it cannot be merged"},
		{"trailer quoted inside prose", quotedInProse, false,
			"a sign-off mentioned inside a sentence PASSED. The trailer is a line, " +
				"not a phrase; accepted anywhere in the body it certifies nothing"},
		{"signed off by someone else", signedByOther, false,
			"a commit signed off in another person's name PASSED. The DCO is a " +
				"statement about who wrote this; accepting a trailer that names " +
				"anyone at all reduces it to a string that must be present"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := run(tc.head)
			if tc.wantPass && code != 0 {
				t.Errorf("exit %d: %s", code, tc.why)
			}
			if !tc.wantPass && code == 0 {
				t.Errorf("exit 0: %s", tc.why)
			}
		})
	}
}

// stepScript returns the de-indented `run:` block of the step with the given name.
func stepScript(body, stepName string) string {
	i := strings.Index(body, "- name: "+stepName)
	if i < 0 {
		return ""
	}
	step := body[i:]
	if j := strings.Index(step[1:], "\n      - name:"); j >= 0 {
		step = step[:j+1]
	}
	k := strings.Index(step, "run: |")
	if k < 0 {
		return ""
	}
	var out []string
	for _, line := range strings.Split(step[k+len("run: |"):], "\n") {
		out = append(out, strings.TrimPrefix(line, "          "))
	}
	return strings.Join(out, "\n")
}
