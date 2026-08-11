package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D659. The shipped CI recipes are the gate most users will run, and neither of
// them could fail.
//
//	bin/groundhold-go verify … --json | tee verify-report.json
//
// A pipeline's status is its LAST command. GitHub's default shell is `bash -e {0}`
// and GitLab's is `sh -e`; neither sets `pipefail`. Measured with the repository's
// own residency pair, which exists to keep failing forever:
//
//	verify …                      exit 2
//	bash -e -c 'verify … | tee'   exit 0
//
// This is the trap `docs/BUG_HUNTING.md` warns hunters about, shipped as advice.
// The gate reads the recipes rather than trusting them, because the reason nobody
// noticed is that nobody ran them.
func TestNoShippedCIRecipePipesTheToolIntoAnything(t *testing.T) {
	skipIfExported(t, "the CI recipes")
	// D662: the workflows that BUILD the artefact are in scope too. The first cut
	// globbed only examples/ci, so the advice shipped to users was gated while
	// `release.yml` produced SHA256SUMS through the identical `| tee` — a binary
	// could be published with no checksum entry and the job stayed green.
	var files []string
	for _, dir := range []string{
		filepath.Join(repoRoot(t), "examples", "ci"),
		filepath.Join(repoRoot(t), ".github", "workflows"),
	} {
		got, err := filepath.Glob(filepath.Join(dir, "*.yml"))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, got...)
	}
	if len(files) < 6 {
		t.Fatalf("found %d recipes and workflows — this gate is measuring nothing "+
			"(D328)", len(files))
	}

	// A groundhold invocation followed by a pipe, on the same line or continued.
	// D662: in a workflow the command that must not be piped is not always the
	// binary — `sha256sum … | tee SHA256SUMS` published an artefact nobody could
	// verify. Any command whose OUTPUT is the step's product counts.
	pipeAfterTool := regexp.MustCompile(
		`(groundhold|sha256sum|make )[^\n#]*\|[^\n|]`)
	checked := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(f)
		lines := strings.Split(string(raw), "\n")
		// D662: a pipe is honest when the step ARMS pipefail — the reproducible
		// rebuild does exactly that and computes hashes through `$(… | cut)`.
		// Refusing those would be an over-reach that teaches people to delete the
		// gate. Look back to the top of the enclosing step for the `set`.
		armed := func(i int) bool {
			for j := i; j >= 0 && i-j < 40; j-- {
				t := strings.TrimSpace(lines[j])
				if strings.HasPrefix(t, "#") {
					// D662: a COMMENT mentioning pipefail is not a command that arms
					// it. The first version of this check accepted any mention, and
					// the comment I wrote above the gitlab recipe explaining this
					// very rule disarmed the gate — the mutant survived. Prose about
					// a control is not the control.
					continue
				}
				if strings.HasPrefix(t, "set ") && strings.Contains(t, "pipefail") {
					return true
				}
				if strings.HasPrefix(t, "- name:") || strings.HasPrefix(t, "- uses:") {
					return false
				}
			}
			return false
		}
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue // the comment explaining this very rule
			}
			if strings.Contains(line, "groundhold") || strings.Contains(line, "sha256sum") {
				checked++
			}
			// A YAML block scalar's `|` opener is not a shell pipe.
			if strings.HasSuffix(trimmed, "|") && !strings.Contains(trimmed, "groundhold") {
				continue
			}
			if pipeAfterTool.MatchString(line) && !armed(i) {
				t.Errorf("%s:%d pipes the tool into another command:\n\t%s\n"+
					"The step's exit status becomes the LAST command's, so the gate "+
					"cannot fail. Redirect to a file and `cat` it instead.",
					name, i+1, trimmed)
			}
			// The CONTINUED form, which is how the gitlab recipe was written and why
			// the first version of this gate passed over the reintroduced bug: the
			// tool on one line, its arguments on the next two, and the pipe on the
			// third. Walk forward while the lines are continuations of this command.
			if strings.Contains(line, "groundhold") || strings.Contains(line, "sha256sum") {
				for j := i + 1; j < len(lines) && j <= i+6; j++ {
					cont := strings.TrimSpace(lines[j])
					if cont == "" || strings.HasPrefix(cont, "- ") ||
						strings.HasPrefix(cont, "#") || !strings.HasPrefix(lines[j], " ") {
						break // a new command or a new key: the invocation ended
					}
					if strings.HasPrefix(cont, "|") && !strings.HasPrefix(cont, "||") &&
						!armed(i) {
						t.Errorf("%s:%d continues into a pipe %d line(s) later:\n\t%s\n\t%s\n"+
							"The step's exit status becomes the LAST command's, so the "+
							"gate cannot fail.", name, i+1, j-i, trimmed, cont)
						break
					}
					if strings.HasSuffix(cont, "|") || strings.Contains(cont, ">") {
						break // redirection or a block opener: not a pipe into a command
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Error("no recipe invokes groundhold at all — the subject moved and this " +
			"gate would pass over an empty directory")
	}
}

// D659. Exit 2 is a FAMILY: spec/errors.md gives it to nothing-to-change,
// not-executable, consent-required, adoption-mismatch and
// provider-permission-denied. A recipe that turns "exit 2" into success turns a
// violated hard constraint into a green job, so it must route on the `code` field.
func TestARecipeThatSwallowsExitTwoRoutesOnTheCode(t *testing.T) {
	skipIfExported(t, "the CI recipes")
	files, _ := filepath.Glob(filepath.Join(repoRoot(t), "examples", "ci", "*.yml"))
	if len(files) < 2 {
		t.Fatalf("found %d CI recipes — nothing to measure", len(files))
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		body := string(raw)
		if !strings.Contains(body, "-eq 2") && !strings.Contains(body, "== 2") {
			continue
		}
		if !strings.Contains(body, "nothing-to-change") {
			t.Errorf("%s treats exit 2 as success without checking WHICH 2 it was — "+
				"consent-required and not-executable share that code, so a refused "+
				"change reads as converged", filepath.Base(f))
		}
	}
}
