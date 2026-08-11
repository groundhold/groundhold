package provider_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D626. A tag push ran `release.yml` and nothing else. `ci.yml`, `security.yml`,
// `lint.yml` and `codeql.yml` all trigger on `pull_request` and on `push` to
// main/master, and none carried a `tags:` filter — so the one event that ships
// something to a user was the one event that skipped gitleaks, govulncheck,
// golangci-lint, CodeQL, the race detector, the mutation meter, the differential fuzz
// and the export gate.
//
// Every one of those exists because something shipped without it. `make export-check`
// was RED for four commits last night (a gate I wrote failed in the exported tree) and
// no release would have noticed.
//
// Two fixes: the gates now run INSIDE the publishing job — a workflow that merely runs
// in parallel cannot stop `gh release create` — and the tag also triggers the other
// four workflows so their tools see the released code.
func TestReleaseRunsTheProjectsGates(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Skipf("no release workflow here: %v", err)
	}
	body := string(raw)

	// Each of these must appear as a step the job RUNS, not merely in a comment.
	runLines := regexp.MustCompile(`(?m)^\s*run:.*$`).FindAllString(body, -1)
	if len(runLines) < 5 {
		t.Fatalf("parsed %d run: lines from release.yml — the scan broke and this "+
			"gate would pass on anything (D328)", len(runLines))
	}
	joined := strings.Join(runLines, "\n")

	var missing []string
	for _, gate := range []struct{ name, needle string }{
		{"the project gate", "make check"},
		{"the cross-implementation fuzz", "make differential"},
		{"the race detector", "make race"},
		{"the mutation meter", "make mutation"},
		{"the public export gate", "make export-check"},
	} {
		if !strings.Contains(joined, gate.needle) {
			missing = append(missing, gate.name+" ("+gate.needle+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the release publishes without running:\n  %s\n"+
			"A gate that only runs on a pull request does not run on the commit that "+
			"ships.", strings.Join(missing, "\n  "))
	}
}

// The release notes tell a reader what ran. That sentence is a claim like any other.
func TestReleaseNotesClaimOnlyGatesThatRun(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Skipf("no release workflow here: %v", err)
	}
	body := string(raw)
	runLines := strings.Join(
		regexp.MustCompile(`(?m)^\s*run:.*$`).FindAllString(body, -1), "\n")

	// The notes name these by word; each must correspond to a step.
	for _, claim := range []struct{ word, needle string }{
		{"differential fuzz", "make differential"},
		{"race detector", "make race"},
		{"mutation", "make mutation"},
		{"export gate", "make export-check"},
	} {
		notesClaim := strings.Contains(body, claim.word)
		gateRuns := strings.Contains(runLines, claim.needle)
		if notesClaim && !gateRuns {
			t.Errorf("the release notes say %q ran and no step runs %q — the summary "+
				"a user reads is a published claim (D585)", claim.word, claim.needle)
		}
	}

	// D670: the workflow's own PROSE is a published claim too, and it was wider than
	// the file. A paragraph read "They run HERE, before anything is built, because a
	// workflow that merely runs in parallel cannot stop `gh release create`" — with
	// gitleaks, govulncheck, golangci-lint and CodeQL among the "they". Each of the
	// four appeared exactly once in this file: in that sentence. They run in
	// security.yml and lint.yml, which is the parallel arrangement the same
	// paragraph calls insufficient, and codeql.yml is additionally gated on the
	// repository being public.
	//
	// So: a tool this file names as running HERE must have a step that runs it.
	// Naming one in a sentence that explains where it does NOT run is fine — the
	// check is about the claim of local execution, which is the word "here".
	steps := strings.Join(append(
		regexp.MustCompile(`(?m)^\s*run:[\s\S]*?$`).FindAllString(runLines, -1),
		regexp.MustCompile(`(?m)^\s*uses:.*$`).FindAllString(body, -1)...), "\n")
	for _, tool := range []string{"gitleaks", "govulncheck", "golangci-lint", "CodeQL"} {
		for _, para := range strings.Split(body, "\n\n") {
			if !strings.Contains(para, tool) || !strings.Contains(para, "run HERE") {
				continue
			}
			if !strings.Contains(strings.ToLower(steps), strings.ToLower(tool)) {
				t.Errorf("the workflow says %s runs HERE and no step invokes it — "+
					"the paragraph's own argument is that a parallel workflow cannot "+
					"stop `gh release create`, so claiming it without running it is "+
					"the weaker half of both worlds", tool)
			}
		}
	}
}

// D626. "Verify version stamp" ran `version` and never looked at the answer. `-X` is
// silently a no-op when the symbol path stops matching, and the release notes tell a
// user to check exactly that command — so a rename would ship a binary reporting `dev`
// past a green step. Measured:
//
//	-X main.buildVersion=v9.9.9-TEST         -> groundhold v9.9.9-TEST
//	-X main.buildVersionRenamed=v9.9.9-TEST  -> groundhold dev   (build exits 0)
func TestReleaseComparesTheVersionStampToTheTag(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Skipf("no release workflow here: %v", err)
	}
	body := string(raw)
	i := strings.Index(body, "Verify version stamp")
	if i < 0 {
		t.Fatal("the release no longer verifies the version stamp at all")
	}
	step := body[i:]
	if j := strings.Index(step[1:], "\n      - name:"); j > 0 {
		step = step[:j]
	}
	// Extract the step's shell and RUN it. The first version of this gate matched
	// tokens — "GITHUB_REF_NAME" and a comparison keyword must both appear — and the
	// mutation meter walked straight through it: renaming the compared variable left
	// both tokens in place. A gate over a script must run the script.
	script := ""
	if k := strings.Index(step, "run: |"); k >= 0 {
		for _, line := range strings.Split(step[k+len("run: |"):], "\n") {
			script += strings.TrimPrefix(line, "          ") + "\n"
		}
	}
	if !strings.Contains(script, "version") {
		t.Fatalf("could not extract the step's shell:\n%s", step)
	}

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "dist"), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(reports string) int {
		stub := filepath.Join(dir, "dist", "groundhold_v9.9.9_linux_amd64")
		if err := os.WriteFile(stub,
			[]byte("#!/bin/sh\necho \""+reports+"\"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", "-c", script)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GITHUB_REF_NAME=v9.9.9")
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode()
			}
			t.Fatalf("running the step: %v", err)
		}
		return 0
	}

	if code := run("groundhold v9.9.9"); code != 0 {
		t.Errorf("a correctly stamped binary was rejected (exit %d)", code)
	}
	if code := run("groundhold dev"); code == 0 {
		t.Error("a binary reporting `dev` passed the version-stamp step — `-X` is " +
			"silently a no-op when the symbol path stops matching, and the release " +
			"notes send users to check exactly this command")
	}
}

// A tag must reach the other four workflows too, so their tools see the released code.
func TestTagTriggersTheOtherWorkflows(t *testing.T) {
	root := repoRoot(t)
	for _, wf := range []string{"security.yml", "lint.yml", "codeql.yml", "ci.yml"} {
		raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", wf))
		if err != nil {
			continue // an exported tree ships a subset
		}
		if !strings.Contains(string(raw), "tags:") {
			t.Errorf("%s never triggers on a tag, so its checks do not see the code "+
				"being released — the one commit that reaches a user is the one this "+
				"workflow skips", wf)
		}
	}
}

// D680. Three claims about what a user downloads, each measured false.
//
//   - ONE of eight published binaries was ever executed. The four version-less
//     copies — including `groundhold_linux_amd64`, the asset the README's install
//     line fetches — were never run anywhere.
//   - `SHA256SUMS` was computed BEFORE `BUILDINFO.txt` and the SBOM existed, with
//     the glob `groundhold_*`, so two of the four published asset kinds could not
//     be covered by construction — including the file the rebuild instructions
//     live in.
//   - The README's install snippet downloaded only the binary and then told the
//     reader to run `sha256sum -c SHA256SUMS`, which reports
//     "No such file or directory".
func TestTheReleasePublishesWhatItClaimsToVerify(t *testing.T) {
	skipIfExported(t, "the release workflow")
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)

	iSum := strings.Index(body, "- name: Checksums")
	iInfo := strings.Index(body, "- name: Record build info")
	iSbom := strings.Index(body, "- name: Generate SBOM")
	if iSum < 0 || iInfo < 0 || iSbom < 0 {
		t.Fatal("a step this gate reads has been renamed — it is measuring nothing")
	}
	if iSum < iInfo || iSum < iSbom {
		t.Error("the checksums are taken before BUILDINFO/SBOM exist, so they " +
			"cannot cover them — the file the rebuild instructions live in is the " +
			"one nobody can verify")
	}
	if !strings.Contains(body, "BUILDINFO.txt sbom.cdx.json > SHA256SUMS") {
		t.Error("the checksum glob does not name every published artefact")
	}
	if !strings.Contains(body, "Run every runnable artefact") {
		t.Error("nothing executes the published binaries beyond the one version " +
			"stamp check")
	}

	rd, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(rd)
	iDl := strings.Index(readme, "gh release download")
	if iDl < 0 {
		t.Fatal("the install snippet moved")
	}
	snippet := readme[iDl:]
	if j := strings.Index(snippet, "```"); j > 0 {
		snippet = snippet[:j]
	}
	if strings.Contains(snippet, "sha256sum -c") && !strings.Contains(snippet, "SHA256SUMS'") {
		t.Error("the install snippet verifies a checksum file it never downloads")
	}
}
