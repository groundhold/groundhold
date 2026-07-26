package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D351: published prose is a claim, and a claim needs a gate.
//
// The counts gate (D324) already stops a number from rotting. It does not stop
// the two other ways published documentation goes false: a link to a file that
// has been moved or was never written, and a command that names a verb the CLI
// does not have. Both are the kind of error a reader discovers instead of a
// maintainer — the reader types the command, or clicks the link, and learns that
// the project does not check what it publishes.
//
// This is deliberately narrow. It gates what a machine can decide without
// judgement: does this path exist, is this verb real. Claims about BEHAVIOUR
// ("no flag lets an unproven hard constraint through") are not checkable by
// regex and belong in the conformance suite and examples/check.sh, where they
// already live.
//
// Scope is the tree that CROSSES the export boundary — the documents strangers
// read. A private note may reference a private path; a published one may not.

var (
	// markdown link with a local target: [text](path) — http/mailto/anchor excluded
	docLink = regexp.MustCompile(`\[[^\]]*\]\((?:\./)?([A-Za-z0-9_][A-Za-z0-9_./-]*)\)`)
	// "groundhold <verb>" as an INVOCATION: inside backticks or after a shell prompt.
	// Bare prose ("groundhold refuses...") is not a claim about the CLI surface.
	docInvoke = regexp.MustCompile("`(?:bin/)?groundhold(?:-go)? ([a-z][a-z-]{2,})")
)

// publishedDocs returns every markdown file that crosses the export boundary,
// mirroring the whitelist in scripts/export-public.sh (D63/D345).
//
// Explicit, never a walk from the repo root: the root holds CLAUDE.md (the
// internal agent doc, deliberately NOT exported) and .claude/worktrees, which
// can hold stale copies of the whole tree. Gating those would report failures
// about documents no stranger will ever read — and would make this test's own
// description false, which is the exact failure it exists to prevent.
func publishedDocs(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	var out []string

	add := func(rel string) {
		if st, err := os.Stat(filepath.Join(root, rel)); err == nil && !st.IsDir() {
			out = append(out, rel)
		}
	}
	// Root-level markdown crosses, EXCEPT the internal agent doc.
	tops, err := filepath.Glob(filepath.Join(root, "*.md"))
	if err != nil {
		t.Fatalf("glob root markdown: %v", err)
	}
	for _, p := range tops {
		if filepath.Base(p) == "CLAUDE.md" {
			continue
		}
		rel, _ := filepath.Rel(root, p)
		out = append(out, rel)
	}
	// docs/ is NOT exported wholesale — exactly these four cross.
	for _, n := range []string{"DESIGN.md", "MATURITY.md", "THREAT_MODEL.md", "VOICE_TRACK.md"} {
		add(filepath.Join("docs", n))
	}
	// These trees cross whole.
	for _, dir := range []string{"spec", "website", "examples", filepath.Join(".claude", "skills")} {
		_ = filepath.Walk(filepath.Join(root, dir), func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() || !strings.HasSuffix(p, ".md") {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			out = append(out, rel)
			return nil
		})
	}
	sort.Strings(out)
	if len(out) < 15 {
		t.Fatalf("only %d published documents found — the scope broke, not the docs", len(out))
	}
	return out
}

// TestPublishedDocsLinkToRealFiles: a relative link in a published document must
// resolve. A stranger clicking it is the only test that ever ran before.
func TestPublishedDocsLinkToRealFiles(t *testing.T) {
	root := repoRoot(t)
	var broken []string
	for _, doc := range publishedDocs(t) {
		raw, err := os.ReadFile(filepath.Join(root, doc))
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		for _, m := range docLink.FindAllStringSubmatch(string(raw), -1) {
			target := m[1]
			if strings.HasPrefix(target, "http") || strings.HasPrefix(target, "mailto") {
				continue
			}
			// resolve relative to the document, then to the repo root
			rel := filepath.Join(filepath.Dir(doc), target)
			if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
				continue
			}
			if _, err := os.Stat(filepath.Join(root, target)); err == nil {
				continue
			}
			broken = append(broken, doc+" -> "+target)
		}
	}
	if len(broken) > 0 {
		t.Errorf("published documents link to %d path(s) that do not exist:\n  %s",
			len(broken), strings.Join(broken, "\n  "))
	}
}

// TestPublishedDocsInvokeRealVerbs: a documented `groundhold <verb>` must be a
// verb the binary actually has. A reader who types it is entitled to have it run.
func TestPublishedDocsInvokeRealVerbs(t *testing.T) {
	root := repoRoot(t)
	// The verb set is read from the usage text the binary itself prints, so this
	// cannot drift from the CLI the way a hand-kept list would.
	usage, err := os.ReadFile(filepath.Join(root, "go", "cmd", "groundhold", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	verbRe := regexp.MustCompile(`(?m)^\s*groundhold ([a-z][a-z-]+)`)
	verbs := map[string]bool{}
	for _, m := range verbRe.FindAllStringSubmatch(string(usage), -1) {
		verbs[m[1]] = true
	}
	if len(verbs) < 20 {
		t.Fatalf("only %d verbs parsed from the usage text — the parser broke, not the docs", len(verbs))
	}
	var unknown []string
	for _, doc := range publishedDocs(t) {
		raw, err := os.ReadFile(filepath.Join(root, doc))
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		for _, m := range docInvoke.FindAllStringSubmatch(string(raw), -1) {
			v := m[1]
			switch v {
			case "version", "help": // real, but not listed as usage lines
				continue
			}
			if !verbs[v] {
				unknown = append(unknown, doc+": groundhold "+v)
			}
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		t.Errorf("published documents invoke %d verb(s) the CLI does not have:\n  %s",
			len(unknown), strings.Join(unknown, "\n  "))
	}
}

// D353: the honesty page's own evidence table is now checked against the suite.
//
// It listed eight conformance cases as proof that "BOTH implementations must
// pass" every pinned rule. FIVE of the eight carry `impl: go` — they run against
// the Go runtime alone, because no second implementation of the executor or the
// porcelain exists. The page was overstating dual verification in the exact place
// it offered evidence for it, which is the worst place to be wrong.
//
// The table now carries a `runs on` column (`both` / `runtime`). This test proves
// each row: the case exists, and the column matches whether the case is marked
// `impl: go`. A future edit cannot quietly promote a runtime-only case to "both".
func TestHonestyPageEvidenceTableMatchesTheSuite(t *testing.T) {
	root := repoRoot(t)

	// name -> true when the case runs against BOTH implementations
	dual := map[string]bool{}
	files, err := filepath.Glob(filepath.Join(root, "conformance", "cases", "*.yaml"))
	if err != nil {
		t.Fatalf("glob cases: %v", err)
	}
	nameRe := regexp.MustCompile(`^\s*-\s+name:\s*(\S+)`)
	implRe := regexp.MustCompile(`^\s+impl:\s*go\b`)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		cur := ""
		for _, line := range strings.Split(string(raw), "\n") {
			if m := nameRe.FindStringSubmatch(line); m != nil {
				cur = m[1]
				dual[cur] = true // dual until an impl: go inside this case says otherwise
				continue
			}
			if cur != "" && implRe.MatchString(line) {
				dual[cur] = false
			}
		}
	}
	if len(dual) < 400 {
		t.Fatalf("only %d cases parsed — the parser broke, not the page", len(dual))
	}

	raw, err := os.ReadFile(filepath.Join(root, "website", "pages", "honesty.md"))
	if err != nil {
		t.Fatalf("read honesty.md: %v", err)
	}
	row := regexp.MustCompile("(?m)^\\|[^|]+\\|\\s*`([a-z0-9-]+)`\\s*\\|\\s*(both|runtime)\\s*\\|")
	rows := row.FindAllStringSubmatch(string(raw), -1)
	if len(rows) < 5 {
		t.Fatalf("honesty.md no longer states its evidence table in the form this "+
			"gate checks (found %d rows) — update both, or the claim is unguarded", len(rows))
	}
	for _, m := range rows {
		name, claimed := m[1], m[2]
		isDual, known := dual[name]
		if !known {
			t.Errorf("honesty.md cites conformance case %q, which does not exist", name)
			continue
		}
		want := "runtime"
		if isDual {
			want = "both"
		}
		if claimed != want {
			t.Errorf("honesty.md says case %q runs on %q; the suite says %q",
				name, claimed, want)
		}
	}
}

// D354: the release notes may not promise an attestation the workflow has not
// confirmed exists.
//
// v0.1.4 shipped notes saying "each binary carries a keyless SLSA
// build-provenance attestation — verify with `gh attestation verify`". The
// command returned 404 and an early adopter reported it. The attest STEP had
// reported success: on a private repository GitHub produces nothing retrievable,
// and a green tick on a step is not evidence that an artifact exists. A security
// claim was published on the strength of a step outcome nobody checked.
//
// The workflow now runs the same command a reader would run, and composes the
// notes from its result. This test pins that shape: the confirmation step must
// exist, and the positive claim must be reachable only inside the branch guarded
// by its output. It is a structural check, not a proof the attestation works —
// that proof is the command itself, which now runs in the pipeline.
func TestReleaseNotesClaimAttestationOnlyWhenConfirmed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	wf := string(raw)

	if !strings.Contains(wf, "gh attestation verify") {
		t.Error("release.yml never runs `gh attestation verify` — the workflow cannot " +
			"know whether the attestation it attests is retrievable, which is exactly " +
			"how v0.1.4 shipped a false claim")
	}
	if !strings.Contains(wf, `id: provenance`) {
		t.Error("release.yml has no `id: provenance` confirmation step for the notes to branch on")
	}

	// The positive claim must sit inside the guarded branch. Find the guard, and
	// require every occurrence of the claim to come after it and before the else.
	guard := strings.Index(wf, `if [ "${PROVENANCE}" = "true" ]`)
	if guard < 0 {
		t.Fatal("release.yml no longer guards the notes on the confirmation result — " +
			"the attestation claim is unconditional again")
	}
	elseAt := strings.Index(wf[guard:], "\n            else")
	if elseAt < 0 {
		t.Fatal("release.yml guard has no else branch — a release with no attestation " +
			"would say nothing about it rather than saying it has none")
	}
	claim := "carries a keyless SLSA build-provenance attestation"
	for i := 0; i >= 0; {
		i = strings.Index(wf[i:], claim)
		if i < 0 {
			break
		}
		if i < guard || i > guard+elseAt {
			t.Errorf("release.yml states %q outside the confirmed-attestation branch — "+
				"that is the v0.1.4 defect returning", claim)
		}
		i += len(claim)
	}
}

// D355: a published document may not depend on a path that does not cross the
// export boundary.
//
// Third occurrence of one pattern in a day. `.gitleaks.toml` was read by an
// exported workflow but not exported (D345). The canary workflows crossed while
// their runner scripts did not (D345). And the `adopt-candidate` SKILL — which
// crosses — instructs an agent to run `scripts/adopt-candidate.sh`, which does
// not, leaving the published skill broken at its central step.
//
// Each was found by hand, after shipping. The class is mechanically decidable, so
// it should not be: the whitelist is read from the exporter itself, which makes
// this gate correct by construction rather than by a second list kept in sync.
func TestPublishedDocsDoNotDependOnPrivatePaths(t *testing.T) {
	root := repoRoot(t)

	// The whitelist, read from the exporter — never a copy of it.
	raw, err := os.ReadFile(filepath.Join(root, "scripts", "export-public.sh"))
	if err != nil {
		// The exporter does not cross its own boundary, so in the PUBLIC tree this
		// gate has nothing to check — and nothing to check it against: everything
		// present there has already crossed by definition. Skipping is the honest
		// outcome, not a weakening.
		//
		// This test failed the export's standalone gate on its first run, which is
		// the joke it deserves: a gate against "a crossing artifact depending on a
		// private path" was itself a crossing artifact depending on a private path.
		// The export gate caught it before anything was published, which is exactly
		// the job that gate exists to do.
		t.Skip("scripts/export-public.sh is absent (the public tree omits it); " +
			"the boundary this gate checks is defined only in the private repo")
	}
	body := string(raw)
	start := strings.Index(body, "INCLUDE=(")
	if start < 0 {
		t.Fatal("export-public.sh has no INCLUDE array — this gate cannot know what crosses")
	}
	end := strings.Index(body[start:], "\n)")
	if end < 0 {
		t.Fatal("export-public.sh INCLUDE array is unterminated")
	}
	var crosses []string
	for _, line := range strings.Split(body[start+len("INCLUDE=("):start+end], "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		crosses = append(crosses, line)
	}
	if len(crosses) < 10 {
		t.Fatalf("parsed only %d whitelist entries — the parser broke, not the docs", len(crosses))
	}
	exported := func(p string) bool {
		for _, inc := range crosses {
			if p == inc || strings.HasPrefix(p, inc+"/") {
				return true
			}
		}
		return false
	}

	// Only paths under a top-level directory that EXISTS in the repo are claims
	// about the tree. `bin/` is excluded on purpose: it is a build output the
	// reader creates, not something the export ships.
	// Bare, not just backticked: the defect that motivated this gate lives inside a
	// fenced code block (`scripts/adopt-candidate.sh \` as a command line), which a
	// backtick-only pattern misses entirely. Found by testing the gate's teeth — the
	// first cut passed happily with the whitelist entry removed.
	repoPath := regexp.MustCompile(`(?:^|[\s` + "`" + `"'(])((?:scripts|go|ref|conformance|docs|spec|website|examples|\.claude|\.github)/[A-Za-z0-9_./*-]+)`)
	var broken []string
	for _, doc := range publishedDocs(t) {
		// DESIGN.md is the RECORD, not a manual. It narrates decisions and names the
		// internal mechanisms that made them — the exporter, the canary runners — and
		// its entries are never rewritten (a decision that changes gets a new entry,
		// never an edited one). Holding a historical narrative to "everything you
		// name must be openable" would corrupt the record to satisfy a linter. The
		// gate is for documents that tell a reader to DO something.
		if doc == filepath.Join("docs", "DESIGN.md") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(root, doc))
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		seen := map[string]bool{}
		for _, m := range repoPath.FindAllStringSubmatch(string(content), -1) {
			p := strings.TrimSuffix(m[1], "/")
			if seen[p] || strings.Contains(p, "*") {
				continue // globs describe a set, not a dependency on one file
			}
			seen[p] = true
			if _, err := os.Stat(filepath.Join(root, p)); err != nil {
				continue // a nonexistent path is the link gate's problem, not this one
			}
			if !exported(p) {
				broken = append(broken, doc+" -> "+p)
			}
		}
	}
	if len(broken) > 0 {
		sort.Strings(broken)
		t.Errorf("%d published document(s) depend on a path that does NOT cross the "+
			"export boundary — a reader of the public repo cannot follow them:\n  %s",
			len(broken), strings.Join(broken, "\n  "))
	}
}
