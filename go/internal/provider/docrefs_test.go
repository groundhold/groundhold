package provider_test

import (
	"fmt"
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
// Explicit, never a walk from the repo root: the root holds the standing instructions
// (deliberately NOT exported) and .claude/worktrees, which
// can hold stale copies of the whole tree. Gating those would report failures
// about documents no stranger will ever read — and would make this test's own
// description false, which is the exact failure it exists to prevent.
// publishedDocs returns every markdown file that crosses the export boundary — DERIVED
// from the exporter's own INCLUDE list, never a second copy of it.
//
// It used to be a second copy: root markdown except those instructions, four named docs/ files,
// and four whole trees. That list and the exporter's had drifted (D497). Four markdown
// files crossed the boundary and no gate looked at them — the three GitHub issue/PR
// templates, which make claims about the project's maturity to the first stranger who
// files a bug, and a README under go/internal/fixture. Links, CLI verbs, denied client
// names and private-path references all went unchecked in the tree that actually ships.
//
// Same fix as D384 and D473: read the authority, do not restate it.
func publishedDocs(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "scripts", "export-public.sh"))
	if err != nil {
		// The exporter is private-side only. In the exported tree everything present
		// crossed by definition, so scan the markdown that is there.
		var out []string
		_ = filepath.Walk(root, func(p string, info os.FileInfo, werr error) error {
			if werr != nil || info == nil || info.IsDir() || !strings.HasSuffix(p, ".md") {
				return nil
			}
			if strings.Contains(p, string(filepath.Separator)+".git"+string(filepath.Separator)) {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			out = append(out, rel)
			return nil
		})
		sort.Strings(out)
		if len(out) < 15 {
			t.Fatalf("only %d published documents found in the exported tree", len(out))
		}
		return out
	}
	block := regexp.MustCompile(`(?s)INCLUDE=\(\n(.*?)\n\)`).FindStringSubmatch(string(raw))
	if block == nil {
		t.Fatal("cannot find INCLUDE in export-public.sh — the scope broke, not the docs")
	}
	var out []string
	for _, line := range strings.Split(block[1], "\n") {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		full := filepath.Join(root, entry)
		st, serr := os.Stat(full)
		if serr != nil {
			continue // an INCLUDE entry that does not exist is the exporter's problem
		}
		if !st.IsDir() {
			if strings.HasSuffix(entry, ".md") {
				out = append(out, entry)
			}
			continue
		}
		_ = filepath.Walk(full, func(p string, info os.FileInfo, werr error) error {
			if werr != nil || info == nil || info.IsDir() || !strings.HasSuffix(p, ".md") {
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
		if len(docLink.FindAllStringSubmatch(
			"see [the spec](spec/state-model.md) for the rest", -1)) == 0 {
			t.Fatal("D603: the link extractor does not match an ordinary markdown " +
				"link — it is not running, so 'every published link resolves' is a " +
				"claim about nothing")
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

// An action published as several SUBPATHS must be pinned to ONE commit across
// every workflow that uses it.
//
// github/codeql-action ships `init` and `analyze` from the same release and
// requires them to match; a mismatch fails the run. Dependabot bumps each
// subpath in its OWN pull request, so merging one without the other splits them
// — which is exactly what happened when `analyze` moved to v4 while `init` stayed
// on v3.
//
// Nothing caught it. The `analyze` check reports `skipping` on a private
// repository, so CI is green on a workflow that cannot work, and the break would
// have surfaced the moment the repo went public — the worst possible time to
// discover it.
//
// The rule is general rather than a codeql special case: if one repository is
// referenced through more than one path, the pins must agree. A second action
// with subpaths gets the same protection for free.
func TestActionSubpathsSharePin(t *testing.T) {
	dir := filepath.Join(repoRoot(t), ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("no workflows directory here: %v", err)
	}
	// owner/repo -> sha -> the "owner/repo/subpath@sha  (file)" sightings
	pins := map[string]map[string][]string{}
	uses := regexp.MustCompile(`uses:\s+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(/[A-Za-z0-9_./-]+)?@([A-Za-z0-9._-]+)`)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range uses.FindAllStringSubmatch(string(raw), -1) {
			repo, sub, sha := m[1], m[2], m[3]
			if sub == "" {
				continue // no subpath: nothing to keep consistent with
			}
			if pins[repo] == nil {
				pins[repo] = map[string][]string{}
			}
			pins[repo][sha] = append(pins[repo][sha],
				fmt.Sprintf("%s%s@%s (%s)", repo, sub, sha, e.Name()))
		}
	}
	if len(pins) == 0 {
		t.Skip("no subpath-referenced actions in these workflows — nothing to check")
	}
	for repo, bySHA := range pins {
		if len(bySHA) < 2 {
			continue
		}
		var sightings []string
		for _, ss := range bySHA {
			sightings = append(sightings, ss...)
		}
		sort.Strings(sightings)
		t.Errorf("%s is pinned to %d different commits across its subpaths:\n\t%s\n"+
			"An action's subpaths ship from one release and must move together — "+
			"dependabot bumps them in separate pull requests, so merging one alone "+
			"splits them, and a check that `skips` on a private repo will not notice.",
			repo, len(bySHA), strings.Join(sightings, "\n\t"))
	}
}

// A self-hosted runner label must never survive the export (D377).
//
// The working repo runs its gates on the organisation's self-hosted fleet; the
// public repo has no such runners. A workflow that asks for a label nobody offers
// does not fail — it QUEUES, indefinitely. That is worse than a red check: a red
// check says something, a permanently pending one says nothing while looking like
// it is about to.
//
// The exporter rewrites the label, and this gate proves the rewrite still covers
// every label the workflows actually use. A new self-hosted label added to a
// workflow without a matching rewrite rule fails here, in the working repo, rather
// than silently on the far side where nobody is watching the queue.
func TestSelfHostedLabelsAreRewrittenOnExport(t *testing.T) {
	root := repoRoot(t)
	exporter, err := os.ReadFile(filepath.Join(root, "scripts", "export-public.sh"))
	if err != nil {
		t.Skip("no exporter here — this is the exported tree, where the rule has already applied")
	}
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("no workflows directory: %v", err)
	}
	// GitHub-hosted labels are the ones GitHub itself provides; anything else is a
	// label only this organisation can satisfy.
	hosted := map[string]bool{
		"ubuntu-latest": true, "ubuntu-24.04": true, "ubuntu-22.04": true,
		"macos-latest": true, "macos-14": true, "macos-15": true,
		"windows-latest": true,
	}
	runsOn := regexp.MustCompile(`(?m)^\s*runs-on:\s*([A-Za-z0-9._-]+)\s*$`)
	seen := map[string][]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		// the canary workflows never cross the boundary, so their labels cannot
		// strand anything on the far side
		if strings.HasPrefix(e.Name(), "canary-") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range runsOn.FindAllStringSubmatch(string(raw), -1) {
			if label := m[1]; !hosted[label] {
				seen[label] = append(seen[label], e.Name())
			}
		}
	}
	// The exporter rewrites `runs-on:` with a sed PATTERN, not a literal list, so
	// the gate has to apply that pattern rather than grep for the label. An earlier
	// version checked for a literal mention and failed the moment the exporter
	// generalised its rule to a family — a gate that only understands one spelling
	// of the fix is a gate that fires on the fix.
	rewrite := regexp.MustCompile(`runs-on: \)([^/]+)\$/`)
	m := rewrite.FindSubmatch(exporter)
	if m == nil {
		t.Fatal("the exporter has no `runs-on:` rewrite rule — every self-hosted label " +
			"would cross the boundary and queue forever on the far side")
	}
	covered, err := regexp.Compile("^" + string(m[1]) + "$")
	if err != nil {
		t.Fatalf("the exporter's rewrite pattern %q is not a valid regexp: %v", m[1], err)
	}
	for label, files := range seen {
		sort.Strings(files)
		if !covered.MatchString(label) {
			t.Errorf("workflow label %q (in %v) is self-hosted and the exporter's rewrite "+
				"pattern %q does not cover it — the public tree would carry a label nobody "+
				"there can satisfy, and its checks would queue forever instead of failing.",
				label, files, m[1])
		}
	}
}

// D384. A pool name that reaches the public tree is a small, permanent disclosure
// of the private build estate, and the export's `runs-on:` guard cannot catch it:
// that guard reads workflow FILES, and the leak was PROSE — a design entry
// explaining which pool died and what else in the organisation runs on it.
//
// The export redacts entries marked `<!-- internal: ci-infrastructure -->`. This
// gate holds the other end: if an entry NAMES the estate and is not marked, the
// author is told here, at `make check`, rather than by the export refusing later
// with a leak already written to disk.
//
// THE LABELS ARE NOT WRITTEN DOWN HERE. This file is exported; the exporter is not.
// A gate that spelled them out would be the very disclosure it exists to prevent —
// which is exactly what the first version of it did, caught by the export's own
// denylist. It reads them from the exporter, and so cannot drift from it either.
//
// THE LIMIT, stated because it was measured: deleting the `build-estate:` tag blinds
// this gate and it says so. Deleting ONE label from that line does not — the gate
// simply stops asking about that label, and a later entry naming it would pass here
// and pass the export. Deriving from a single source buys agreement between the two
// ends; it cannot defend the source against being edited. That edit is a visible
// one-line diff in the exporter, which is where the defence actually lives.
func buildEstatePatterns(t *testing.T, root string) *regexp.Regexp {
	t.Helper()
	return denylistPatterns(t, root, "build-estate:",
		"no `build-estate:` entry in the export denylist — either the tag was "+
			"dropped or the pools stopped being denied; both mean this gate is blind")
}

// denylistPatterns reads one TAGGED line of the exporter's denylist and compiles it.
// The patterns are never written here: this file is exported and the exporter is not,
// so a gate that spelled them out would be the disclosure it exists to prevent (the
// first version of the build-estate gate was exactly that, caught by the export's own
// audit). Reading them from the exporter also means the two ends cannot drift.
func denylistPatterns(t *testing.T, root, tag, emptyMsg string) *regexp.Regexp {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "scripts", "export-public.sh"))
	if os.IsNotExist(err) {
		// The exporter is deliberately not exported, so in the public tree this
		// gate has nothing to read and nothing to guard: the redaction has already
		// happened upstream. Skipping is the honest outcome, and it is the reason
		// the labels can live in the exporter at all.
		t.Skip("export-public.sh is private-side only; this gate does not apply here")
	}
	if err != nil {
		t.Fatalf("read export-public.sh: %v", err)
	}
	var alts []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "DENY=") ||
			!strings.Contains(line, tag) {
			continue
		}
		// DENY="$DENY|a|b"   # <tag> ...
		open := strings.Index(line, `"`)
		close := strings.Index(line[open+1:], `"`)
		if open < 0 || close < 0 {
			t.Fatalf("cannot parse the %s denylist line: %s", tag, line)
		}
		body := strings.TrimPrefix(line[open+1:open+1+close], "$DENY|")
		for _, alt := range strings.Split(body, "|") {
			if alt = strings.TrimSpace(alt); alt != "" {
				alts = append(alts, alt)
			}
		}
	}
	if len(alts) == 0 {
		t.Fatal(emptyMsg)
	}
	return regexp.MustCompile("(?i)" + strings.Join(alts, "|"))
}

func TestDesignEntriesNamingTheBuildEstateAreMarkedInternal(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "docs", "DESIGN.md"))
	if err != nil {
		t.Fatalf("read DESIGN.md: %v", err)
	}
	estate := buildEstatePatterns(t, root)
	const marker = "<!-- internal: ci-infrastructure -->"

	// D713: this matched `## D123.` only — a DOT — and entries have been written
	// `## D123 — title` for hundreds of decisions. Everything since that style change
	// was one undivided blob attributed to the last dot-style heading, so this gate
	// checked a merged region and, on the first entry that tripped it, accused an
	// unrelated decision from 260 entries earlier. A per-entry gate whose entries are
	// wrong is not a per-entry gate.
	heading := regexp.MustCompile(`(?m)^## D\d+[.\s][^\n]*$`)
	locs := heading.FindAllStringIndex(string(raw), -1)
	if len(locs) == 0 {
		t.Fatal("no design entries found — DESIGN.md structure changed")
	}
	for i, loc := range locs {
		end := len(raw)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		entry := string(raw[loc[0]:end])
		if !estate.MatchString(entry) {
			continue
		}
		if !strings.Contains(entry, marker) {
			t.Errorf("%s names the private build estate but carries no %s "+
				"— the export would publish it", string(raw[loc[0]:loc[1]]), marker)
		}
	}
}

// The marker this gate tells authors to write must still be the one the export
// acts on. If the two spellings diverge, every marked entry publishes in full.
func TestExportRedactsTheMarkerThisGateTellsAuthorsToWrite(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "scripts", "export-public.sh"))
	if os.IsNotExist(err) {
		t.Skip("export-public.sh is private-side only; this gate does not apply here")
	}
	if err != nil {
		t.Fatalf("read export-public.sh: %v", err)
	}
	if !strings.Contains(string(raw), "internal: ci-infrastructure") {
		t.Error("export-public.sh no longer redacts internal design entries — " +
			"the marker this gate tells authors to write would do nothing")
	}
}

// D465: the gap list is the one part of MATURITY that ages against the code, and it ages
// in the direction nobody challenges. Entry 3 went on saying the more important half of
// a production incident was "NOT yet fixed" for as long as it took to read the code
// instead of the document — through an honesty pass (D464) that revised three other
// entries and walked past it. A document is not too hard on itself in a way anyone
// complains about.
//
// Staleness itself is not mechanically decidable. What IS decidable is whether each
// claim can be CHECKED at all: a gap anchored to a decision can be verified by following
// it, which is exactly how this one was caught. So the gate demands the anchor.

var maturityGapItem = regexp.MustCompile(`(?m)^([0-9]+)\. \*\*`)

// D790: the twin of D789's bound, in a second file. Widened here too — three digits
// would have gone blind at four, silently, exactly as the other copy would have.
var designDecisionRef = regexp.MustCompile(`\bD([0-9]+)\b`)

func TestMaturityGapsAreAnchoredToDecisions(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "MATURITY.md"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "## The gaps we are NOT hiding")
	if start < 0 {
		t.Fatal("MATURITY.md has no gap list — the gate would be vacuous (D328)")
	}
	end := strings.Index(src[start:], "\n## What")
	if end < 0 {
		t.Fatal("could not bound the gap list")
	}
	gaps := src[start : start+end]

	idx := maturityGapItem.FindAllStringIndex(gaps, -1)
	if len(idx) < 5 {
		t.Fatalf("found only %d gap entries — the gate would be vacuous (D328)", len(idx))
	}
	for i, loc := range idx {
		stop := len(gaps)
		if i+1 < len(idx) {
			stop = idx[i+1][0]
		}
		body := gaps[loc[0]:stop]
		num := maturityGapItem.FindStringSubmatch(body)[1]
		if !designDecisionRef.MatchString(body) {
			t.Errorf("MATURITY gap %s cites no decision — a gap a reader cannot follow "+
				"into DESIGN.md is a gap nobody can check, and an unchecked gap is how "+
				"this list went on describing a fixed incident as open (D465)", num)
		}
	}
}

// TestMaturityDecisionRefsExist: every decision MATURITY names must be a real heading in
// DESIGN.md. A dangling anchor is worse than none — it looks like evidence.
func TestMaturityDecisionRefsExist(t *testing.T) {
	mat, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "MATURITY.md"))
	if err != nil {
		t.Fatal(err)
	}
	design, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "DESIGN.md"))
	if err != nil {
		t.Fatal(err)
	}
	headings := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^## D([0-9]+)[.: \-—]`).FindAllStringSubmatch(string(design), -1) {
		headings[m[1]] = true
	}
	if len(headings) < 100 {
		t.Fatalf("found only %d decision headings — the gate would be vacuous (D328)",
			len(headings))
	}
	var dangling []string
	seen := map[string]bool{}
	for _, m := range designDecisionRef.FindAllStringSubmatch(string(mat), -1) {
		if seen[m[1]] || headings[m[1]] {
			continue
		}
		seen[m[1]] = true
		dangling = append(dangling, "D"+m[1])
	}
	sort.Strings(dangling)
	if len(dangling) > 0 {
		t.Errorf("MATURITY.md cites decisions DESIGN.md does not have: %v — an anchor "+
			"that goes nowhere reads as evidence and is not", dangling)
	}
}

// D473: a denied client name must be SANITIZED or ABSENT — checked at `make check`
// rather than at publish time.
//
// The exporter denies a set of client tokens, and separately rewrites some of them on
// the way out. D340 settled the stance and it is not reopened here: the honest field
// attribution stays in the PRIVATE repo and the name is genericized on export, which is
// why `acme` appears in design entries and the export is still clean.
//
// The gap is that only ONE of the denied tokens has a rewrite. The other seven have
// none, so if any of them ever reaches a published file the export does not genericize
// it — it REFUSES, with the leak already written to the working tree, and the author
// learns at publish time. The exporter's own comment calls that the failure mode it
// exists to prevent.
//
// So the property is the export's own outcome, asserted early: for every denied client
// token, either the exporter rewrites it, or it does not appear in the tree that
// crosses. The tokens are read from the exporter and never written here (this file is
// exported; the exporter is not), the same mechanism D384 established.
func clientPatterns(t *testing.T, root string) *regexp.Regexp {
	t.Helper()
	return denylistPatterns(t, root, "# clients",
		"no `# clients` entry in the export denylist — either the tag was dropped or "+
			"client names stopped being denied; both mean this gate is blind")
}

// sanitizedTokens returns the tokens the exporter REWRITES on the way out, read from
// its sed replacement expressions.
func sanitizedTokens(t *testing.T, root string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "scripts", "export-public.sh"))
	if os.IsNotExist(err) {
		t.Skip("export-public.sh is private-side only; this gate does not apply here")
	}
	if err != nil {
		t.Fatalf("read export-public.sh: %v", err)
	}
	out := map[string]bool{}
	sub := regexp.MustCompile(`s[/|]([A-Za-z0-9_-]+)[/|]`)
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(line, "sed -i") {
			continue
		}
		for _, m := range sub.FindAllStringSubmatch(line, -1) {
			out[strings.ToLower(m[1])] = true
		}
	}
	return out
}

func TestDeniedClientsAreSanitizedOrAbsent(t *testing.T) {
	root := repoRoot(t)
	deny := clientPatterns(t, root)
	sanitized := sanitizedTokens(t, root)
	docs := publishedDocs(t)
	if len(docs) < 5 {
		t.Fatalf("only %d published docs found — the gate would be vacuous (D328)", len(docs))
	}

	seen := map[string]string{} // token -> first place it appears
	for _, rel := range docs {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(raw), "\n") {
			for _, m := range deny.FindAllString(line, -1) {
				k := strings.ToLower(m)
				if _, ok := seen[k]; !ok {
					seen[k] = fmt.Sprintf("%s:%d", rel, i+1)
				}
			}
		}
	}

	var unsanitized []string
	for tok, where := range seen {
		if !sanitized[tok] {
			unsanitized = append(unsanitized, tok+" ("+where+")")
		}
	}
	sort.Strings(unsanitized)
	if len(unsanitized) > 0 {
		t.Errorf("published documents name a denied party the exporter does NOT rewrite: "+
			"%v\nThe export will refuse this tree rather than genericize it, and it will "+
			"refuse at publish time with the name already written. Either add a sanitizer "+
			"beside the acme one (the D340 stance: the FACT of the field run stays, the "+
			"client name does not) or genericize the prose here.", unsanitized)
	}
}

// D474: every action in a workflow must be pinned to a commit SHA, and the SAME action
// must carry the SAME pin across the file.
//
// I added a CI job and pinned setup-python from memory — to a hash the repo does not
// use. It would have run a DIFFERENT commit of the same action than every other job in
// the file, which is the exact hazard SHA-pinning exists to remove, introduced by the
// act of pinning. Nothing would have failed; the pin looked right.
var wfUses = regexp.MustCompile(`uses:\s+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([A-Za-z0-9]+)([^\n]*)`)

var versionComment = regexp.MustCompile(`^\s*#\s*v[0-9]`)

func TestWorkflowActionPinsAreConsistent(t *testing.T) {
	root := repoRoot(t)
	files, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 3 {
		t.Fatalf("only %d workflows found — the gate would be vacuous (D328)", len(files))
	}
	pins := map[string]map[string][]string{} // action -> ref -> where
	var unpinned, uncommented []string
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(root, f)
		for i, line := range strings.Split(string(raw), "\n") {
			m := wfUses.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			action, ref, rest := m[1], m[2], m[3]
			if len(ref) == 40 && !versionComment.MatchString(rest) {
				// D479: the scheduled job that re-resolves each tag and compares it to
				// the pin can only run on pins that SAY which tag they are. A hash with
				// no version comment is pinned and unverifiable — the strongest form of
				// "trusted as pinned", and the one nobody can audit.
				uncommented = append(uncommented,
					fmt.Sprintf("%s:%d %s@%s", rel, i+1, action, ref[:12]))
			}
			if len(ref) != 40 {
				unpinned = append(unpinned, fmt.Sprintf("%s:%d %s@%s", rel, i+1, action, ref))
				continue
			}
			if pins[action] == nil {
				pins[action] = map[string][]string{}
			}
			pins[action][ref] = append(pins[action][ref],
				fmt.Sprintf("%s:%d", rel, i+1))
		}
	}
	// D488: the floor was on the number of FILES, so a tree whose workflows contain no
	// `uses:` at all passed — the gate found nothing to check and called that success.
	// Count the SUBJECT (pins), not the container (files); the scripts gate next door
	// got this right and this one did not, which is why the sweep tested both.
	var pinned int
	for _, refs := range pins {
		for _, where := range refs {
			pinned += len(where)
		}
	}
	if pinned+len(unpinned) < 10 {
		t.Fatalf("only %d action reference(s) found across %d workflows — the gate would "+
			"be vacuous (D328)", pinned+len(unpinned), len(files))
	}
	sort.Strings(unpinned)
	if len(unpinned) > 0 {
		t.Errorf("workflow actions not pinned to a commit SHA: %v — a tag is mutable, "+
			"which is the whole reason this repo pins", unpinned)
	}
	sort.Strings(uncommented)
	if len(uncommented) > 0 {
		t.Errorf("pinned actions with no `# vX.Y.Z` comment: %v — the pin is then "+
			"unverifiable: nothing can re-resolve the tag and confirm the hash is the "+
			"commit it claimed (D479)", uncommented)
	}
	var split []string
	for action, refs := range pins {
		if len(refs) > 1 {
			var parts []string
			for ref, where := range refs {
				sort.Strings(where)
				parts = append(parts, ref[:12]+" @ "+strings.Join(where, ","))
			}
			sort.Strings(parts)
			split = append(split, action+": "+strings.Join(parts, " vs "))
		}
	}
	sort.Strings(split)
	if len(split) > 0 {
		t.Errorf("the same action is pinned to DIFFERENT commits across the workflows: "+
			"%v\nOne of them is stale or was written from memory; either way two jobs run "+
			"different code from the same name, which is what pinning exists to prevent "+
			"(D474 — introduced by me, doing exactly that).", split)
	}
}

// D485: the same verb check, on the SCRIPTS.
//
// The published-docs gate exists because a reader types what a document shows. A script
// is executed, so a wrong verb fails loudly — for whoever runs it. Three scripts in this
// repository are referenced by nothing (`preship.sh` was one until D484, and
// `integration-gcp.sh`, `console-fixtures.sh` still are), which means a rotted verb in
// them waits silently for the person who finally needs the tool, on the day they need
// it. Sixty-seven invocations, all real today.
//
// Comment lines are skipped and the invocation must be anchored to the binary
// (`"$BIN"`, `./bin/groundhold`): the word "groundhold" appears in prose throughout
// these files, and a looser match reported sixteen phantom verbs — "the groundhold
// binary", "groundhold output" — which is how a gate earns its way to being ignored.
// The anchor must cover every spelling a script uses for the binary. It did not:
// `"$GROUNDHOLD"` was missing, which is the form used by adopt-candidate.sh — the ONE
// script that crosses the export boundary, the one a public reader runs. Sixty-seven
// invocations matched and every single one was in a script that never ships (D495).
var scriptInvoke = regexp.MustCompile(
	`(?:"?\$\{?(?:BIN|GROUNDHOLD)\}?"?|\.?/?bin/groundhold(?:-go)?)\s+(?:--?[a-zA-Z-]+(?:[= ]\S+)?\s+)*([a-z][a-z-]{2,})\b`)

func TestScriptsInvokeRealVerbs(t *testing.T) {
	root := repoRoot(t)
	verbs := cliVerbs(t, root)
	files, err := filepath.Glob(filepath.Join(root, "scripts", "*.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no scripts found — the gate would be vacuous (D328)")
	}
	var unknown []string
	var invocations int
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(root, f)
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, m := range scriptInvoke.FindAllStringSubmatch(line, -1) {
				invocations++
				if !verbs[m[1]] {
					unknown = append(unknown, fmt.Sprintf("%s:%d groundhold %s", rel, i+1, m[1]))
				}
			}
		}
	}
	// Floor on the SUBJECT (invocations), never on the container (file count): the
	// exported tree carries ONE script by design, and a file-count floor fatals there
	// while proving nothing anywhere. D488's rule, which this gate broke two hours
	// after that rule was written down.
	if invocations < 5 {
		t.Fatalf("only %d invocations matched across %d script(s) — the anchor broke, "+
			"not the scripts (D328)", invocations, len(files))
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		t.Errorf("scripts invoke %d verb(s) the CLI does not have:\n  %s\n"+
			"An unreferenced script rots silently and fails the person who finally needs it.",
			len(unknown), strings.Join(unknown, "\n  "))
	}
}

// cliVerbs reads the verb set from the usage text the binary prints, so it cannot drift
// from the CLI the way a hand-kept list would.
func cliVerbs(t *testing.T, root string) map[string]bool {
	t.Helper()
	usage, err := os.ReadFile(filepath.Join(root, "go", "cmd", "groundhold", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	verbs := map[string]bool{"version": true, "help": true}
	for _, m := range regexp.MustCompile(`(?m)^\s*groundhold ([a-z][a-z-]+)`).
		FindAllStringSubmatch(string(usage), -1) {
		verbs[m[1]] = true
	}
	if len(verbs) < 20 {
		t.Fatalf("only %d verbs parsed from the usage text — the parser broke", len(verbs))
	}
	return verbs
}
