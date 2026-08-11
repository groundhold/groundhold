package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"groundhold/internal/ledger"
	"groundhold/internal/vocab"
)

// D607. D587 gated the USAGE text: every flag a verb refuses without must appear in
// that verb's usage line, derived from the refusal messages themselves. It did not
// gate the invocations the project publishes ELSEWHERE — the CI examples, the Makefile
// demo targets, the READMEs — and three of those had been unrunnable for as long as
// `--at` has been required:
//
//	examples/ci/github-actions.yml  plan …            -> exit 1, plan.json written empty
//	examples/ci/github-actions.yml  forecast …        -> exit 1
//	Makefile: plan                                    -> exit 1 (the target's own guard
//	                                                     expects 2, so `make plan` fails)
//
// `make plan` and `make verify` are not part of `make check`, and nothing runs the CI
// example, so all three sat green. A published invocation that cannot run is the same
// class as a published recipe that cannot run (D568) and a documented sequence that
// dead-ends (D570): advice is a claim, and this one is checkable.
//
// The required-flag map is derived from the refusal messages in main.go, the same
// source D587 uses, so a new required flag makes every stale published invocation fail
// here without anyone remembering to look.
func TestPublishedInvocationsCarryTheFlagsTheVerbRefusesWithout(t *testing.T) {
	req := requiredFlagsByVerb(t)
	if len(req) < 10 {
		t.Fatalf("parsed %d verbs with required flags — the probe broke and this gate "+
			"would pass on anything (D328)", len(req))
	}

	root := repoRootFromCmd(t)
	// Where the project publishes runnable command lines. Prose in docs/ is excluded
	// deliberately: those are often deliberately partial ("plan … --at <ts>"), and the
	// files below are the ones a reader COPIES or a machine RUNS.
	targets := []string{
		"Makefile",
		filepath.Join("examples", "ci", "github-actions.yml"),
		filepath.Join("examples", "ci", "gitlab-ci.yml"),
	}

	invoke := regexp.MustCompile(`(?:bin/)?groundhold(?:-go)?\s+([a-z][a-z-]{2,})\b`)
	var bad []string
	scanned := 0

	for _, rel := range targets {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue // an exported tree ships a subset
		}
		for _, line := range joinContinuations(string(raw)) {
			m := invoke.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			verb := m[1]
			flags, ok := req[verb]
			if !ok {
				continue
			}
			scanned++
			for f := range flags {
				if !strings.Contains(line, f) {
					bad = append(bad, rel+": `"+verb+"` published without "+f)
				}
			}
		}
	}

	if scanned == 0 {
		t.Fatal("no published invocation of a verb with required flags was found — the " +
			"scan broke, and this gate would pass over anything (D328)")
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("published invocations that cannot run:\n  %s\n"+
			"The verb refuses without that flag, so the command exits non-zero wherever "+
			"it is copied or scheduled.", strings.Join(bad, "\n  "))
	}
}

// D692. D607 gated the FLAGS a published invocation carries. It did not gate the
// DOCUMENTS one names, and the canary's teardown — the section a reader with a live
// Azure resource is told to run, headed "run it — an unowned canary is how bills
// start" — could not run at all:
//
//	sed -i 's/^  - id: net/  - id: net\n    state: retired/' examples/canary-azure/canary.contract.yaml
//	bin/groundhold-go converge ... --allow-data-loss --yes
//
// Two defects in three lines. The `sed -i` mutates a repo-tracked contract and
// produces a document the loader REFUSES (`constraint targets retired capability` —
// the same README explains that refusal two sections further down), and the converge
// elides every operand, so there is nothing to copy. The README even admitted it:
// "the retirement pair used here lives in the session notes rather than the repo".
// A teardown nobody can run, for a canary that spends real money.
//
// The general rule, and the one gated here: a published procedure must NAME the
// documents it feeds groundhold, and those documents must ship — because a document
// that ships is a document `examples/check.sh` loads, and one synthesized by a shell
// command in a README is checked by nobody. Scope is `examples/*/README.md`, where
// the reader is told to run the commands against their own cloud. Prose under
// website/ and docs/ is deliberately partial in places ("adopt … --map …") and stays
// out, the same boundary D607 drew.
func TestPublishedProceduresNameDocumentsThatShip(t *testing.T) {
	root := repoRootFromCmd(t)
	readmes, err := filepath.Glob(filepath.Join(root, "examples", "*", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(readmes) < 3 {
		t.Fatalf("found %d example READMEs — the scan broke and this gate would pass "+
			"over nothing (D328)", len(readmes))
	}

	invoke := regexp.MustCompile(`(?:bin/)?groundhold(?:-go)?\s+([a-z][a-z-]{2,})\b`)
	// The two document kinds every verb takes POSITIONALLY, so a match is always an
	// input the reader must already have — never an output path like `--out plan.json`.
	operand := regexp.MustCompile(`[A-Za-z0-9._/-]+\.(?:contract|candidate)\.yaml`)

	var bad []string
	invocations := 0
	for _, path := range readmes {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, path)
		dir := filepath.Dir(path)
		fenced := false
		for _, line := range joinContinuations(string(raw)) {
			if strings.HasPrefix(strings.TrimSpace(line), "```") {
				fenced = !fenced
				continue
			}
			if !fenced {
				continue // prose may describe a command; only a fence invites copying
			}
			if strings.Contains(line, "sed -i") {
				for _, doc := range operand.FindAllString(line, -1) {
					bad = append(bad, rel+": the procedure rewrites the shipped "+doc+
						" in place instead of naming a document that ships")
				}
			}
			if !invoke.MatchString(line) {
				continue
			}
			invocations++
			for _, field := range strings.Fields(line) {
				if field == "..." || field == "…" {
					bad = append(bad, rel+": `"+strings.TrimSpace(line)+
						"` elides its operands — there is nothing here to copy")
				}
			}
			for _, doc := range operand.FindAllString(line, -1) {
				_, fromRoot := os.Stat(filepath.Join(root, doc))
				_, fromHere := os.Stat(filepath.Join(dir, doc))
				if fromRoot != nil && fromHere != nil {
					bad = append(bad, rel+": names "+doc+", which does not ship")
				}
			}
		}
	}

	// Findings first, THEN the vacuity floor. The other order cost this gate its own
	// negative control: with the broken teardown restored, the floor tripped — the
	// defect DELETED two invocations — and the run reported a broken scan while the
	// three real violations went unprinted. A guard that fires before the check it
	// guards hides exactly what it was written to surface.
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("published procedures a reader cannot run:\n  %s\n"+
			"A document the project ships is a document examples/check.sh loads; one a "+
			"README synthesizes is checked by nobody.", strings.Join(bad, "\n  "))
	}
	if invocations < 6 {
		t.Fatalf("only %d published invocations found in %d example READMEs — the fence "+
			"or command scan broke (D328)", invocations, len(readmes))
	}
}

// D692, the other half: examples/check.sh must find what it checks.
//
// Its validate list was ten paths typed by hand, and the eleventh shipped contract —
// the canary's retirement contract, added in the same commit as this test — would
// have been validated by nobody. Whether a shipped example gets checked was a
// question of whether its author remembered a list in another file (D583).
//
// Expectations stay declared: the script refuses to guess whether an example is
// meant to compile or to be refused, so the PAIR table is still written out. What
// may not be hand-written is the SCOPE — hence a discovery per document kind, and
// this gate over the two lines that perform it.
func TestExampleSuiteDiscoversWhatItChecks(t *testing.T) {
	root := repoRootFromCmd(t)
	raw, err := os.ReadFile(filepath.Join(root, "examples", "check.sh"))
	if err != nil {
		t.Skip("no examples/check.sh in this tree")
	}
	script := string(raw)
	for _, kind := range []string{"contract", "candidate"} {
		find := "find examples spec/examples -name '*." + kind + ".yaml'"
		if !strings.Contains(script, find) {
			t.Errorf("examples/check.sh no longer discovers shipped %ss (%s) — a scope "+
				"retyped by hand checks the author's memory, not the tree", kind, find)
		}
	}
}

// D693: the runtime's OWN advice, at the moment a reader is most likely to follow it.
//
// D607 gated the invocations the project publishes in files. It never looked at the
// remediations the binary prints — and nine of them named a verb the reader could not
// run:
//
//	run `groundhold resume`     -> resume requires an explicit --at … (and --ledger, --provider)
//	run `groundhold discover`   -> discover requires an explicit --at …   (×5, in four drivers)
//	Run `groundhold repair`     -> repair requires --ledger
//	Run `groundhold crawl`      -> crawl requires an explicit --at …
//	run `groundhold suggest`    -> usage: groundhold suggest <contract.yaml> …
//
// Every one appears in a refusal — the ledger is corrupted, a foreign cluster sits at
// our name, a receipt is unsettled — so it is read by someone already stuck, who
// pastes it and is refused a second time by the tool that just told them what to do.
//
// The authority here is the CLI ITSELF, not a scrape of its refusal text: a verb named
// with no operands is RUN with no operands, and must not refuse. D607's derivation
// reads `"<verb> requires --<flag>"` out of main.go, which is exactly why `resume`'s
// `--provider` was missing from it — that refusal is formatted from a variable. A gate
// built on the same partial scrape would have blessed a remediation still missing a
// required flag (D317: ask the code, do not read its text).
func TestRuntimeRemediationsCanBeFollowed(t *testing.T) {
	root := repoRootFromCmd(t)
	// Only an IMPERATIVE mention: "run `groundhold x`". A verb named as a noun ("the
	// id column of `groundhold export`") is a reference, not advice, and demanding
	// flags of it would manufacture findings out of correct prose.
	imperative := regexp.MustCompile("(?:[Rr]un|re-run|then)\\s+`groundhold ([a-z][a-z-]+)([^`]*)`")

	seen := map[string]string{} // bare verb -> where it is advised
	files := 0
	mentions := 0
	err := filepath.Walk(filepath.Join(root, "go"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return err
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		files++
		rel, _ := filepath.Rel(root, path)
		for _, stmt := range joinGoConcat(string(raw)) {
			line, i := stmt.text, stmt.line-1
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue // a doc comment is not printed to anyone
			}
			for _, m := range imperative.FindAllStringSubmatch(line, -1) {
				mentions++
				if strings.TrimSpace(m[2]) == "" {
					seen[m[1]] = fmt.Sprintf("%s:%d", rel, i+1)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 || mentions < 5 {
		t.Fatalf("walked %d go files and found %d advised verbs — the scan broke and this "+
			"gate would pass over nothing (D328)", files, mentions)
	}

	// Run each bare-advised verb exactly as the reader would type it. Every one of
	// these refuses before touching anything when it refuses at all, so this is a
	// read-only question asked of the real dispatcher.
	var bad []string
	for verb, where := range seen {
		if code := runQuietly(t, verb); code != 0 {
			bad = append(bad, fmt.Sprintf("%s: `groundhold %s` is advised bare but exits %d",
				where, verb, code))
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("remediations a reader cannot follow:\n  %s\n"+
			"Advice printed by a refusal is read by someone already stuck. Name the "+
			"operands the verb needs — the caller usually knows them, and perr.AtNow "+
			"carries the clock N1 requires.", strings.Join(bad, "\n  "))
	}
}

type goStmt struct {
	line int
	text string
}

// joinGoConcat collapses Go's adjacent-literal concatenation into one logical line,
// keeping the line the statement STARTS on.
//
// Without it this gate reads a wrapped message as two fragments and finds no verb in
// either. Measured, not theorised: the mutant that re-broke the AWS lambda advice
// SURVIVED, because gofmt had split its backtick span across two source lines —
// exactly the shape two of the nine original defects had. A scanner that cannot see a
// wrapped string reports clean on the half of the code that wraps.
func joinGoConcat(text string) []goStmt {
	raw := strings.Split(text, "\n")
	var out []goStmt
	for i := 0; i < len(raw); i++ {
		cur := raw[i]
		start := i + 1
		for i+1 < len(raw) {
			trimmed := strings.TrimRight(cur, " \t")
			next := strings.TrimSpace(raw[i+1])
			if !strings.HasSuffix(trimmed, `+`) || !strings.HasPrefix(next, `"`) {
				break
			}
			joined := strings.TrimSpace(strings.TrimSuffix(trimmed, `+`))
			if strings.HasSuffix(joined, `"`) {
				cur = strings.TrimSuffix(joined, `"`) + strings.TrimPrefix(next, `"`)
			} else {
				cur = joined + next
			}
			i++
		}
		out = append(out, goStmt{line: start, text: cur})
	}
	return out
}

// runQuietly invokes the dispatcher with one argument and returns its exit code,
// with stdout and stderr parked in a temp file so a refusal does not spray the test
// log. It is the same entry point main() uses.
func runQuietly(t *testing.T, args ...string) int {
	t.Helper()
	devnull, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	outSave, errSave := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = devnull, devnull
	defer func() { os.Stdout, os.Stderr = outSave, errSave }()
	return run(args)
}

// joinContinuations rebuilds each command as ONE line. A published command wraps two
// ways: a shell backslash, and a YAML scalar folded over deeper-indented lines with no
// backslash at all. Missing the second gave a false positive on the first run of this
// gate (`audit` in gitlab-ci.yml, whose --ledger sits on the next line) — worth keeping
// in mind: a scanner that reads a wrapped command as truncated accuses correct work.
func joinContinuations(text string) []string {
	raw := strings.Split(strings.ReplaceAll(text, "\\\n", " "), "\n")
	var out []string
	for i := 0; i < len(raw); i++ {
		line := raw[i]
		if strings.TrimSpace(line) == "" {
			out = append(out, line)
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		for i+1 < len(raw) {
			next := raw[i+1]
			trimmed := strings.TrimSpace(next)
			if trimmed == "" {
				break
			}
			nextIndent := len(next) - len(strings.TrimLeft(next, " \t"))
			if nextIndent <= indent || strings.HasPrefix(trimmed, "- ") ||
				strings.HasPrefix(trimmed, "#") {
				break
			}
			line += " " + trimmed
			i++
		}
		out = append(out, line)
	}
	return out
}

// requiredFlagsByVerb reads the refusals out of main.go: `"<verb> requires --<flag>"`.
// Same derivation as D587's usage gate — the refusal is the authority, not a list.
func requiredFlagsByVerb(t *testing.T) map[string]map[string]bool {
	t.Helper()
	src := readMainSource(t)
	req := map[string]map[string]bool{}
	for _, m := range regexp.MustCompile(`"([a-z-]+) requires (?:an explicit )?(--[a-z-]+)`).
		FindAllStringSubmatch(src, -1) {
		if req[m[1]] == nil {
			req[m[1]] = map[string]bool{}
		}
		req[m[1]][m[2]] = true
	}

	// The --at refusal is formatted from a variable (`"%s requires an explicit --at"`,
	// driven by timeSensitiveVerbs), so a regex over the source finds NONE of those
	// verbs — which is why `make plan` could lose its --at and the first version of
	// this gate stayed green. Read the set the runtime actually uses (D317: ask the
	// code, do not scrape its text).
	if len(timeSensitiveVerbs) == 0 {
		t.Fatal("timeSensitiveVerbs is empty — the --at requirement would go unchecked")
	}
	for verb := range timeSensitiveVerbs {
		if req[verb] == nil {
			req[verb] = map[string]bool{}
		}
		req[verb]["--at"] = true
	}
	return req
}

func repoRootFromCmd(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "Makefile")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("no Makefile above this directory — nothing published to check")
	return ""
}

// D701: `explain` publishes the attribute note.
//
// The note key held the sharpest prose in the vocabulary — what static verification
// proves versus what an outcome probe proves — on twelve attributes, and nothing read
// it. A closed key set that merely TOLERATED it would have legalised the silence; the
// entry condition for a vocabulary key is that something consumes it, so this is the
// consumer, held here.
func TestExplainPublishesTheAttributeNote(t *testing.T) {
	root := repoRootFromCmd(t)
	vocabs, err := vocab.LoadDir(filepath.Join(root, "spec", "vocab"))
	if err != nil {
		t.Skip("no spec/vocab in this tree")
	}
	// Find a shipped attribute that actually carries a note — asserting against an
	// empty subject would pass on anything (D328).
	var attr, want string
	for _, v := range vocabs {
		for path, spec := range v.Attributes {
			if n, _ := spec["note"].(string); strings.TrimSpace(n) != "" {
				if attr == "" || path < attr {
					attr, want = path, strings.TrimSpace(n)
				}
			}
		}
	}
	if attr == "" {
		t.Fatal("no shipped attribute carries a note — this gate has no subject")
	}

	out, err := os.CreateTemp(t.TempDir(), "explain")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	save := os.Stdout
	os.Stdout = out
	code := run([]string{"explain", attr})
	os.Stdout = save
	if code != 0 {
		t.Fatalf("explain %s exited %d", attr, code)
	}
	body, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), want) {
		t.Errorf("explain %s does not print the note the vocabulary carries.\nwant: %s",
			attr, want)
	}
}

// D709: a corrupt anchor beside the ledger must not silently disarm trust.
//
// D135's whole point is that the receiver's held artifact brings the policy — "forgetting
// --trust no longer downgrades anything". The load test was `err == nil && a != nil`,
// and LoadAnchorFile returns an error for a MISSING file and a CORRUPT one alike, so a
// damaged anchor took the absent path: no trusted keys, no trustFrom cutoff, and every
// verb ran verifying under no policy at all. The downgrade D135 prevents, caused by a
// damaged file rather than a forgotten flag.
func TestACorruptAnchorRefusesInsteadOfDisarmingTrust(t *testing.T) {
	dir := t.TempDir()
	lp := filepath.Join(dir, "l.jsonl")
	if err := os.WriteFile(lp, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ledger.AnchorPath(lp), []byte("{not an anchor"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runQuietly(t, "runs", "--ledger", lp, "--at", "2026-01-01T00:00:00Z"); code == 0 {
		t.Error("a verb ran to success beside an unreadable anchor — the trust policy " +
			"it should verify under was silently not applied")
	}

	// Control: with NO anchor at all there is no policy to lose, and the verb must
	// not be blocked. Absent and unreadable are different answers.
	clean := filepath.Join(t.TempDir(), "l.jsonl")
	if err := os.WriteFile(clean, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runQuietly(t, "runs", "--ledger", clean, "--at", "2026-01-01T00:00:00Z"); code != 0 {
		t.Errorf("no anchor is not a failure — an absent policy is not an unreadable "+
			"one; exit %d", code)
	}
}
