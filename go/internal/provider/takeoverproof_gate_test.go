package provider_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// D1248. D1246 found that the published proof of takeover could not pass — `adopt`
// binds the ledger and touches nothing, so the first `converge` plans a `claim`, and
// the documents demanded a no-op BEFORE that claim while diagnosing the planned claim
// as a bad draft. Two places were corrected: the spec's §proof of takeover and the
// skill's step 5.
//
// Five more said the same thing and were left standing — the intro sentence of the same
// spec file, its migration path, the README's onboarding paragraph, and the skill's
// frontmatter and its Never list. Fixing the file the finding was reported in is not
// fixing the class, which is a lesson this codebase has already written down and I did
// not apply while writing the entry that records it.
//
// So the ratchet is over the CLAIM, not over the two files: any published document that
// tells a reader a converged no-op proves the takeover must also name the step that
// makes the no-op reachable. A sixth statement cannot arrive mute.

// takeoverProofDocs finds the published surfaces a reader or an agent actually follows.
// docs/ is deliberately absent: DESIGN.md is a record of decisions in the order they were
// taken, and entries written before D1246 describe the world as it was then.
//
// This is a SCAN and not a list, because the list version had a phantom in it within an
// hour of being written — `website/docs/index.md`, a path that has never existed, since
// the pages live under `website/pages/`. It was invisible because missing files were
// skipped, so one of seven entries watched nothing. A hand-kept register of published
// surfaces goes stale the first time one moves, and it cannot notice a page that arrives
// after it was written; a scan has neither failure.
func takeoverProofDocs(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	add := func(p string) {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			out = append(out, p)
		}
	}
	add("README.md")
	add("examples/check.sh")
	for _, dir := range []string{"spec", "website/pages", "website", "examples"} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
				add(dir + "/" + e.Name())
			}
		}
	}
	skills, err := os.ReadDir(filepath.Join(root, ".claude", "skills"))
	if err != nil {
		t.Fatalf("read skills: %v", err)
	}
	for _, e := range skills {
		if e.IsDir() {
			add(".claude/skills/" + e.Name() + "/SKILL.md")
		}
	}
	if len(out) < 15 {
		t.Fatalf("the published-surface scan found only %d files (%v) — it is broken, and a "+
			"gate over a set it cannot see is worse than none", len(out), out)
	}
	return out
}

// The phrases by which a document asserts the proof. Any one of them commits the file
// to explaining what has to happen first.
var proofPhrases = []string{"no-op proof", "converged no-op", "no-op run"}

// proofStatements returns the offset of every assertion that a no-op proves takeover.
// Per STATEMENT rather than per file: one corrected paragraph must not excuse the next.
func proofStatements(body string) []int {
	var at []int
	for _, p := range proofPhrases {
		for i := 0; ; {
			j := strings.Index(body[i:], p)
			if j < 0 {
				break
			}
			at = append(at, i+j)
			i += j + len(p)
		}
	}
	sort.Ints(at)
	return at
}

// near is the window a reader takes in around the sentence they are reading. Wide
// enough that the explanation may sit a few lines away, narrow enough that a mention
// elsewhere in a long document does not count as having said it here.
func near(body string, at int) string {
	const window = 420
	lo, hi := at-window, at+window
	if lo < 0 {
		lo = 0
	}
	if hi > len(body) {
		hi = len(body)
	}
	return body[lo:hi]
}

func excerpt(body string, at int) string {
	lo, hi := at-40, at+40
	if lo < 0 {
		lo = 0
	}
	if hi > len(body) {
		hi = len(body)
	}
	return strings.Join(strings.Fields(body[lo:hi]), " ")
}

func TestEveryStatementOfTheTakeoverProofNamesTheClaim(t *testing.T) {
	root := repoRoot(t)
	var asserts, silent []string
	for _, rel := range takeoverProofDocs(t, root) {
		// The scan only yields files it stat'd, so an unreadable one here is a real fault
		// and never a stale name.
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		body := string(raw)
		for _, where := range proofStatements(body) {
			asserts = append(asserts, rel)
			// PROXIMITY, not presence. The first cut asked whether the file contained
			// "claim" anywhere and passed on README before a word of it was corrected —
			// because README says "an RTO claim is not satisfied by configuration", a
			// sentence about something else entirely. A gate satisfied by unrelated prose
			// is the vacuous shape this codebase keeps meeting, and I built it again while
			// writing the entry that records the class.
			if !strings.Contains(near(body, where), "claim") {
				silent = append(silent, rel+" ("+excerpt(body, where)+")")
			}
		}
	}

	// D328: the subject must exist. If nothing published describes the proof any more,
	// this gate is watching nothing and should be retired deliberately rather than
	// passing quietly — and the proof itself would then be undocumented, which is worse.
	if len(asserts) < 3 {
		t.Fatalf("only %d published documents describe the takeover proof (%v) — the scan "+
			"is broken, or the proof has gone undocumented", len(asserts), asserts)
	}
	sort.Strings(silent)
	if len(silent) > 0 {
		t.Errorf("these documents promise that a converged no-op proves the takeover and "+
			"never name the claim that makes it reachable:\n  %s\n\n"+
			"`adopt` binds the ledger and touches nothing in the cloud, so the first "+
			"`converge` plans a claim and REFUSES without --yes. A reader following this "+
			"text reads that refusal as a bad draft and redrafts forever — no redraft "+
			"removes a missing authorship stamp (D1246).", strings.Join(silent, "\n  "))
	}
}

// The correction has to say the ORDER, not merely mention the word. "claim" appears in
// unrelated senses across a large document, so the two files that carry the full
// explanation are held to naming what comes first.
func TestTheSpecAndSkillSayTheClaimComesFirst(t *testing.T) {
	root := repoRoot(t)
	for rel, must := range map[string][]string{
		"spec/onboarding.md":                       {"claim", "adopt"},
		".claude/skills/onboard-existing/SKILL.md": {"claim", "not a draft to fix"},
	} {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for _, m := range must {
			if !strings.Contains(string(raw), m) {
				t.Errorf("%s must contain %q — the diagnosis is the harmful half: a planned "+
					"claim read as a bad draft sends the operator back to redraft, and the "+
					"next line forbids the only act that ends the loop", rel, m)
			}
		}
	}
}
