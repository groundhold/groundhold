package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D703: an answered question must stop being listed as open.
//
// Three of CLAUDE.md's open questions were resolved in one session — D481 by D698,
// D509 by D699, D526 by D700 — and the index that TELLS the next author what is open
// went on saying they were open, complete with "do not resolve unilaterally". The
// decision record is append-only and correct; the index is the thing a reader consults
// first, and nothing connected the two.
//
// The convention this gate rests on: an entry that resolves an open question writes
// `Answers: Dxxx.` on its own line. That makes the link machine-findable in the
// direction it is needed — from the answer to the question — and this gate walks it.
//
// It deliberately does NOT check the reverse (an open question with no answer is just
// an open question), and it says nothing about whether the answer is right.
func TestAnsweredQuestionsAreNotStillListedAsOpen(t *testing.T) {
	root := repoRoot(t)
	design, err := os.ReadFile(filepath.Join(root, "docs", "DESIGN.md"))
	if err != nil {
		t.Skip("no docs/DESIGN.md in this tree")
	}
	answered := regexp.MustCompile(`(?m)^Answers: (D\d+)\.`).
		FindAllStringSubmatch(string(design), -1)
	if len(answered) == 0 {
		t.Fatal("no `Answers: Dxxx.` line in the decision record — the convention this " +
			"gate walks is gone, and it would pass over a stale index (D328)")
	}

	claude, err := os.ReadFile(filepath.Join(root, "CLAUDE.md"))
	if err != nil {
		t.Skip("CLAUDE.md does not cross into this tree")
	}
	body := string(claude)
	i := strings.Index(body, "## Open questions")
	if i < 0 {
		t.Fatal("CLAUDE.md has no open-questions section — this gate has no subject")
	}
	open := body[i:]
	if j := strings.Index(open[1:], "\n## "); j > 0 {
		open = open[:j+1]
	}

	for _, m := range answered {
		q := m[1]
		k := strings.Index(open, "raised "+q)
		if k < 0 {
			continue // answered something that was never in the index — fine
		}
		// The question is still listed. It must say so: the same sentence that names
		// the question has to carry ANSWERED, or a reader is told not to resolve
		// something that has been resolved.
		end := k + 240
		if end > len(open) {
			end = len(open)
		}
		window := open[k:end]
		if !strings.Contains(window, "ANSWERED") {
			t.Errorf("%s is answered in docs/DESIGN.md but CLAUDE.md still lists it as an "+
				"OPEN question with no answer marker — the index a reader consults first "+
				"is telling them not to resolve something that is resolved", q)
		}
	}
}
