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

// D498: two decisions with the same number make every reference to it ambiguous.
//
// DESIGN.md is append-only and its headings are the anchors everything else cites —
// code comments, MATURITY's gap list (D465 made those citations mandatory), the memory
// files, the canary runbook. "See D329" is only useful if D329 is one thing.
//
// Three numbers are currently used twice, all from parallel sessions appending at the
// same time. They are NOT renumbered: D329 and D330 are each cited from several Go
// files and from the canary runbook, and rewriting a number breaks references that are
// correct for one of the two meanings and wrong for the other — the fix would create
// exactly the ambiguity it removes. They are recorded here instead, and the gate stops
// a FOURTH from arriving unnoticed.
var knownDuplicateDecisions = map[int]string{
	94:  "messaging-topic residency vs verdict provability — two D94s from parallel work",
	329: "OAC dual invoke vs the banner registry — cited from apireq and the canary runbook",
	330: "reachability probe vs the routing-contract artefacts — cited from azure/contract",
}

func TestDesignDecisionNumbersAreUnique(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "docs", "DESIGN.md"))
	if err != nil {
		t.Fatal(err)
	}
	heading := regexp.MustCompile(`(?m)^## D(\d+)`)
	counts := map[int]int{}
	for _, m := range heading.FindAllStringSubmatch(string(raw), -1) {
		var n int
		_, _ = fmt.Sscanf(m[1], "%d", &n)
		counts[n]++
	}
	if len(counts) < 200 {
		t.Fatalf("only %d decision headings parsed — the gate would be vacuous (D328)",
			len(counts))
	}

	var unexpected, stale []string
	for n, c := range counts {
		if c > 1 {
			if _, known := knownDuplicateDecisions[n]; !known {
				unexpected = append(unexpected,
					fmt.Sprintf("D%d appears %d times", n, c))
			}
		}
	}
	for n := range knownDuplicateDecisions {
		if counts[n] <= 1 {
			stale = append(stale, fmt.Sprintf("D%d is no longer duplicated", n))
		}
	}
	sort.Strings(unexpected)
	sort.Strings(stale)

	if len(unexpected) > 0 {
		t.Errorf("decision numbers used more than once: %v\n"+
			"Every reference to that number is now ambiguous — code comments, MATURITY's "+
			"gap citations, the memory files. Pick the next free number before appending "+
			"(D498).", unexpected)
	}
	if len(stale) > 0 {
		t.Errorf("knownDuplicateDecisions is out of date: %v — remove the entry so the "+
			"list keeps meaning what it says", stale)
	}
}

// D499: a decision number cited from the SOURCE must resolve, exactly as one cited
// from MATURITY must (D465). Eleven Go comments pointed at D358 and D411, neither of
// which was in the file — the same conflict-resolution loss D498 caught in the act,
// found afterwards because nothing looked.
//
// Combined headings are real and legitimate (`## D467/D468 — ...` covers one decision
// taken on two clouds), so the parser reads every number a heading names, not just the
// first. That distinction is why D468 looked dangling and was not.
var designHeadingNums = regexp.MustCompile(`(?m)^## D(\d+)(?:/D(\d+))?`)

func decisionNumbers(t *testing.T, root string) map[int]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "docs", "DESIGN.md"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[int]bool{}
	for _, m := range designHeadingNums.FindAllStringSubmatch(string(raw), -1) {
		for _, g := range m[1:] {
			if g == "" {
				continue
			}
			var n int
			_, _ = fmt.Sscanf(g, "%d", &n)
			out[n] = true
		}
	}
	return out
}

// TestDesignCitesItsOwnDecisions: the record's INTERNAL cross-references must resolve
// too. Three inside DESIGN.md pointed at D125, a third entry lost the same way as D358
// and D411 (D500). The published docs were gated by D465 and the source by D499; the
// record itself was the last unchecked citer, which is the least surprising place for
// a dangling reference to survive and the worst place for one to live.
func TestDesignCitesItsOwnDecisions(t *testing.T) {
	root := repoRoot(t)
	have := decisionNumbers(t, root)
	raw, err := os.ReadFile(filepath.Join(root, "docs", "DESIGN.md"))
	if err != nil {
		t.Fatal(err)
	}
	// D789: this was `\d{1,3}`, so it would have stopped seeing citations entirely once
	// the numbers reached four digits — silently, while still passing. 787 entries exist
	// today and forty were written in one day; the horizon was weeks, not years. A gate
	// with a bound that the thing it measures will cross is a gate carrying an expiry
	// date nobody set. (Naming the four-digit number here would itself be a citation of
	// a decision that does not exist — this gate would catch it, and did.)
	ref := regexp.MustCompile(`\bD(\d+)\b`)
	var dangling []string
	var cites int
	for i, line := range splitLines(string(raw)) {
		if strings.HasPrefix(line, "## D") {
			continue // the heading declares, it does not cite
		}
		for _, m := range ref.FindAllStringSubmatch(line, -1) {
			var n int
			_, _ = fmt.Sscanf(m[1], "%d", &n)
			cites++
			if !have[n] {
				dangling = append(dangling, fmt.Sprintf("DESIGN.md:%d cites D%d", i+1, n))
			}
		}
	}
	if cites < 500 {
		t.Fatalf("only %d internal citations found — the detector broke (D328)", cites)
	}
	sort.Strings(dangling)
	if len(dangling) > 0 {
		t.Errorf("DESIGN.md cites decisions it does not contain: %v\n"+
			"An append-only record whose own cross-references dangle has lost the thing "+
			"that makes it a record (D500).", dangling)
	}
}

func TestSourceCitesDecisionsThatExist(t *testing.T) {
	root := repoRoot(t)
	have := decisionNumbers(t, root)
	if len(have) < 200 {
		t.Fatalf("only %d decisions parsed — the gate would be vacuous (D328)", len(have))
	}
	// D789: this was `\d{1,3}`, so it would have stopped seeing citations entirely once
	// the numbers reached four digits — silently, while still passing. 787 entries exist
	// today and forty were written in one day; the horizon was weeks, not years. A gate
	// with a bound that the thing it measures will cross is a gate carrying an expiry
	// date nobody set. (Naming the four-digit number here would itself be a citation of
	// a decision that does not exist — this gate would catch it, and did.)
	ref := regexp.MustCompile(`\bD(\d+)\b`)
	var dangling []string
	var cites int
	err := filepath.Walk(filepath.Join(root, "go"), func(p string, info os.FileInfo, werr error) error {
		if werr != nil || info == nil || info.IsDir() || filepath.Ext(p) != ".go" {
			return nil
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		for i, line := range splitLines(string(raw)) {
			for _, m := range ref.FindAllStringSubmatch(line, -1) {
				var n int
				_, _ = fmt.Sscanf(m[1], "%d", &n)
				cites++
				if !have[n] {
					dangling = append(dangling, fmt.Sprintf("%s:%d cites D%d", rel, i+1, n))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if cites < 200 {
		t.Fatalf("only %d decision citations found in the source — the detector broke, "+
			"not the comments (D328)", cites)
	}
	sort.Strings(dangling)
	if len(dangling) > 0 {
		t.Errorf("source comments cite decisions DESIGN.md does not have: %v\n"+
			"A reader following the citation lands nowhere. Either the entry was lost in "+
			"a conflict (write the stub, D499) or the number is a typo.", dangling)
	}
}

func splitLines(s string) []string { return strings.Split(s, "\n") }
