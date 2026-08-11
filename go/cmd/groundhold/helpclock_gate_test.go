package main

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D688. The help text names the verbs that REQUIRE `--at`. It listed nine, and
// `timeSensitiveVerbs` holds twenty — so eleven verbs, including every verb added
// to the set since the sentence was written, were absent from the sentence that
// documents them. Measured on the one an audit hit:
//
//	groundhold discover --provider fake --region eu-central-1 > discover.json
//	  discover requires an explicit --at (RFC3339 timestamp)      exit 1
//	groundhold --help
//	  groundhold discover … [--at <ts>]          <- bracketed as OPTIONAL
//	  Time-sensitive verbs (plan/apply/…/resume) REQUIRE an explicit --at
//	                                             <- discover not among them
//
// Two published statements about one verb, both wrong, in the text the tool prints
// about itself. The set is the source of truth; this gate reads it rather than a
// second list, so the sentence cannot drift from what the binary enforces.
func TestHelpNamesEveryVerbThatRequiresAnExplicitClock(t *testing.T) {
	if len(timeSensitiveVerbs) < 10 {
		t.Fatalf("timeSensitiveVerbs holds %d verbs — the subject collapsed",
			len(timeSensitiveVerbs))
	}
	help := captureStdout(t, func() { run([]string{"--help"}) })
	if len(help) < 500 {
		t.Fatalf("--help produced %d bytes — nothing to check", len(help))
	}

	// The sentence that makes the claim, and the verb list inside it.
	i := strings.Index(help, "REQUIRE an explicit --at")
	if i < 0 {
		t.Fatal("the help no longer states the rule — this gate is measuring nothing")
	}
	start := strings.LastIndex(help[:i], "Time-sensitive verbs")
	if start < 0 {
		t.Fatal("the rule's sentence moved")
	}
	// The whole paragraph, not the words before the phrase: the list may sit on
	// either side of it, and reading only one side is how a gate measures the
	// sentence's shape instead of its content.
	end := strings.Index(help[start:], "Provider verbs")
	if end < 0 {
		end = len(help) - start
	}
	claim := help[start : start+end]
	listed := map[string]bool{}
	for _, w := range regexp.MustCompile(`[a-z]+`).FindAllString(claim, -1) {
		listed[w] = true
	}

	var missing []string
	for verb := range timeSensitiveVerbs {
		if !listed[verb] {
			missing = append(missing, verb)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the help's list of verbs that REQUIRE --at omits %s — the binary "+
			"refuses each of them without it, so the text the tool prints about "+
			"itself contradicts the tool", strings.Join(missing, ", "))
	}

	// And the per-verb usage line must not bracket --at as optional for a verb that
	// requires it. `[--at` is the optional form in this help's own notation.
	for verb := range timeSensitiveVerbs {
		usage := regexp.MustCompile(`(?m)^\s+groundhold ` + verb + `\b[^\n]*(?:\n\s{15,}[^\n]*)*`)
		for _, block := range usage.FindAllString(help, -1) {
			if strings.Contains(block, "[--at") {
				t.Errorf("the usage for %q brackets --at as optional and the verb "+
					"refuses without it:\n%s", verb, strings.TrimSpace(block))
			}
		}
	}
}
