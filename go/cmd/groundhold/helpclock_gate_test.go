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

// D1006. The help publishes two more closed sets that had drifted from the code: the
// verbs that REQUIRE --provider (the F4 note still listed `repair` and `anchor`, removed
// from providerVerbs in D571 — pure-ledger verbs that name no driver), and the accepted
// provider NAMES (three copies said "aws|gcp|azure|k8s|fake" while 8 are accepted, so a
// user who mistyped `cloudfare` was told cloudflare was not a real provider). Both are
// reconciled here against the sets the binary enforces, so neither can outlive the code.
func TestHelpNamesTheProviderVerbsAndProviders(t *testing.T) {
	if len(providerVerbs) < 8 || len(knownProviders) < 6 {
		t.Fatalf("provider sets collapsed (%d verbs, %d providers)",
			len(providerVerbs), len(knownProviders))
	}
	help := captureStdout(t, func() { run([]string{"--help"}) })
	if len(help) < 500 {
		t.Fatalf("--help produced %d bytes — nothing to check", len(help))
	}

	vstart := strings.Index(help, "Provider verbs (")
	if vstart < 0 {
		t.Fatal("the help no longer states the --provider rule in the form this gate reads")
	}
	seg := help[vstart:]
	vend := strings.Index(seg, ") REQUIRE")
	pstart := strings.Index(seg, "--provider (")
	if vend < 0 || pstart < 0 {
		t.Fatal("the --provider verb or name list lost the shape this gate reads")
	}
	pend := strings.Index(seg[pstart:], ")")
	if pend < 0 {
		t.Fatal("the accepted-provider list lost its closing paren")
	}

	reconcile := func(what, listText string, tokenRe *regexp.Regexp, enforced map[string]bool) {
		prose := map[string]bool{}
		for _, w := range tokenRe.FindAllString(listText, -1) {
			prose[w] = true
		}
		var miss, extra []string
		for v := range enforced {
			if !prose[v] {
				miss = append(miss, v)
			}
		}
		for w := range prose {
			if !enforced[w] {
				extra = append(extra, w)
			}
		}
		sort.Strings(miss)
		sort.Strings(extra)
		if len(miss) > 0 {
			t.Errorf("the help's %s OMITS %s — the binary enforces each, so the text the "+
				"tool prints about itself contradicts the tool", what, strings.Join(miss, ", "))
		}
		if len(extra) > 0 {
			t.Errorf("the help's %s names %s, which the binary does NOT enforce (a stale "+
				"published set — D1006/D571)", what, strings.Join(extra, ", "))
		}
	}

	reconcile("--provider verb list", seg[len("Provider verbs ("):vend],
		regexp.MustCompile(`[a-z]+`), providerVerbs)
	reconcile("accepted-provider list", seg[pstart+len("--provider ("):pstart+pend],
		regexp.MustCompile(`[a-z0-9]+`), knownProviders)
}
