package main

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// D586. The usage block is advice, and today's walk established that advice is a
// published claim like any other (D569, D585). Two of the eleven verbs that REQUIRE
// `--provider` do not mention it in their own usage line:
//
//	groundhold crawl --at <ts> [--budget <n>] [--out <dir>] [--pairings <f>]
//	groundhold react --event <file> --ledger <f> --at <ts> [--crawl <base.json>]
//
// Typed exactly as shown, `crawl` answers `crawl requires an explicit --provider ...
// INVALID`. I hit this myself earlier the same day, following the help text, and read
// it as my own mistake — which is what an operator will do.
//
// The check is derived from `providerVerbs`, the CLI's own closed set (D571 pruned it
// to the verbs that actually reach a driver), so a verb added there later cannot
// leave a stale usage line behind (D550).
func TestUsageShowsTheProviderFlagWhereItIsRequired(t *testing.T) {
	blocks := usageBlocks(t)

	var missing []string
	checked := 0
	for verb := range providerVerbs {
		b, ok := blocks[verb]
		if !ok {
			t.Errorf("%q requires --provider and has no usage entry at all", verb)
			continue
		}
		checked++
		if !strings.Contains(b, "--provider") {
			missing = append(missing, verb)
		}
	}
	if checked < len(providerVerbs) {
		t.Errorf("checked %d of %d provider verbs — the gate skipped its own subject",
			checked, len(providerVerbs))
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%v require --provider and their usage lines do not show it — typed as "+
			"printed, the invocation refuses, and the operator reads it as their own "+
			"mistake", missing)
	}
}

// D587. D586 fixed `--provider`, which is one flag. The CLASS is "a flag a verb
// refuses without must be shown in that verb's usage line", and D583's test applies:
// a gate covering one flag leaves the next author to remember the rest.
//
// The subject is derived from the refusals themselves — every `"<verb> requires
// --<flag>"` message in the source — so a new required flag is advertised or this
// fails. Measured when written: all twenty verbs that refuse without a flag already
// show it, `--provider` having been the only gap. Held rather than left to
// maintenance, which is the state a gap is in just before it opens (D554).
func TestUsageShowsEveryFlagAVerbRefusesWithout(t *testing.T) {
	src := readMainSource(t)
	req := map[string]map[string]bool{}
	// Two phrasings, because the subject is derived from prose the author chose. Twenty
	// refusals say "<verb> requires --flag"; one says "<verb>: --flag is required", and
	// a gate that reads only the first shape decides its own subject by spelling
	// (D1252). Its flag was advertised — measured, not assumed — so nothing was wrong;
	// the reach was just narrower than the sentence above claims.
	shapes := []*regexp.Regexp{
		regexp.MustCompile(`"([a-z0-9-]+) requires (?:an explicit )?(--[a-z-]+)`),
		regexp.MustCompile(`"([a-z0-9-]+): (--[a-z-]+) is required`),
	}
	var matches [][]string
	for _, re := range shapes {
		matches = append(matches, re.FindAllStringSubmatch(src, -1)...)
	}
	for _, m := range matches {
		if req[m[1]] == nil {
			req[m[1]] = map[string]bool{}
		}
		req[m[1]][m[2]] = true
	}
	if len(req) < 10 {
		t.Fatalf("parsed %d verbs with required flags — the probe broke and this gate "+
			"would pass on anything", len(req))
	}
	blocks := usageBlocks(t)
	var bad []string
	for verb, flags := range req {
		b, ok := blocks[verb]
		if !ok {
			// A flag that requires another flag (`--quarantine requires --fingerprint`)
			// has no usage line of its own and never should. Anything else with no block
			// is a VERB this gate cannot see, and skipping it quietly is how the parser's
			// blindness above survived: the subject vanished and the gate reported clean
			// over what was left (D1252).
			if strings.HasPrefix(verb, "--") {
				continue
			}
			t.Errorf("%q refuses without a flag and has no usage block — either the usage "+
				"line is missing or the parser cannot read it. Both mean this gate is not "+
				"checking the verb it names.", verb)
			continue
		}
		for f := range flags {
			if !strings.Contains(b, f) {
				bad = append(bad, verb+" "+f)
			}
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("%v: the verb refuses without the flag and its usage line does not "+
			"show it — the invocation an operator copies cannot run", bad)
	}
}

// usageBlocks splits the usage text into one entry per verb, continuation lines
// folded in. Shared by both gates so a parser fix reaches each of them (D583).
func usageBlocks(t *testing.T) map[string]string {
	t.Helper()
	// D1252: the class was `[a-z-]+` — no digit. On the `k8s-skeleton` line the capture
	// stopped at `k` and the required `\s` then met `8`, so the LINE did not match and
	// the verb had no block at all. Both gates below then treated it as absent: one
	// would have said so, the other skipped it silently. Fifty-two of fifty-three, and
	// nothing said which one was gone.
	head := regexp.MustCompile(`(?m)^  groundhold ([a-z0-9-]+)\s`)
	blocks := map[string]string{}
	var cur string
	for _, line := range strings.Split(usage, "\n") {
		if m := head.FindStringSubmatch(line); m != nil {
			cur = m[1]
			blocks[cur] = line
			continue
		}
		if cur == "" {
			continue
		}
		if strings.TrimSpace(line) == "" {
			cur = ""
			continue
		}
		if strings.HasPrefix(line, strings.Repeat(" ", 18)) {
			blocks[cur] += " " + line
		}
	}
	if len(blocks) < 20 {
		t.Fatalf("parsed %d usage entries — the probe broke and this gate would pass "+
			"on anything", len(blocks))
	}
	return blocks
}

// readMainSource reads the CLI source the refusals live in.
func readMainSource(t *testing.T) string {
	t.Helper()
	_, self, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(self), "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// D1252. The parser above is shared by both gates, so its blindness is theirs. A
// character class cannot be proven by a tree that happens to hold no counter-example,
// and until `k8s-skeleton` arrived this tree held none — which is why the gap opened
// unobserved. So the parser is asked directly whether it can see the verb it lost, and
// how many it finds at all.
func TestTheUsageParserSeesEveryVerbIncludingOnesWithDigits(t *testing.T) {
	blocks := usageBlocks(t)
	if len(blocks) < 50 {
		t.Fatalf("the usage parser found %d verbs — it is broken, and both gates over it "+
			"would then report clean about whatever survived", len(blocks))
	}
	if _, ok := blocks["k8s-skeleton"]; !ok {
		var digitless int
		for v := range blocks {
			if strings.ContainsAny(v, "0123456789") {
				digitless++
			}
		}
		t.Errorf("the usage parser cannot see `k8s-skeleton` (%d of %d parsed verbs "+
			"contain a digit). A verb it cannot see has no usage block, and a gate that "+
			"skips a missing block checks one fewer thing than it says it does.",
			digitless, len(blocks))
	}
}
