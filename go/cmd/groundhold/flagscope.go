package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// D1109. The flag switch in main is GLOBAL: a token is recognised if ANY verb takes
// it. D567 shut the narrow door — a token no verb at all knows is an operator error
// rather than a positional — and left the wide one open by construction. A flag that
// belongs to ANOTHER verb was accepted everywhere and consumed nowhere:
//
//	verify <c> <cand> --heads /x     exit 0   (--heads is forecast's)
//	verify <c> <cand> --ledger /x    exit 0   (verify reads no ledger)
//	plan   <c> <cand> --heads /x     exit 0   (only forecast reads heads)
//	hash   <doc> --at <ts>           exit 0   (hash has no clock)
//
// That is the shape of the run D567 was found by: `posture --discovery discovery.json`
// printed `"shadow": 0` and a hashed posture over a cluster holding 169 unmanaged
// objects — a confident, signed answer to a question it was never asked, because the
// operator's actual question went into a variable posture never reads.
//
// The allowed set is DERIVED from the usage block compiled into this binary, so the
// refusal is a projection of the documentation rather than a second list that drifts
// from it (the same move as reading the deny list from the export script). Adding a
// flag to a verb means documenting it, in the one place readers already look.

// usageFlagsPattern matches a verb's opening usage line: two spaces, "groundhold",
// the verb.
// Two published forms: the plain one, and the one that puts a global flag before the
// verb (`groundhold [--provider aws|gcp] apireq classify …`). Missing the second form
// makes a verb look like it documents fewer flags than it does, and this check would
// then refuse invocations the usage block itself prints.
var usageVerbLine = regexp.MustCompile(`^  groundhold (?:\[[^\]]*\] )?([a-z][a-z-]*)(\s|$)`)

// usageContinuation is a wrapped continuation of the line above it. A blank line or a
// shallower indent ends the verb's block — without that boundary the parser runs on
// into the prose sections and every verb inherits every flag mentioned anywhere,
// which would make this check pass on everything.
var usageContinuation = regexp.MustCompile(`^ {5,}\S`)

var usageFlag = regexp.MustCompile(`--[a-z][a-z-]*`)

// presentationGlobals are documented under "Global:" as applying to every verb: the
// vocabulary controls, the rendering controls, help, and the machine-output switch.
// --version is answered before dispatch and never reaches this check; it is listed so
// a reader does not think it was forgotten.
var presentationGlobals = map[string]bool{
	"--vocab": true, "--no-vocab": true, "--explain": true,
	"--color": true, "--ascii": true, "--help": true, "--json": true,
	"--version": true,
	// Signing and trust are armed BEFORE dispatch (D102: a bad key refuses up front
	// rather than half-signing a session), so no verb "takes" them — they configure
	// the ledger layer every verb writes through. Per-verb enforcement would refuse
	// `publish --sign-key`, which is how production builds a signed ledger.
	"--sign-key": true, "--trust": true, "--trust-from": true,
}

// workspaceContextSentence is where the usage block names the flags an operator sets
// once per workspace and omits per command — "just location/identity", in its words.
// They are read from that sentence rather than restated here, so the check and the
// documentation cannot disagree about which flags are safe everywhere. The same
// paragraph is emphatic about what is NOT in the set: --at is a safety invariant that
// never defaults, and the consent flags must be typed each time, on purpose. Both stay
// per-verb, which is why `hash --at` and `apply --yes` are still answerable questions.
var workspaceContextSentence = regexp.MustCompile(
	`(?s)Workspace-context flags default from the environment when absent(.*?)These are just`)

func globalFlagsFromUsage() map[string]bool {
	out := map[string]bool{}
	for f := range presentationGlobals {
		out[f] = true
	}
	if m := workspaceContextSentence.FindStringSubmatch(usage); m != nil {
		for _, f := range usageFlag.FindAllString(m[1], -1) {
			out[f] = true
		}
	}
	return out
}

// flagsByVerb parses the usage block into the set of flags each verb documents.
func flagsByVerb() map[string]map[string]bool {
	out := map[string]map[string]bool{}
	var cur string
	for _, line := range strings.Split(usage, "\n") {
		if m := usageVerbLine.FindStringSubmatch(line); m != nil {
			cur = m[1]
			if out[cur] == nil {
				out[cur] = map[string]bool{}
			}
		} else if cur != "" && (strings.TrimSpace(line) == "" || !usageContinuation.MatchString(line)) {
			cur = ""
		}
		if cur != "" {
			for _, f := range usageFlag.FindAllString(line, -1) {
				out[cur][f] = true
			}
		}
	}
	return out
}

// refuseFlagsThisVerbDoesNotTake returns a non-zero exit when the operator passed a
// flag this verb does not document. It is an OPERATOR error (exit 1), not a refusal
// of a well-formed request: the request was never well formed, and the alternative —
// running anyway — answers a question that was not asked.
func refuseFlagsThisVerbDoesNotTake(verb string, seen []string) int {
	if len(seen) == 0 {
		return 0
	}
	byVerb := flagsByVerb()
	globalFlags := globalFlagsFromUsage()
	allowed, documented := byVerb[verb]
	if !documented {
		// A verb with no usage line of its own (an alias, or one reached another
		// way) gets no per-verb opinion. Silence here is deliberate: refusing on a
		// verb this parser cannot see would break invocations to prove a point.
		return 0
	}
	for _, f := range seen {
		if allowed[f] || globalFlags[f] {
			continue
		}
		var takers []string
		for v, fs := range byVerb {
			if fs[f] {
				takers = append(takers, v)
			}
		}
		sort.Strings(takers)
		fmt.Fprintf(os.Stderr,
			"%s does not take %s — refusing rather than ignoring it: a run that "+
				"drops an input answers a question you did not ask.\n", verb, f)
		if len(takers) > 0 {
			fmt.Fprintf(os.Stderr, "  %s is taken by: %s\n", f, strings.Join(takers, ", "))
		} else {
			fmt.Fprintf(os.Stderr, "  %s is not taken by any verb.\n", f)
		}
		fmt.Fprintf(os.Stderr, "  groundhold %s --help lists what this verb accepts.\n", verb)
		return 1
	}
	return 0
}
