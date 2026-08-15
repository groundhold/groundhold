package main

import (
	"strings"
	"testing"
)

// D1109. The check that a verb refuses a flag it does not take is only worth having if
// it can still fail. Three ways it could quietly stop working, each asserted here.
func TestAVerbRefusesAFlagThatBelongsToAnotherVerb(t *testing.T) {
	byVerb := flagsByVerb()
	if len(byVerb) < 40 {
		t.Fatalf("parsed %d verbs out of the usage block — the parser broke, and a "+
			"verb it cannot see gets no opinion, so this check would pass on "+
			"everything (D328)", len(byVerb))
	}

	// The parser must not run past a verb's own block. If it does, every verb
	// inherits every flag named anywhere in the prose and nothing is ever refused.
	// `certify-capsule` is the verb whose block ends where the prose begins, so it is
	// the one that leaks first: without the boundary it inherits every flag named in
	// the sections below it, and after that no verb refuses anything. `hash` documents
	// no flags either and is a second witness.
	for _, v := range []string{"certify-capsule", "hash"} {
		if n := len(byVerb[v]); n != 0 {
			t.Errorf("%s documents no flags of its own, yet the parser gave it %d (%v) "+
				"— a verb's block ran on into the prose, and every verb it swallowed "+
				"now accepts every flag mentioned there", v, n, byVerb[v])
		}
	}

	// The invocations D1092 recorded as landing on exit 0 — minus the one this
	// deliberately still allows, see below.
	for _, c := range []struct{ verb, flag string }{
		{"verify", "--heads"},
		{"plan", "--heads"},
		{"hash", "--at"},
		{"posture", "--discovery"},
	} {
		if rc := refuseFlagsThisVerbDoesNotTake(c.verb, []string{c.flag}); rc == 0 {
			t.Errorf("%s accepted %s, which it does not read — the run would answer a "+
				"question the operator did not ask", c.verb, c.flag)
		}
	}

	// And the other direction, which is the half that breaks people's invocations:
	// a flag the verb DOES document must survive, as must every global.
	for _, c := range []struct{ verb, flag string }{
		{"verify", "--json"},
		{"verify", "--explain"},
		{"plan", "--ledger"},    // workspace context, documented as global
		{"apply", "--provider"}, // same
		{"react", "--pairings"}, // documented after this check found it undocumented
		{"forecast", "--heads"},
		// D1110: the escape hatch D1109 silently disabled. It must stay accepted by
		// the verbs that read it — nothing else in the tree passes this flag, so
		// without this assertion breaking it again would go unnoticed a second time.
		{"verify", "--allow-plaintext-secret"},
		{"apply", "--allow-plaintext-secret"},
		// Armed before dispatch, so no verb documents them and every verb must
		// accept them; this is how a signed ledger is built (D102).
		{"publish", "--sign-key"},
		{"attest", "--sign-key"},
		{"export", "--trust"},
	} {
		if rc := refuseFlagsThisVerbDoesNotTake(c.verb, []string{c.flag}); rc != 0 {
			t.Errorf("%s refused %s, which it accepts — the check is now breaking "+
				"working invocations, which is worse than the bug it replaced", c.verb, c.flag)
		}
	}

	// The globals must come from the usage text, not from a second list. If the
	// workspace-context sentence stops parsing, the set collapses to presentation
	// flags and half the CLI starts refusing.
	g := globalFlagsFromUsage()
	for _, f := range []string{"--ledger", "--provider", "--project", "--region", "--actor", "--kubeconfig"} {
		if !g[f] {
			t.Errorf("global set does not contain %s — the workspace-context sentence "+
				"in the usage block stopped parsing", f)
		}
	}
	// The deliberate hole, asserted so it is a decision rather than an oversight.
	// `verify --ledger` was on D1092's list and is still accepted, because the usage
	// block declares --ledger workspace context: "just location/identity — safe
	// operator context, set once per workspace and omitted per command". A verb that
	// reads no ledger is not made to answer a different question by being told where
	// one lives, which is what separates it from --discovery: that flag carries the
	// CONTENT of the question, and dropping it is how posture came to report
	// "shadow": 0 over 169 unmanaged objects. Tightening location/identity flags to
	// the verbs that actually read them means documenting them per verb first, and
	// changing this assertion is how you would announce having done it.
	if rc := refuseFlagsThisVerbDoesNotTake("verify", []string{"--ledger"}); rc != 0 {
		t.Error("verify now refuses --ledger. That may well be right, but it is a " +
			"decision about workspace-context flags, not a detail — make it in the " +
			"usage block first, then update this assertion.")
	}

	// --at and the consent flags are emphatically NOT workspace context; the usage
	// block says so, and treating them as global would restore `hash --at`.
	for _, f := range []string{"--at", "--yes", "--allow-data-loss"} {
		if g[f] {
			t.Errorf("%s is treated as global — the usage block says it must be typed "+
				"each time, and making it global re-opens the absorption", f)
		}
	}
}

// The message has to say where the flag belongs, because "you meant another verb" is
// the likeliest truth and the operator should not have to grep for it.
func TestTheRefusalNamesTheVerbsThatDoTakeTheFlag(t *testing.T) {
	byVerb := flagsByVerb()
	takers := []string{}
	for v, fs := range byVerb {
		if fs["--heads"] {
			takers = append(takers, v)
		}
	}
	if len(takers) == 0 {
		t.Fatal("no verb documents --heads — this test's premise is gone")
	}
	if !strings.Contains(strings.Join(takers, ","), "forecast") {
		t.Errorf("--heads is documented on %v, not forecast — update this test", takers)
	}
}
