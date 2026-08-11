package main

import (
	"regexp"
	"strings"
	"testing"

	"groundhold/internal/posture"
)

// D569. Posture hands the operator a recipe per class — that is its whole value over
// a plain report. Following the shadow recipe verbatim on a live cluster:
//
//	step 1  groundhold discover --provider <p> --region <scope> --at <ts>   ->  worked
//	step 2  groundhold adopt <contract> <candidate> --map ... --ledger <l> --at <ts>
//	        ->  "adopt requires an explicit --provider" ... INVALID
//
// `adopt` is in `providerVerbs`, the CLOSED set of verbs that must refuse a defaulted
// fake driver (F4). The recipe omits the flag — and step 1 of the SAME recipe
// includes it, so the two lines disagree with each other about the same tool.
//
// This is D568's lesson one step on: there the recipe worked but its result was
// invisible; here the recipe does not run. Advice is a published claim, and this one
// was never executed by anyone before an operator would be.
//
// The gate is derived, not restated: every command in every posture recipe is checked
// against `providerVerbs` — the CLI's own set — so a verb added there later cannot
// leave a stale recipe behind (D550).
func TestPostureRecipesAreRunnable(t *testing.T) {
	verb := regexp.MustCompile(`^groundhold ([a-z-]+)`)
	seen := 0
	for _, in := range []posture.Input{
		{At: "t", Bindings: map[string]string{"c": "p"}, Verdict: map[string]string{},
			Deposed: map[string]bool{}, Decayed: map[string]bool{}},
		{At: "t", Bindings: map[string]string{"c": "p"}, Verdict: map[string]string{"c": "violated"},
			Deposed: map[string]bool{}, Decayed: map[string]bool{}},
		{At: "t", Bindings: map[string]string{"c": "p"}, Verdict: map[string]string{"c": "unverifiable"},
			Deposed: map[string]bool{}, Decayed: map[string]bool{}},
		{At: "t", Bindings: map[string]string{"c": "p"}, Verdict: map[string]string{},
			Deposed: map[string]bool{}, Decayed: map[string]bool{"c": true}},
		{At: "t", Bindings: map[string]string{}, Verdict: map[string]string{},
			Deposed: map[string]bool{}, Decayed: map[string]bool{},
			Discovered: []posture.Discovered{{ProviderID: "core/v1/ResourceQuota/default/q",
				Scope: "default", ScopeComplete: true}}},
	} {
		for _, row := range posture.Classify(in).Rows {
			for _, step := range row.Remediation.Steps {
				m := verb.FindStringSubmatch(step)
				if m == nil {
					continue // a prose step ("edit the contract...") is not a command
				}
				seen++
				if providerVerbs[m[1]] && !strings.Contains(step, "--provider") {
					t.Errorf("the %s recipe tells the operator to run a provider verb "+
						"without --provider, which refuses before doing anything:\n  %s\n"+
						"%q is in providerVerbs (F4: fake must never be a silent default), "+
						"so this step cannot run as written.", row.Class, step, m[1])
				}
			}
		}
	}
	if seen < 5 {
		t.Fatalf("only %d recipe commands examined — this gate would be near-vacuous", seen)
	}
}
