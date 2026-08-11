package main

import (
	"sort"
	"strings"
	"testing"
)

// TestProviderVerbsMembership pins the EXACT set of verbs the F4 fail-closed guard
// gates — the verbs that OBSERVE or MUTATE real infrastructure through a provider
// driver. A verb dropped from this set silently regains the footgun (a real run
// against the FAKE provider by default); a new provider verb added without gating
// is the same hole. This test forces either change to be a deliberate edit.
func TestProviderVerbsMembership(t *testing.T) {
	// D571: `anchor` and `repair` LEFT this set, deliberately. They are pure ledger
	// operations — runAnchor(ledgerPath, checkPath) and runRepair(ledgerPath,
	// quarantine, fingerprint, explain) take no provider and their bodies name no
	// driver — so there is no fake-default footgun to guard, and demanding
	// --provider on the two verbs used when a ledger is damaged claimed they contact
	// a cloud they never touch. This gate did its job: it refused the edit until it
	// was justified here.
	want := []string{
		"adopt", "apply", "converge", "crawl", "discover",
		"observe", "preflight", "probe", "react", "refresh", "resume",
	}
	got := make([]string, 0, len(providerVerbs))
	for v, on := range providerVerbs {
		if on {
			got = append(got, v)
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("providerVerbs drifted WITHOUT updating this test — if deliberate,\n"+
			"update `want` and confirm the verb's fake-default refusal; if not, a\n"+
			"real-infra-against-fake hole just opened.\n  want: %v\n  got:  %v", want, got)
	}
}

// TestProviderGuardFailsClosed exercises the guard through run(): a provider verb
// with no explicit provider refuses (would default to fake), a typo'd provider is
// an error, and an explicit provider passes the guard.
func TestProviderGuardFailsClosed(t *testing.T) {
	at := "2026-07-21T00:00:00Z"
	cases := []struct {
		name string
		args []string
		want int // 1 => refused by the guard
	}{
		{"defaulted fake refused", []string{"observe", "--at", at}, 1},
		{"unknown provider refused", []string{"observe", "--provider", "awss", "--at", at}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GROUNDHOLD_PROVIDER", "") // no ambient provider
			if got := run(tc.args); got != tc.want {
				t.Fatalf("run(%v) = %d, want %d", tc.args, got, tc.want)
			}
		})
	}
}

// TestKnownProvidersClosed is a floor guard: the set must be non-empty and clean,
// or the typo check would accept anything (or nothing).
func TestKnownProvidersClosed(t *testing.T) {
	if len(knownProviders) == 0 {
		t.Fatal("knownProviders is empty — the typo guard would reject every provider")
	}
	for _, must := range []string{"aws", "gcp", "azure", "fake"} {
		if !knownProviders[must] {
			t.Errorf("knownProviders is missing %q", must)
		}
	}
}
