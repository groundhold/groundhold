package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestVerbHelpExtractsBlock: a per-verb --help returns just that verb's block,
// starting with its `groundhold <verb>` line.
func TestVerbHelpExtractsBlock(t *testing.T) {
	h, ok := verbHelp("preflight")
	if !ok {
		t.Fatal("preflight must have a help block")
	}
	if !strings.HasPrefix(strings.TrimSpace(h), "groundhold preflight") {
		t.Fatalf("preflight help must start with its own line, got:\n%s", h)
	}
	if strings.Contains(h, "groundhold apply") {
		t.Fatalf("preflight help must not bleed into the next verb:\n%s", h)
	}
}

func TestVerbHelpUnknownVerb(t *testing.T) {
	if _, ok := verbHelp("definitely-not-a-verb"); ok {
		t.Fatal("an unknown verb must not resolve to a help block")
	}
	if _, ok := verbHelp(""); ok {
		t.Fatal("empty verb must not resolve to a help block")
	}
}

// TestEveryGuardedVerbIsDocumented is the completeness rung: any verb the CLI
// gates (time-sensitive or provider) MUST have a usage block, or `groundhold
// <verb> --help` silently falls back to the whole usage — a self-documentation
// hole. A verb added to a guard set without a usage line fails here.
func TestEveryGuardedVerbIsDocumented(t *testing.T) {
	for v := range timeSensitiveVerbs {
		if _, ok := verbHelp(v); !ok {
			t.Errorf("time-sensitive verb %q has no usage block (--help would fall back)", v)
		}
	}
	for v := range providerVerbs {
		if _, ok := verbHelp(v); !ok {
			t.Errorf("provider verb %q has no usage block (--help would fall back)", v)
		}
	}
}

// TestHelpBypassesGuards: --help on a provider verb prints help (exit 0), never
// the fail-closed provider refusal (exit 1) — help must reach an agent before any
// guard.
func TestHelpBypassesGuards(t *testing.T) {
	t.Setenv("GROUNDHOLD_PROVIDER", "")
	if got := run([]string{"preflight", "--help"}); got != 0 {
		t.Fatalf("preflight --help = %d, want 0 (guard must not eat --help)", got)
	}
	if got := run([]string{"help", "apply"}); got != 0 {
		t.Fatalf("help apply = %d, want 0", got)
	}
	if got := run([]string{"--help"}); got != 0 {
		t.Fatalf("--help = %d, want 0 (explicit help is success)", got)
	}
}

// D505: every provider the CLI can RESOLVE must be advertised, and every provider the
// usage text names must be resolvable.
//
// Six verbs under-advertised. `adopt`, `resume` and `probe` said `fake|gcp` while
// accepting five providers, so an operator reading the help concluded that adopting an
// AWS resource was unsupported — on the one verb the external pilot demonstrably ran
// against AWS. And `observe` was the single verb whose switch had no `k8s` case at all:
// a capability could be created and retired on a cluster and never read back, which is
// the gap TestObserveCompleteness forbids INSIDE a driver, sitting at the CLI seam
// between them.
//
// What this gate does NOT do, stated because the honest limit matters: it does not
// check that each VERB advertises exactly its own resolver's set. Mapping a switch back
// to the verb that owns it is guesswork in a 4000-line dispatch, and a gate built on a
// guess is the tautology D501 deleted. It checks the union in both directions, which
// catches a provider added and never advertised, and a provider advertised and never
// wired.
func TestAdvertisedProvidersMatchTheResolvers(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(raw)

	usage := regexp.MustCompile("(?s)usage = `(.*?)`").FindStringSubmatch(src)
	if usage == nil {
		t.Fatal("usage text not found — the gate would be vacuous (D328)")
	}
	advertised := map[string]bool{}
	for _, m := range regexp.MustCompile(`--provider <?([a-z0-9|]+)>?`).
		FindAllStringSubmatch(usage[1], -1) {
		for _, p := range strings.Split(m[1], "|") {
			if len(p) > 1 { // "p" is the placeholder in `--provider <p>`
				advertised[p] = true
			}
		}
	}
	if len(advertised) < 3 {
		t.Fatalf("only %d providers parsed from the usage text — the parser broke (D328)",
			len(advertised))
	}

	// Resolvable: a case label inside any `switch providerName`/`switch name` that
	// builds a provider. Read from the source rather than a list, so a new one counts
	// the moment it is wired.
	resolvable := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?s)switch (?:providerName|name) \{(.*?)\n\t*\}`).
		FindAllStringSubmatch(src, -1) {
		for _, c := range regexp.MustCompile(`case "([a-z0-9]+)":`).
			FindAllStringSubmatch(m[1], -1) {
			resolvable[c[1]] = true
		}
	}
	if len(resolvable) < 3 {
		t.Fatalf("only %d resolvable providers found — the parser broke (D328)",
			len(resolvable))
	}

	var unadvertised, unwired []string
	for p := range resolvable {
		if !advertised[p] {
			unadvertised = append(unadvertised, p)
		}
	}
	for p := range advertised {
		if !resolvable[p] {
			unwired = append(unwired, p)
		}
	}
	sort.Strings(unadvertised)
	sort.Strings(unwired)

	if len(unadvertised) > 0 {
		t.Errorf("providers the CLI resolves but never advertises: %v — an operator "+
			"reads the help and concludes the provider is unsupported (D505)", unadvertised)
	}
	if len(unwired) > 0 {
		t.Errorf("providers the usage text names that no switch resolves: %v — the help "+
			"promises something the binary refuses", unwired)
	}
}
