package main

import (
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
