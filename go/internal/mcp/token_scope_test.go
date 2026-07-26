package mcp

import (
	"strings"
	"testing"
	"time"
)

// D319 (adversarial audit of the MCP boundary): the confirmation token pins the
// PLAN but not the TARGET, so a confirmed apply can be redirected.
//
// The two-step exists so the second call re-executes exactly the reviewed
// decision. It pins `hash(plan)` — and nothing else. But the argv apply actually
// runs is (plan, contract, candidate, LEDGER, PROVIDER, at), and the
// confirmation payload shows only the plan text. So an agent can request
// confirmation for applying plan P against one ledger/provider and spend that
// token applying the identical plan against a DIFFERENT ledger or a different
// provider — writing bindings into a ledger nobody reviewed.
//
// The package is honest that the token does not authenticate a human. This is a
// narrower claim: whatever it does pin should cover the decision it displays.
func TestConfirmTokenCannotBeSpentOnADifferentTarget(t *testing.T) {
	var applied []string
	run := func(args ...string) (int, string, string) {
		if args[0] == "hash" {
			return 0, "sha256:planhash\n", ""
		}
		applied = append(applied, strings.Join(args, " "))
		return 0, `{"status":"ok"}`, ""
	}
	s := &Server{run: run, allowApply: true, tokens: map[string]token{},
		now: func() time.Time { return time.Unix(1000, 0) }}

	// step 1: confirmation for a plan targeted at ledger A, provider gcp
	first := s.apply(map[string]any{
		"plan": "plan.json", "contract": "c.yaml", "candidate": "cand.yaml",
		"ledger": "ledger-A.jsonl", "provider": "gcp"})
	if first["status"] != "confirmation_required" {
		t.Fatalf("expected confirmation_required, got %v", first)
	}
	tok, _ := first["confirm_token"].(string)
	if tok == "" {
		t.Fatal("no confirm_token issued")
	}

	// step 2: the SAME plan, spent against a different ledger and provider
	second := s.apply(map[string]any{
		"plan": "plan.json", "contract": "c.yaml", "candidate": "cand.yaml",
		"ledger": "ledger-B.jsonl", "provider": "aws", "confirm_token": tok})

	if second["status"] == "ok" {
		t.Fatalf("a token confirmed for ledger-A/gcp was spent on ledger-B/aws — "+
			"the confirmation displays the plan but the decision includes its "+
			"target.\nargv: %v", applied)
	}
	if len(applied) > 0 {
		t.Errorf("apply ran despite the redirected target: %v", applied)
	}
}

// The same token must still work for the target it was issued for — the fix must
// pin the decision, not break the feature.
func TestConfirmTokenStillWorksForTheSameTarget(t *testing.T) {
	var applied []string
	run := func(args ...string) (int, string, string) {
		if args[0] == "hash" {
			return 0, "sha256:planhash\n", ""
		}
		applied = append(applied, strings.Join(args, " "))
		return 0, `{"status":"ok"}`, ""
	}
	s := &Server{run: run, allowApply: true, tokens: map[string]token{},
		now: func() time.Time { return time.Unix(1000, 0) }}

	args := map[string]any{
		"plan": "plan.json", "contract": "c.yaml", "candidate": "cand.yaml",
		"ledger": "ledger-A.jsonl", "provider": "gcp"}
	first := s.apply(args)
	tok, _ := first["confirm_token"].(string)
	if tok == "" {
		t.Fatal("no confirm_token issued")
	}
	second := map[string]any{}
	for k, v := range args {
		second[k] = v
	}
	second["confirm_token"] = tok
	if got := s.apply(second); got["status"] != "ok" {
		t.Fatalf("the confirmed target must still apply: %v", got)
	}
	if len(applied) != 1 {
		t.Fatalf("expected exactly one apply, got %v", applied)
	}
}

// D319: expired tokens were only removed on redemption, so a long-lived server
// accumulated one per confirmation forever. Issuing a confirmation now sweeps.
func TestExpiredTokensAreSwept(t *testing.T) {
	now := time.Unix(1000, 0)
	run := func(args ...string) (int, string, string) {
		return 0, "sha256:planhash\n", ""
	}
	s := &Server{run: run, allowApply: true, tokens: map[string]token{},
		now: func() time.Time { return now }}

	for i := 0; i < 5; i++ {
		s.apply(map[string]any{"plan": "plan.json", "ledger": "l"})
	}
	if len(s.tokens) != 5 {
		t.Fatalf("expected 5 live tokens, got %d", len(s.tokens))
	}
	now = now.Add(10 * time.Minute) // every one is now expired
	s.apply(map[string]any{"plan": "plan.json", "ledger": "l"})
	if len(s.tokens) != 1 {
		t.Errorf("issuing a confirmation must sweep expired tokens; %d remain", len(s.tokens))
	}
}
