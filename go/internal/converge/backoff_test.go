package converge

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// D241: a throttled apply (provider-again-later) is not a converge failure — the
// receipt concluded as `retryable` (cleared pending), so converge backs off,
// re-plans against the moved head, and re-applies. A throttle then success
// converges.
func TestConvergeBacksOffOnThrottleThenConverges(t *testing.T) {
	t.Chdir(t.TempDir()) // the plan step writes .groundhold/converge-plan.yaml
	var applyN, planN, slept int
	run := func(args ...string) (int, string, string) {
		switch args[0] {
		case "verify":
			return 0, "", ""
		case "plan":
			planN++
			if planN >= 3 { // the post-apply convergence check
				return 2, `{"code":"nothing-to-change"}`, ""
			}
			return 0, "{}", "" // initial plan (1) and the backoff re-plan (2)
		case "forecast":
			return 0, "", ""
		case "apply":
			applyN++
			if applyN == 1 {
				return 4, `{"code":"provider-again-later"}`, "throttled"
			}
			return 0, "", "applied"
		}
		return 0, "", "" // observe, etc.
	}
	var out bytes.Buffer
	o := Options{Contract: "c", Candidate: "k", At: "2026-01-01T00:00:00Z",
		Yes: true, Run: run, Out: &out,
		Sleep:       func(time.Duration) { slept++ },
		BaseBackoff: time.Millisecond, MaxApplyRetries: 4}
	exit := Converge(o)
	if exit != 0 {
		t.Fatalf("throttle then success must converge (exit 0), got %d:\n%s", exit, out.String())
	}
	if applyN != 2 {
		t.Errorf("expected 2 apply attempts (throttle + success), got %d", applyN)
	}
	if slept != 1 {
		t.Errorf("expected exactly 1 backoff sleep, got %d", slept)
	}
	if !strings.Contains(out.String(), "backing off") {
		t.Errorf("expected a backoff message, got:\n%s", out.String())
	}
}

// The backoff is BOUNDED: a persistent throttle surfaces provider-again-later
// after MaxApplyRetries rather than looping forever.
func TestConvergeThrottleIsBounded(t *testing.T) {
	t.Chdir(t.TempDir())
	var applyN, slept int
	run := func(args ...string) (int, string, string) {
		switch args[0] {
		case "verify":
			return 0, "", ""
		case "plan":
			return 0, "{}", ""
		case "forecast":
			return 0, "", ""
		case "apply":
			applyN++
			return 4, `{"code":"provider-again-later"}`, "throttled"
		}
		return 0, "", ""
	}
	var out bytes.Buffer
	o := Options{Contract: "c", Candidate: "k", At: "2026-01-01T00:00:00Z",
		Yes: true, Run: run, Out: &out,
		Sleep:       func(time.Duration) { slept++ },
		BaseBackoff: time.Millisecond, MaxApplyRetries: 2}
	exit := Converge(o)
	if exit != 4 {
		t.Fatalf("a persistent throttle must surface provider-again-later (exit 4), got %d:\n%s", exit, out.String())
	}
	if applyN != 3 { // initial + 2 retries
		t.Errorf("expected 3 apply attempts (initial + MaxApplyRetries=2), got %d", applyN)
	}
	if slept != 2 {
		t.Errorf("expected 2 backoff sleeps, got %d", slept)
	}
}

// D243: converge honors the provider's Retry-After hint (from the apply result)
// as the backoff delay, instead of a blind exponential — and caps it so a huge
// hint cannot stall converge unbounded.
func TestConvergeHonorsRetryAfter(t *testing.T) {
	t.Chdir(t.TempDir())
	var applyN, planN int
	var slept []time.Duration
	run := func(args ...string) (int, string, string) {
		switch args[0] {
		case "verify":
			return 0, "", ""
		case "plan":
			planN++
			if planN >= 3 {
				return 2, `{"code":"nothing-to-change"}`, ""
			}
			return 0, "{}", ""
		case "forecast":
			return 0, "", ""
		case "apply":
			applyN++
			if applyN == 1 {
				return 4, `{"code":"provider-again-later","retryAfterSeconds":7}`, "throttled"
			}
			return 0, "", "applied"
		}
		return 0, "", ""
	}
	var out bytes.Buffer
	o := Options{Contract: "c", Candidate: "k", At: "2026-01-01T00:00:00Z",
		Yes: true, Run: run, Out: &out,
		Sleep:       func(d time.Duration) { slept = append(slept, d) },
		BaseBackoff: time.Second, MaxBackoff: 30 * time.Second, MaxApplyRetries: 4}
	if exit := Converge(o); exit != 0 {
		t.Fatalf("throttle-with-hint then success must converge, got %d:\n%s", exit, out.String())
	}
	if len(slept) != 1 || slept[0] != 7*time.Second {
		t.Fatalf("must honor Retry-After (7s), slept=%v", slept)
	}
	if !strings.Contains(out.String(), "honoring Retry-After") {
		t.Errorf("say must note honoring Retry-After, got:\n%s", out.String())
	}
}

// A hostile/huge Retry-After is capped at MaxBackoff (never stalls unbounded).
func TestConvergeCapsRetryAfter(t *testing.T) {
	t.Chdir(t.TempDir())
	var applyN, planN int
	var slept []time.Duration
	run := func(args ...string) (int, string, string) {
		switch args[0] {
		case "plan":
			planN++
			if planN >= 3 {
				return 2, `{"code":"nothing-to-change"}`, ""
			}
			return 0, "{}", ""
		case "apply":
			applyN++
			if applyN == 1 {
				return 4, `{"code":"provider-again-later","retryAfterSeconds":99999}`, "throttled"
			}
			return 0, "", ""
		}
		return 0, "", "" // verify, forecast, observe
	}
	var out bytes.Buffer
	o := Options{Contract: "c", Candidate: "k", At: "2026-01-01T00:00:00Z",
		Yes: true, Run: run, Out: &out,
		Sleep:       func(d time.Duration) { slept = append(slept, d) },
		BaseBackoff: time.Second, MaxBackoff: 5 * time.Second, MaxApplyRetries: 4}
	Converge(o)
	if len(slept) != 1 || slept[0] != 5*time.Second {
		t.Fatalf("a huge Retry-After must be capped at MaxBackoff (5s), slept=%v", slept)
	}
}
