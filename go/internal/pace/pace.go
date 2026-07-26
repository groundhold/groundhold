// Package pace is the gentle crawl scheduler (D141). It is the anti-DoS policy in
// ONE place: a per-provider token bucket for steady rate, exponential backoff with
// full jitter on 429/5xx (an explicit Retry-After always wins), zero retries on
// 401/403 (a pairing problem, refused loudly — never hammered), a per-provider
// circuit breaker, and a global request budget. The clock is INJECTED, so every
// wait is virtual in tests: the scheduler is deterministically testable without
// wall-clock or network, and it sits entirely outside the verifier (#6). It does no
// I/O itself — the caller's fn does the one request and reports an Outcome.
package pace

import (
	"errors"
	"fmt"
	"time"
)

// Outcome classifies one provider call for the pacer.
type Outcome int

const (
	OK          Outcome = iota // 2xx
	Throttled                  // 429 — back off, retry
	ServerError                // 5xx — back off, retry
	AuthError                  // 401/403 — a pairing problem, never retried
)

// Result is what a paced call reports back. RetryAfter, when > 0, is the
// provider's explicit ask and is honored verbatim over the computed backoff.
type Result struct {
	Outcome    Outcome
	RetryAfter time.Duration
}

// Policy is the per-crawl gentleness configuration.
type Policy struct {
	Rate         float64       // steady request rate per provider (tokens/second)
	Burst        int           // token-bucket capacity
	BackoffBase  time.Duration // first backoff step
	BackoffCap   time.Duration // maximum backoff step
	MaxAttempts  int           // attempts per call, including the first
	BreakerTrips int           // consecutive provider failures that trip the breaker
	Budget       int           // global hard cap on requests made this crawl
}

// DefaultPolicy is deliberately conservative: 1 req/s, small burst, minute-capped
// backoff, a breaker at 3, and a bounded budget — gentle by default.
func DefaultPolicy() Policy {
	return Policy{
		Rate: 1, Burst: 5,
		BackoffBase: time.Second, BackoffCap: 5 * time.Minute,
		MaxAttempts: 5, BreakerTrips: 3, Budget: 2000,
	}
}

// Clock is the injected time source. Real: Now=time.Now, Sleep=time.Sleep. Tests
// supply a virtual clock whose Sleep advances Now, so waits are exact and instant.
type Clock struct {
	Now    func() time.Time
	Sleep  func(time.Duration)
	Jitter func() float64 // full-jitter multiplier in [0,1)
}

// Sentinel errors let the crawl mark a scope incomplete with a precise reason.
var (
	ErrBudget    = errors.New("crawl request budget exhausted")
	ErrBroken    = errors.New("provider circuit breaker open")
	ErrAuth      = errors.New("provider auth refused")
	ErrExhausted = errors.New("retries exhausted")
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Scheduler paces calls under a Policy. Not safe for concurrent use — a crawl runs
// one provider call at a time by design (the strongest anti-DoS statement).
type Scheduler struct {
	pol     Policy
	clk     Clock
	spent   int
	buckets map[string]*bucket
	fails   map[string]int
	broken  map[string]bool

	Made      int // requests actually issued
	Throttles int // 429s seen
	Backoffs  int // backoff waits taken
	// Floored (D321) names the Policy fields that were non-positive and fell back
	// to the DefaultPolicy value — so a caller that under-specified the gentleness
	// learns it was applied anyway rather than silently getting none.
	Floored []string
}

// New builds a scheduler. Any field left non-positive falls back to the
// DefaultPolicy value and is NAMED in Floored — gentleness is not optional (D321).
//
// The bug this closes: waitToken only waits when `Rate > 0`, so a Policy with Rate
// unset disabled the token bucket entirely and the scheduler issued calls as fast
// as the caller could loop — the exact behaviour this package exists to prevent,
// reached by leaving one field zero. A safety component that does nothing when
// partially configured is the shape refused everywhere else here (a safety clock
// fails closed; an unpredictable token is not issued). Substitution is silent to
// the CALL PATH but not to the operator: Floored is surfaced in the crawl's
// honesty block, so "we paced you at the default" is stated, never assumed.
func New(pol Policy, clk Clock) *Scheduler {
	def := DefaultPolicy()
	var floored []string
	if pol.Rate <= 0 {
		pol.Rate, floored = def.Rate, append(floored, "rate")
	}
	if pol.Burst <= 0 {
		pol.Burst, floored = def.Burst, append(floored, "burst")
	}
	if pol.BackoffBase <= 0 {
		pol.BackoffBase, floored = def.BackoffBase, append(floored, "backoffBase")
	}
	if pol.BackoffCap <= 0 {
		pol.BackoffCap, floored = def.BackoffCap, append(floored, "backoffCap")
	}
	if pol.MaxAttempts <= 0 {
		pol.MaxAttempts, floored = def.MaxAttempts, append(floored, "maxAttempts")
	}
	if pol.BreakerTrips <= 0 {
		pol.BreakerTrips, floored = def.BreakerTrips, append(floored, "breakerTrips")
	}
	if pol.Budget <= 0 {
		pol.Budget, floored = def.Budget, append(floored, "budget")
	}
	return &Scheduler{pol: pol, clk: clk, Floored: floored,
		buckets: map[string]*bucket{}, fails: map[string]int{}, broken: map[string]bool{}}
}

// Policy returns the EFFECTIVE policy after flooring — what the provider was
// actually subjected to, not what the caller asked for.
func (s *Scheduler) Policy() Policy { return s.pol }

// Spent is the number of requests issued so far (for the honesty block).
func (s *Scheduler) Spent() int { return s.spent }

// Do runs one paced call to provider. It waits for a rate token, invokes fn, and on
// Throttled/ServerError retries with backoff (Retry-After wins) up to MaxAttempts;
// AuthError never retries; an already-broken provider refuses immediately; the
// global budget refuses when exhausted. The returned error is one of the sentinels.
func (s *Scheduler) Do(provider string, fn func() Result) (Result, error) {
	if s.broken[provider] {
		return Result{}, fmt.Errorf("%w: %s", ErrBroken, provider)
	}
	var last Result
	for attempt := 0; attempt < s.pol.MaxAttempts; attempt++ {
		if s.spent >= s.pol.Budget {
			return Result{}, fmt.Errorf("%w: %s", ErrBudget, provider)
		}
		if attempt > 0 {
			s.backoff(attempt-1, last.RetryAfter)
		}
		s.waitToken(provider)
		s.spent++
		s.Made++
		last = fn()
		switch last.Outcome {
		case OK:
			s.fails[provider] = 0
			return last, nil
		case AuthError:
			return last, fmt.Errorf("%w: %s (401/403 — fix the pairing, not retried)", ErrAuth, provider)
		case Throttled:
			s.Throttles++
		}
		s.fails[provider]++
		if s.fails[provider] >= s.pol.BreakerTrips {
			s.broken[provider] = true
			return last, fmt.Errorf("%w: %s (%d consecutive failures)", ErrBroken, provider, s.fails[provider])
		}
	}
	return last, fmt.Errorf("%w: %s (%d attempts)", ErrExhausted, provider, s.pol.MaxAttempts)
}

// waitToken blocks (virtually) until the provider's bucket has a token, then spends it.
func (s *Scheduler) waitToken(provider string) {
	b := s.buckets[provider]
	now := s.clk.Now()
	if b == nil {
		b = &bucket{tokens: float64(s.pol.Burst), last: now}
		s.buckets[provider] = b
	}
	s.refill(b, now)
	if b.tokens < 1 { // Rate is guaranteed positive by New (D321)
		need := (1 - b.tokens) / s.pol.Rate
		s.clk.Sleep(time.Duration(need * float64(time.Second)))
		s.refill(b, s.clk.Now())
	}
	b.tokens -= 1
}

func (s *Scheduler) refill(b *bucket, now time.Time) {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * s.pol.Rate
		if b.tokens > float64(s.pol.Burst) {
			b.tokens = float64(s.pol.Burst)
		}
		b.last = now
	}
}

// backoff waits before a retry: Retry-After verbatim when given, else full-jitter
// exponential (sleep in [0, base*2^attempt), capped).
func (s *Scheduler) backoff(attempt int, retryAfter time.Duration) {
	s.Backoffs++
	if retryAfter > 0 {
		s.clk.Sleep(retryAfter)
		return
	}
	step := s.pol.BackoffBase * (1 << uint(attempt))
	if step <= 0 || step > s.pol.BackoffCap {
		step = s.pol.BackoffCap
	}
	s.clk.Sleep(time.Duration(s.clk.Jitter() * float64(step)))
}
