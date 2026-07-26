package pace

import (
	"testing"
	"time"
)

// D321 (adversarial audit of the gentle crawl): a Policy with a non-positive Rate
// silently disables the rate limit entirely.
//
// waitToken only sleeps when `b.tokens < 1 && s.pol.Rate > 0`. With Rate == 0 the
// second clause is false, so no wait is ever taken, the bucket goes negative and
// keeps going — the scheduler issues calls as fast as the caller can loop. This is
// the exact failure the package exists to prevent ("the anti-DoS policy in ONE
// place"), reached by leaving one field unset.
//
// The CLI never does this (it starts from DefaultPolicy and only overrides
// Budget), so this is a library fail-open rather than a live incident. But a
// safety component that does nothing when partially configured is the shape this
// repo refuses everywhere else: a safety clock fails closed, an unpredictable
// token is not issued. Gentleness must not be optional.
func TestNonPositiveRateStillPaces(t *testing.T) {
	for _, rate := range []float64{0, -1} {
		now := time.Unix(0, 0)
		slept := time.Duration(0)
		clk := Clock{
			Now:    func() time.Time { return now },
			Sleep:  func(d time.Duration) { slept += d; now = now.Add(d) },
			Jitter: func() float64 { return 0 },
		}
		// everything else sane — only Rate is unset
		s := New(Policy{Rate: rate, Burst: 2, BackoffBase: time.Second,
			BackoffCap: time.Minute, MaxAttempts: 3, BreakerTrips: 3, Budget: 100}, clk)

		for i := 0; i < 20; i++ {
			if _, err := s.Do("aws", func() Result { return Result{Outcome: OK} }); err != nil {
				t.Fatalf("rate=%v call %d: %v", rate, i, err)
			}
		}
		if slept == 0 {
			t.Errorf("rate=%v: 20 calls issued with ZERO pacing — a non-positive "+
				"Rate disabled the token bucket entirely", rate)
		}
	}
}

// The floor must not slow down a policy that is already explicit: a caller asking
// for a fast-but-declared rate keeps it.
func TestExplicitRateIsRespected(t *testing.T) {
	now := time.Unix(0, 0)
	slept := time.Duration(0)
	clk := Clock{
		Now:    func() time.Time { return now },
		Sleep:  func(d time.Duration) { slept += d; now = now.Add(d) },
		Jitter: func() float64 { return 0 },
	}
	s := New(Policy{Rate: 100, Burst: 1, BackoffBase: time.Second,
		BackoffCap: time.Minute, MaxAttempts: 3, BreakerTrips: 3, Budget: 100}, clk)
	for i := 0; i < 10; i++ {
		if _, err := s.Do("aws", func() Result { return Result{Outcome: OK} }); err != nil {
			t.Fatal(err)
		}
	}
	// 100/s over 10 calls with burst 1 is ~90ms of waiting, not seconds
	if slept > time.Second {
		t.Errorf("an explicit fast rate was slowed to %v — the floor must only "+
			"apply to an UNSET rate", slept)
	}
}
