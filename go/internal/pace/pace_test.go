package pace

import (
	"errors"
	"testing"
	"time"
)

// vclock is a virtual clock: Sleep advances Now, so paced waits are exact and
// instantaneous, and the test asserts the precise wait sequence.
type vclock struct {
	t      time.Time
	sleeps []time.Duration
	jitter float64
}

func (v *vclock) clock() Clock {
	return Clock{
		Now:    func() time.Time { return v.t },
		Sleep:  func(d time.Duration) { v.t = v.t.Add(d); v.sleeps = append(v.sleeps, d) },
		Jitter: func() float64 { return v.jitter },
	}
}

func testPolicy() Policy {
	return Policy{Rate: 1, Burst: 1, BackoffBase: time.Second, BackoffCap: time.Minute,
		MaxAttempts: 5, BreakerTrips: 3, Budget: 100}
}

func TestOKFirstTryNoWait(t *testing.T) {
	v := &vclock{t: time.Unix(0, 0)}
	s := New(testPolicy(), v.clock())
	r, err := s.Do("fake", func() Result { return Result{Outcome: OK} })
	if err != nil || r.Outcome != OK {
		t.Fatalf("r=%v err=%v", r, err)
	}
	if len(v.sleeps) != 0 || s.Spent() != 1 {
		t.Fatalf("no wait expected, sleeps=%v spent=%d", v.sleeps, s.Spent())
	}
}

func TestRetryAfterWinsOverBackoff(t *testing.T) {
	v := &vclock{t: time.Unix(0, 0), jitter: 0.5}
	s := New(testPolicy(), v.clock())
	n := 0
	r, err := s.Do("fake", func() Result {
		n++
		if n == 1 {
			return Result{Outcome: Throttled, RetryAfter: 2 * time.Second}
		}
		return Result{Outcome: OK}
	})
	if err != nil || r.Outcome != OK {
		t.Fatalf("r=%v err=%v", r, err)
	}
	// the backoff must be exactly the Retry-After, not the jittered computed value
	if len(v.sleeps) != 1 || v.sleeps[0] != 2*time.Second {
		t.Fatalf("Retry-After must win, sleeps=%v", v.sleeps)
	}
	if s.Throttles != 1 || s.Backoffs != 1 {
		t.Fatalf("stats: throttles=%d backoffs=%d", s.Throttles, s.Backoffs)
	}
}

func TestFullJitterBackoffSequence(t *testing.T) {
	v := &vclock{t: time.Unix(0, 0), jitter: 0.5}
	// generous burst so the token bucket never blocks — this isolates backoff waits
	pol := testPolicy()
	pol.Burst = 10
	s := New(pol, v.clock())
	n := 0
	_, err := s.Do("fake", func() Result {
		n++
		if n <= 2 {
			return Result{Outcome: ServerError}
		}
		return Result{Outcome: OK}
	})
	if err != nil {
		t.Fatal(err)
	}
	// attempt 0 fails -> backoff base*2^0=1s * jitter 0.5 = 500ms
	// attempt 1 fails -> backoff base*2^1=2s * jitter 0.5 = 1s
	want := []time.Duration{500 * time.Millisecond, time.Second}
	if len(v.sleeps) != 2 || v.sleeps[0] != want[0] || v.sleeps[1] != want[1] {
		t.Fatalf("backoff sequence = %v, want %v", v.sleeps, want)
	}
}

func TestAuthErrorNeverRetries(t *testing.T) {
	v := &vclock{t: time.Unix(0, 0)}
	s := New(testPolicy(), v.clock())
	n := 0
	_, err := s.Do("fake", func() Result { n++; return Result{Outcome: AuthError} })
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
	if n != 1 || len(v.sleeps) != 0 {
		t.Fatalf("auth error must not retry or wait: calls=%d sleeps=%v", n, v.sleeps)
	}
}

func TestGlobalBudgetRefuses(t *testing.T) {
	pol := testPolicy()
	pol.Budget = 2
	v := &vclock{t: time.Unix(0, 0)}
	s := New(pol, v.clock())
	for i := 0; i < 2; i++ {
		if _, err := s.Do("fake", func() Result { return Result{Outcome: OK} }); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if _, err := s.Do("fake", func() Result { return Result{Outcome: OK} }); !errors.Is(err, ErrBudget) {
		t.Fatalf("want ErrBudget after the budget, got %v", err)
	}
}

func TestCircuitBreakerTripsAndStaysOpen(t *testing.T) {
	v := &vclock{t: time.Unix(0, 0), jitter: 0}
	s := New(testPolicy(), v.clock())
	// three consecutive server errors trip the breaker (BreakerTrips=3)
	_, err := s.Do("fake", func() Result { return Result{Outcome: ServerError} })
	if !errors.Is(err, ErrBroken) {
		t.Fatalf("breaker must trip on 3 failures, got %v", err)
	}
	// a broken provider refuses immediately, no request issued
	before := s.Made
	_, err = s.Do("fake", func() Result { return Result{Outcome: OK} })
	if !errors.Is(err, ErrBroken) || s.Made != before {
		t.Fatalf("broken provider must refuse without a request: err=%v made delta=%d", err, s.Made-before)
	}
}

func TestTokenBucketPacesSecondCall(t *testing.T) {
	pol := testPolicy() // Rate 1/s, Burst 1
	v := &vclock{t: time.Unix(0, 0)}
	s := New(pol, v.clock())
	// first call spends the single burst token, no wait
	_, _ = s.Do("fake", func() Result { return Result{Outcome: OK} })
	if len(v.sleeps) != 0 {
		t.Fatalf("first call must not wait, sleeps=%v", v.sleeps)
	}
	// second call must wait ~1s for a token to refill at 1/s
	_, _ = s.Do("fake", func() Result { return Result{Outcome: OK} })
	if len(v.sleeps) != 1 || v.sleeps[0] != time.Second {
		t.Fatalf("second call must wait 1s for a token, sleeps=%v", v.sleeps)
	}
}

func TestPerProviderBucketsAreIndependent(t *testing.T) {
	v := &vclock{t: time.Unix(0, 0)}
	s := New(testPolicy(), v.clock())
	// two different providers each get their own burst token — no cross-throttle
	_, _ = s.Do("a", func() Result { return Result{Outcome: OK} })
	_, _ = s.Do("b", func() Result { return Result{Outcome: OK} })
	if len(v.sleeps) != 0 {
		t.Fatalf("independent providers must not throttle each other, sleeps=%v", v.sleeps)
	}
}
