package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// concImpl is a minimal valid lambda create impl with a declared reserved_concurrency.
func concImpl(rc any) map[string]any {
	m := map[string]any{
		"image_uri": "000000000000.dkr.ecr.eu-central-1.amazonaws.com/fn:latest",
		"role_arn":  "arn:aws:iam::000000000000:role/fn-exec",
	}
	if rc != nil {
		m["reserved_concurrency"] = rc
	}
	return m
}

// TestLambdaReservedConcurrencyOperand pins reserved_concurrency end to end on the pure
// paths: it is read into the plan, it classifies as an in-place secondary patch (never a
// replacement), and it is DECLARED-ONLY in OperandTargets (an adopted function's live
// reservation must not drift to "unset" because the contract is silent).
func TestLambdaReservedConcurrencyOperand(t *testing.T) {
	p, err := BuildLambda("000000000000", "prod", "api", memAttrs(), concImpl(50), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.ReservedConcurrencySet || p.ReservedConcurrency != 50 {
		t.Fatalf("reserved_concurrency not read: set=%v val=%d", p.ReservedConcurrencySet, p.ReservedConcurrency)
	}
	if class, _ := classifyLambdaChange(lambdaConcOperand); class != "mutable" {
		t.Fatalf("a reserved_concurrency change must be an in-place patch, got %q", class)
	}
	// declared-only target
	targets, err := (&Driver{}).OperandTargets("lambda", memAttrs(), concImpl(50))
	if err != nil {
		t.Fatal(err)
	}
	var found string
	for _, tg := range targets {
		if tg.Path == lambdaConcOperand {
			found, _ = tg.Desired.(string)
		}
	}
	if found != "50" {
		t.Fatalf("a declared reserved_concurrency must yield a target, got %q", found)
	}
	silent, _ := (&Driver{}).OperandTargets("lambda", memAttrs(), concImpl(nil))
	for _, tg := range silent {
		if tg.Path == lambdaConcOperand {
			t.Fatalf("a silent contract must NOT emit a concurrency target, got %v", tg.Desired)
		}
	}
	// 0 is a VALID reservation (throttle to zero), distinct from absent.
	p0, err := BuildLambda("000000000000", "prod", "api", memAttrs(), concImpl(0), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p0.ReservedConcurrencySet || p0.ReservedConcurrency != 0 {
		t.Fatal("reserved_concurrency 0 must be a declared reservation (throttle to zero), not absent")
	}
}

// TestLambdaReservedConcurrencyRefused: a negative reservation is refused in preflight
// (its floor is 0), and a non-integer is refused rather than silently defaulted.
func TestLambdaReservedConcurrencyRefused(t *testing.T) {
	if _, err := BuildLambda("000000000000", "prod", "api", memAttrs(), concImpl(-1), 1); err == nil {
		t.Error("a negative reserved_concurrency must refuse in preflight")
	}
	if _, err := BuildLambda("000000000000", "prod", "api", memAttrs(), concImpl("many"), 1); err == nil {
		t.Error("a non-integer reserved_concurrency must refuse")
	}
}

// TestObserveLambdaReservedConcurrency pins the observe side: the reservation is read
// from its OWN endpoint (GetFunctionConcurrency) and rendered exactly as OperandTargets
// renders the declared value, so a drift is comparable like-for-like.
func TestObserveLambdaReservedConcurrency(t *testing.T) {
	d, done := operandDriver(t, "ok")
	defer done()
	obs, _, err := d.observeLambda("api", operandPID)
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, o := range obs {
		if o.Path == lambdaConcOperand {
			got, _ = o.Value.(string)
		}
	}
	if got != "50" {
		t.Fatalf("observe must read reserved concurrency from its own endpoint, got %q", got)
	}
	targets, _ := d.OperandTargets("lambda", memAttrs(), concImpl(50))
	var desired string
	for _, tg := range targets {
		if tg.Path == lambdaConcOperand {
			desired, _ = tg.Desired.(string)
		}
	}
	if desired != got {
		t.Fatalf("declared 50 must match observed 50 byte-for-byte: desired %q observed %q", desired, got)
	}
}

// TestEnsureLambdaConcurrencyReconciles pins the secondary-call reconcile: it reads the
// live reservation first, PUTs only when the declared ceiling differs, and issues NO call
// when it already matches (idempotent). It also captures/verifies the PutFunctionConcurrency
// route. A non-declared plan is a no-op (declared-only).
func TestEnsureLambdaConcurrencyReconciles(t *testing.T) {
	var puts int
	var lastBody string
	live := 30
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/concurrency"):
			_ = json.NewEncoder(w).Encode(map[string]any{"ReservedConcurrentExecutions": live})
		case r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/concurrency"):
			puts++
			b, _ := io.ReadAll(r.Body)
			lastBody = string(b)
			_ = json.NewEncoder(w).Encode(map[string]any{"ReservedConcurrentExecutions": 50})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	d := NewDriver("eu-central-1")
	d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	d.Account = "000000000000"
	d.LambdaBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond

	// declared 50, live 30 -> one PUT carrying 50
	plan, _ := BuildLambda("000000000000", "prod", "api", memAttrs(), concImpl(50), 1)
	if r := d.ensureLambdaConcurrency("eu-central-1", operandPID, "apifn", plan); r != nil {
		t.Fatalf("reconcile should succeed, got %+v", r)
	}
	if puts != 1 || !strings.Contains(lastBody, "50") {
		t.Fatalf("declared 50 over live 30 must PUT once with 50: puts=%d body=%q", puts, lastBody)
	}

	// declared == live -> NO put (idempotent)
	puts = 0
	live = 50
	plan2, _ := BuildLambda("000000000000", "prod", "api", memAttrs(), concImpl(50), 1)
	if r := d.ensureLambdaConcurrency("eu-central-1", operandPID, "apifn", plan2); r != nil {
		t.Fatal(r)
	}
	if puts != 0 {
		t.Fatalf("a reservation already at the declared ceiling must issue no PUT, got %d", puts)
	}

	// not declared -> no-op, no read, no put
	puts = 0
	planNone, _ := BuildLambda("000000000000", "prod", "api", memAttrs(), concImpl(nil), 1)
	if r := d.ensureLambdaConcurrency("eu-central-1", operandPID, "apifn", planNone); r != nil {
		t.Fatal(r)
	}
	if puts != 0 {
		t.Fatal("a silent contract must not touch concurrency")
	}
}
