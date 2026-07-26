package provider

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestClassifyTable(t *testing.T) {
	transport := errors.New("connection reset")
	cases := []struct {
		name   string
		status int
		code   string
		terr   error
		want   ErrorClass
	}{
		// transport + success
		{"transport error", 0, "", transport, ClassAmbiguous},
		{"transport beats status", 500, "InternalError", transport, ClassAmbiguous},
		{"200 ok", 200, "", nil, ClassOK},
		{"201 ok", 201, "", nil, ClassOK},
		{"204 ok", 204, "", nil, ClassOK},

		// status ladder (no code)
		{"429 throttle", 429, "", nil, ClassTransient},
		{"408 timeout", 408, "", nil, ClassTransient},
		{"401 unauth", 401, "", nil, ClassDenied},
		{"403 forbidden", 403, "", nil, ClassDenied},
		{"500 server", 500, "", nil, ClassAmbiguous},
		{"502 server", 502, "", nil, ClassAmbiguous},
		{"503 unavailable", 503, "", nil, ClassAmbiguous},
		{"504 gw timeout", 504, "", nil, ClassAmbiguous},
		{"400 bad request", 400, "", nil, ClassTerminal},
		{"404 not found", 404, "", nil, ClassTerminal},
		{"409 conflict", 409, "", nil, ClassTerminal},
		{"422 unprocessable", 422, "", nil, ClassTerminal},
		{"3xx surfaced", 302, "", nil, ClassTerminal}, // wrong-host redirect: deterministic, not ambiguous

		// transient codes win over status bucket (a throttle riding a 400)
		{"AWS Throttling on 400", 400, "Throttling", nil, ClassTransient},
		{"AWS ThrottlingException", 400, "ThrottlingException", nil, ClassTransient},
		{"AWS RequestLimitExceeded", 400, "RequestLimitExceeded", nil, ClassTransient},
		{"AWS SlowDown", 503, "SlowDown", nil, ClassTransient},
		{"GCP RESOURCE_EXHAUSTED", 429, "RESOURCE_EXHAUSTED", nil, ClassTransient},
		{"GCP rateLimitExceeded", 403, "rateLimitExceeded", nil, ClassTransient},
		{"Azure TooManyRequests", 400, "TooManyRequests", nil, ClassTransient},

		// auth codes -> denied (even on a non-401/403 status)
		{"AWS AccessDenied on 400", 400, "AccessDenied", nil, ClassDenied},
		{"AWS UnauthorizedOperation", 400, "UnauthorizedOperation", nil, ClassDenied},
		{"GCP PERMISSION_DENIED", 403, "PERMISSION_DENIED", nil, ClassDenied},
		{"Azure AuthorizationFailed", 403, "AuthorizationFailed", nil, ClassDenied},

		// ambiguous codes -> ambiguous (may have landed)
		{"AWS InternalError on 400", 400, "InternalError", nil, ClassAmbiguous},
		{"GCP UNAVAILABLE", 400, "UNAVAILABLE", nil, ClassAmbiguous},
		{"GCP DEADLINE_EXCEEDED", 400, "DEADLINE_EXCEEDED", nil, ClassAmbiguous},
		{"Azure ServiceUnavailable", 400, "ServiceUnavailable", nil, ClassAmbiguous},

		// unrecognized code on a clean 4xx stays terminal
		{"unknown code on 400", 400, "NoSuchBucketPolicy", nil, ClassTerminal},
		// unrecognized code on a 5xx stays ambiguous (fail-closed)
		{"unknown code on 500", 500, "WeirdNewError", nil, ClassAmbiguous},
	}
	for _, c := range cases {
		if got := Classify(c.status, c.code, c.terr); got != c.want {
			t.Errorf("%s: Classify(%d,%q,%v) = %d, want %d", c.name, c.status, c.code, c.terr, got, c.want)
		}
	}
}

func TestClassMappings(t *testing.T) {
	// Unknown() / Retryable() spine.
	if !ClassTransient.Unknown() || !ClassAmbiguous.Unknown() || !ClassDenied.Unknown() {
		t.Error("transient/ambiguous/denied must all be Unknown()")
	}
	if ClassOK.Unknown() || ClassTerminal.Unknown() {
		t.Error("ok/terminal must NOT be Unknown()")
	}
	if !ClassTransient.Retryable() {
		t.Error("transient must be Retryable()")
	}
	if ClassAmbiguous.Retryable() || ClassDenied.Retryable() || ClassTerminal.Retryable() {
		t.Error("only transient is Retryable() — ambiguous/denied/terminal need reconcile or fail")
	}
}

func TestMutationResult(t *testing.T) {
	// ClassOK and ClassTerminal -> nil (caller proceeds / fails with own text).
	if r := MutationResult(200, "", nil, "pid1", "create"); r != nil {
		t.Errorf("2xx must yield nil, got %+v", r)
	}
	if r := MutationResult(400, "MalformedRequest", nil, "pid1", "create"); r != nil {
		t.Errorf("terminal must yield nil (caller fails with own text), got %+v", r)
	}
	// transient -> unknown, pid preserved.
	r := MutationResult(429, "", nil, "pid-x", "create bucket")
	if r == nil || r.Status != "unknown" || r.ProviderID != "pid-x" {
		t.Fatalf("429 must be unknown+pid, got %+v", r)
	}
	// denied (403) -> unknown, pid preserved, NOT failed.
	r = MutationResult(403, "", nil, "pid-y", "delete role")
	if r == nil || r.Status != "unknown" || r.ProviderID != "pid-y" {
		t.Fatalf("403 must be unknown+pid (never failed), got %+v", r)
	}
	// ambiguous (5xx) -> unknown, pid preserved.
	r = MutationResult(500, "", nil, "pid-z", "create")
	if r == nil || r.Status != "unknown" || r.ProviderID != "pid-z" {
		t.Fatalf("500 must be unknown+pid, got %+v", r)
	}
	// transport -> unknown, pid preserved.
	r = MutationResult(0, "", errFor("dropped"), "pid-t", "create")
	if r == nil || r.Status != "unknown" || r.ProviderID != "pid-t" {
		t.Fatalf("transport must be unknown+pid, got %+v", r)
	}
}

func errFor(s string) error { return errors.New(s) }

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name, val string
		want      int
	}{
		{"empty", "", 0},
		{"delta-seconds", "120", 120},
		{"zero", "0", 0},
		{"negative", "-5", 0},
		{"garbage", "soon", 0},
		{"http-date future", now.Add(30 * time.Second).UTC().Format(http.TimeFormat), 30},
		{"http-date past", now.Add(-30 * time.Second).UTC().Format(http.TimeFormat), 0},
	}
	for _, c := range cases {
		if got := ParseRetryAfter(c.val, now); got != c.want {
			t.Errorf("%s: ParseRetryAfter(%q) = %d, want %d", c.name, c.val, got, c.want)
		}
	}
}

// MutationResult carries the Retry-After hint only for a transient throttle.
func TestMutationResultRetryAfter(t *testing.T) {
	r := MutationResult(429, "", nil, "pid", "create", 45)
	if r == nil || r.RetryAfterSeconds != 45 {
		t.Fatalf("429 with retry-after 45 must carry it, got %+v", r)
	}
	// a 5xx (ambiguous, not transient) must NOT carry a retry-after (reconcile, not retry)
	r = MutationResult(500, "", nil, "pid", "create", 45)
	if r == nil || r.RetryAfterSeconds != 0 {
		t.Fatalf("ambiguous 5xx must not carry retry-after, got %+v", r)
	}
	// omitted variadic -> 0
	r = MutationResult(429, "", nil, "pid", "create")
	if r == nil || r.RetryAfterSeconds != 0 {
		t.Fatalf("no hint -> 0, got %+v", r)
	}
}
