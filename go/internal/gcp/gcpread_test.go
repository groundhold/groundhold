package gcp

import (
	"strings"
	"testing"
)

// D306/D309: gcpread.go turns a failed read into a message that says WHY
// (transport/http/body), instead of collapsing every cause into the bare word
// "unreadable" — and mutDetail bounds a mutation's error detail to Google's own
// message, never a raw response dump. These are pure functions; test directly.

func TestGcpReadErrorTransport(t *testing.T) {
	err := readTransport("alertPolicies.get", errString("connection reset by peer"))
	got := err.Error()
	want := "alertPolicies.get: no answer — connection reset by peer"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestGcpReadErrorBody(t *testing.T) {
	err := readBody("secrets.get", 200)
	got := err.Error()
	want := "secrets.get: HTTP 200 but the body did not parse"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestGcpReadErrorHTTPWithCode(t *testing.T) {
	err := readHTTP("buckets.get", 403, "PERMISSION_DENIED")
	got := err.Error()
	want := "buckets.get: HTTP 403 (PERMISSION_DENIED)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestGcpReadErrorHTTPWithoutCode(t *testing.T) {
	err := readHTTP("buckets.get", 500, "")
	got := err.Error()
	want := "buckets.get: HTTP 500"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestGcpReadErrorHTTPCodeBounded: an oversized or newline-carrying Google
// error code must not blow up the message or break single-line log parsing.
func TestGcpReadErrorHTTPCodeBounded(t *testing.T) {
	long := ""
	for i := 0; i < 200; i++ {
		long += "x"
	}
	err := readHTTP("op", 400, long)
	got := err.Error()
	if len(got) > 250 {
		t.Fatalf("HTTP error message not bounded: %d chars", len(got))
	}
	if !strings.Contains(got, "…") {
		t.Fatalf("an oversized code must be truncated with an ellipsis, got %q", got)
	}

	withNewline := readHTTP("op", 400, "line1\nline2")
	if strings.Contains(withNewline.Error(), "\n") {
		t.Fatalf("a code with newlines must be flattened to one line, got %q", withNewline.Error())
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// ---- mutDetail (D309) -------------------------------------------------

func TestMutDetailUsesGoogleMessage(t *testing.T) {
	body := []byte(`{"error":{"message":"Instance already exists"}}`)
	got := mutDetail(body)
	if got != "Instance already exists" {
		t.Fatalf("got %q", got)
	}
}

func TestMutDetailTruncatesLongMessage(t *testing.T) {
	msg := ""
	for i := 0; i < 250; i++ {
		msg += "a"
	}
	body := []byte(`{"error":{"message":"` + msg + `"}}`)
	got := mutDetail(body)
	if len(got) > 210 {
		t.Fatalf("mutDetail must bound the message length, got %d chars", len(got))
	}
	if !strings.Contains(got, "…") {
		t.Fatalf("a truncated message must carry an ellipsis, got %q", got)
	}
}

func TestMutDetailFlattensNewlines(t *testing.T) {
	body := []byte(`{"error":{"message":"line1\nline2"}}`)
	got := mutDetail(body)
	if strings.Contains(got, "\n") {
		t.Fatalf("mutDetail must flatten newlines, got %q", got)
	}
}

// TestMutDetailFallsBackToCode: no message, but the response DOES carry a
// structured status/reason — use that instead of a bare "unreadable".
func TestMutDetailFallsBackToCode(t *testing.T) {
	body := []byte(`{"error":{"status":"FAILED_PRECONDITION"}}`)
	got := mutDetail(body)
	if got != "FAILED_PRECONDITION" {
		t.Fatalf("got %q, want FAILED_PRECONDITION", got)
	}
}

// TestMutDetailFallsBackToReasonOverStatus: errors[0].reason takes priority
// over the top-level status when both are present.
func TestMutDetailFallsBackToReasonOverStatus(t *testing.T) {
	body := []byte(`{"error":{"status":"FAILED_PRECONDITION","errors":[{"reason":"quotaExceeded"}]}}`)
	got := mutDetail(body)
	if got != "quotaExceeded" {
		t.Fatalf("got %q, want quotaExceeded (reason over status)", got)
	}
}

// TestMutDetailNoMessageNoCode: an unparseable or empty body must never crash
// and must say honestly that nothing was carried, not fabricate detail.
func TestMutDetailNoMessageNoCode(t *testing.T) {
	for _, body := range [][]byte{nil, []byte(``), []byte(`not json`), []byte(`{}`)} {
		got := mutDetail(body)
		if got != "(the response carried no error code or message)" {
			t.Fatalf("body %q: got %q", body, got)
		}
	}
}
