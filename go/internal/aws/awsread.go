// Diagnosable reads for AWS (D296) — the sibling of internal/azure/armread.go
// (D295). The defect is identical and cross-cloud: a read that produced no
// document reported the bare word "unreadable", discarding the HTTP status and
// the service's own error code, so an operator could not tell a throttle from a
// permission gap from a retired API shape without re-issuing the call by hand.
//
// The AWS half cannot share Azure's single reader: every service here has its
// own transport helper (acmCall, rdsPost, eksDo, s3Do, iamPost, …) and its own
// not-found predicate (an error CODE string, not a uniform 404). So this file
// carries the DIAGNOSTIC only — the shape of the answer — and each getter keeps
// its own call and its own absence test. Semantics are unchanged: absence stays
// found=false with no error, everything else becomes an error that says why.
package aws

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
)

// awsReadError describes WHY a read did not produce a document. A diagnostic,
// never a decision input: callers still treat any non-nil error as "no
// evidence" (D242) — they can finally say what happened.
type awsReadError struct {
	Op     string // the API call, e.g. "DescribeCertificate"
	Cause  string // transport | http | body
	Status int    // HTTP status; 0 when the failure preceded a response
	Code   string // the service's own error code, when it sent one
	Detail string
}

func (e *awsReadError) Error() string {
	var b strings.Builder
	b.WriteString(e.Op)
	switch e.Cause {
	case "transport":
		b.WriteString(": no answer — ")
		b.WriteString(e.Detail)
	case "body":
		fmt.Fprintf(&b, ": HTTP %d but the body did not parse", e.Status)
	default:
		fmt.Fprintf(&b, ": HTTP %d", e.Status)
		if c := strings.TrimSpace(e.Code); c != "" {
			if len(c) > 160 {
				c = c[:160] + "…"
			}
			fmt.Fprintf(&b, " (%s)", strings.ReplaceAll(c, "\n", " "))
		}
	}
	return b.String()
}

// readTransport builds the "no answer" case.
func readTransport(op string, err error) error {
	return &awsReadError{Op: op, Cause: "transport", Detail: err.Error()}
}

// readHTTP builds the non-2xx case, carrying the service's own code. The code
// string is bounded and newline-free: a diagnostic must never become a channel
// for an unbounded response body.
func readHTTP(op string, status int, code string) error {
	return &awsReadError{Op: op, Cause: "http", Status: status, Code: code}
}

// awsErrCodeOf lifts a service's own error code from either wire shape — the
// Query-protocol XML (<Error><Code>) or the JSON one (__type / code /
// ErrorCode / message). It NEVER falls back to the raw body: an unbounded body
// in a diagnostic is how a response leaks into a log. An unrecognised shape
// yields "", and the status alone carries the diagnosis.
func awsErrCodeOf(body []byte) string {
	if c := rdsErrCode(body); c != "" {
		return c
	}
	var e struct {
		Type      string `json:"__type"`
		Code      string `json:"code"`
		ErrorCode string `json:"ErrorCode"`
		Message   string `json:"message"`
		Msg       string `json:"Message"`
	}
	_ = json.Unmarshal(body, &e)
	for _, c := range []string{e.Type, e.Code, e.ErrorCode, e.Message, e.Msg} {
		if c = strings.TrimSpace(c); c != "" {
			if len(c) > 160 {
				c = c[:160] + "…"
			}
			return strings.ReplaceAll(c, "\n", " ")
		}
	}
	return ""
}

// readBody builds the garbled-2xx case. A body that does not parse is NOT a
// well-formed absence — refusing here keeps a decision-gating read from
// treating a truncated answer as reality (D87).
func readBody(op string, status int) error {
	return &awsReadError{Op: op, Cause: "body", Status: status}
}

// ---- credential redaction (D309) -------------------------------------------
//
// A failed mutation's Reason is persisted in the ledger and signed into
// capsules. The driver remembers the credential values the candidate handed it
// and removes them from the Reason at the boundary, so no call site has to
// remember to ask. See internal/provider/redact.go for why this is exact rather
// than pattern-matching.

func (d *Driver) rememberSecrets(impl map[string]any) {
	d.secrets.Remember(impl)
}

func (d *Driver) forgetSecrets() { d.secrets.Forget() }

func (d *Driver) scrub(s string) string { return d.secrets.Scrub(s) }

// ---- mutation diagnostics (D309) -------------------------------------------
//
// The read side has said since D296 that a diagnostic must never carry a body
// wholesale. The mutation side used to do exactly that — `truncate(body)` pasted
// up to 400 raw bytes into a CreateResult.Reason, which apply.go persists as
// receipt["reason"], `export` publishes and `capsule` signs. mutDetail is the
// replacement: the service's own MESSAGE, bounded and newline-free, falling back
// to its error CODE when it sent no message. Nothing else crosses.
//
// This is the STRUCTURAL half of the defence. It cannot stop a provider from
// echoing a value we sent inside that message, which is why the driver also
// scrubs its own credentials at the boundary (internal/provider/redact.go).
func mutDetail(body []byte) string {
	if m := awsErrMessage(body); m != "" {
		return m
	}
	if c := awsErrCodeOf(body); c != "" {
		return c
	}
	return "(the response carried no error code or message)"
}

// boundMsg trims a provider-supplied message to a diagnostic-safe shape: bounded
// and newline-free. Every per-service error extractor ends here, so no single one
// of them can reintroduce an unbounded paste (D309).
func boundMsg(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return strings.ReplaceAll(s, "\n", " ")
}

// awsErrMessage lifts the human message from either wire shape — the
// Query-protocol XML (<Error><Message>) or the JSON one (message / Message).
// Bounded and newline-free: a diagnostic must never become a channel for an
// unbounded response.
func awsErrMessage(body []byte) string {
	var x struct {
		Message string `xml:"Error>Message"`
	}
	_ = xml.Unmarshal(body, &x)
	msg := strings.TrimSpace(x.Message)
	if msg == "" {
		var j struct {
			Message string `json:"message"`
			Msg     string `json:"Message"`
		}
		_ = json.Unmarshal(body, &j)
		msg = strings.TrimSpace(j.Message)
		if msg == "" {
			msg = strings.TrimSpace(j.Msg)
		}
	}
	if msg == "" {
		return ""
	}
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return strings.ReplaceAll(msg, "\n", " ")
}
