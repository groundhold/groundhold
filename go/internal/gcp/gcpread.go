// Diagnosable reads for GCP (D299) — the third sibling of internal/azure/
// armread.go (D295) and internal/aws/awsread.go (D296). Identical defect,
// identical fix: a read that produced no document reported the bare word
// "unreadable", discarding the HTTP status and Google's own error code, so a
// 403 (missing role), a 404-shaped absence and a retired API version all read
// the same to an operator.
//
// Semantics are untouched: a 404 remains an authoritative absence (found=false,
// no error); everything else becomes an error that says why.
package gcp

import (
	"encoding/json"
	"fmt"
	"strings"
)

type gcpReadError struct {
	Op     string // the API call, e.g. "alertPolicies.get"
	Cause  string // transport | http | body
	Status int
	Code   string // Google's own status/reason, when it sent one
	Detail string
}

func (e *gcpReadError) Error() string {
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

// readTransport / readHTTP / readBody mirror the AWS constructors so a reader
// moving between drivers meets one vocabulary, not three.
func readTransport(op string, err error) error {
	return &gcpReadError{Op: op, Cause: "transport", Detail: err.Error()}
}

func readHTTP(op string, status int, code string) error {
	return &gcpReadError{Op: op, Cause: "http", Status: status, Code: code}
}

func readBody(op string, status int) error {
	return &gcpReadError{Op: op, Cause: "body", Status: status}
}

// ---- mutation diagnostics (D309) -------------------------------------------
//
// The read side has said since D296 that a diagnostic must never carry a body
// wholesale. The mutation side used to do exactly that — `truncate(body)` pasted
// up to 300 raw bytes into a CreateResult.Reason, which apply.go persists as
// receipt["reason"], `export` publishes and `capsule` signs. mutDetail is the
// replacement: Google's own error MESSAGE, bounded and newline-free, falling
// back to the structured status/reason when no message was sent.
//
// This is the STRUCTURAL half of the defence; the driver also scrubs its own
// credentials at the boundary (internal/provider/redact.go), because no amount
// of structure stops a provider echoing a value we supplied inside its message.
func mutDetail(body []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	msg := ""
	if json.Unmarshal(body, &e) == nil {
		msg = strings.TrimSpace(e.Error.Message)
	}
	if msg == "" {
		if c := gcpErrCode(body); c != "" {
			return c
		}
		return "(the response carried no error code or message)"
	}
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return strings.ReplaceAll(msg, "\n", " ")
}
