// Diagnosable reads (D295). Every Azure read path used to collapse four
// distinct failures — the URL guard refusing, a transport drop, a non-200
// answer, an unparseable body — into the single word "unreadable", discarding
// the HTTP status and the ARM error code. The four-valued verdict was right
// (absence of evidence, never a fabricated value), but the DIAGNOSIS was
// missing: an operator, and the author debugging D294, could not tell a 403
// from a retired api-version without re-issuing the request by hand.
//
// This file adds the missing half WITHOUT touching the semantics: 404 remains
// an authoritative absence (found=false, no error), everything else becomes an
// error that names the operation, the status and the provider's own code.
package azure

import (
	"encoding/json"
	"fmt"
	"strings"
)

// armReadError describes WHY a read did not produce a document. It is a
// diagnostic, never a decision input: callers still treat any non-nil error as
// "no evidence" (D242), they can just finally SAY what happened.
type armReadError struct {
	Op     string // the ARM operation, e.g. "virtualNetworks.get"
	Cause  string // scope | transport | http | body
	Status int    // HTTP status; 0 when the failure preceded a response
	Code   string // the provider's own error code, when it sent one
	Detail string // short, provider-supplied or local; never a whole body
}

func (e *armReadError) Error() string {
	var b strings.Builder
	b.WriteString(e.Op)
	switch e.Cause {
	case "scope":
		b.WriteString(": refused before the request — ")
		b.WriteString(e.Detail)
	case "transport":
		b.WriteString(": no answer — ")
		b.WriteString(e.Detail)
	case "body":
		fmt.Fprintf(&b, ": HTTP %d but the body did not parse", e.Status)
	default:
		fmt.Fprintf(&b, ": HTTP %d", e.Status)
		if e.Code != "" {
			fmt.Fprintf(&b, " (%s)", e.Code)
		}
		if e.Detail != "" {
			b.WriteString(" — ")
			b.WriteString(e.Detail)
		}
	}
	return b.String()
}

// azErrMessage lifts the provider's human message, trimmed. Azure error
// messages describe the failure and may name the resource — which the caller
// already knows, since it asked for it — so they are safe to surface. Bodies
// are never included wholesale: an unbounded body in a diagnostic is how
// secrets leak into logs.
func azErrMessage(body []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	m := strings.TrimSpace(e.Error.Message)
	if len(m) > 200 {
		m = m[:200] + "…"
	}
	return strings.ReplaceAll(m, "\n", " ")
}

// mutDetailAz renders a MUTATION failure's detail (D309): Azure's own error
// message, bounded and newline-free — never the raw body. The mutation side used
// to paste up to 400 raw bytes into a CreateResult.Reason, which apply.go
// persists as receipt["reason"], `export` publishes and `capsule` signs.
//
// This is the STRUCTURAL half of the defence; the driver also scrubs its own
// credentials at the boundary (internal/provider/redact.go), because no amount
// of structure stops a provider echoing a value we supplied inside its message.
func mutDetailAz(body []byte) string {
	if m := azErrMessage(body); m != "" {
		return m
	}
	if c := azErrCode(body); c != "" {
		return c
	}
	return "(the response carried no error code or message)"
}

// armTransport / armHTTP / armBody build the same three diagnoses for readers
// that cannot use armGetInto — the ones that need the raw body back, or that
// read through a call helper of their own. Same vocabulary, same bounds.
func armTransport(op string, err error) error {
	return &armReadError{Op: op, Cause: "transport", Detail: err.Error()}
}

func armHTTP(op string, status int, body []byte) error {
	return &armReadError{Op: op, Cause: "http", Status: status,
		Code: azErrCode(body), Detail: azErrMessage(body)}
}

func armBody(op string, status int) error {
	return &armReadError{Op: op, Cause: "body", Status: status}
}

// armGetInto performs one ARM GET and unmarshals the document into out.
//
//	found=false, err=nil  -> the resource is authoritatively ABSENT (404)
//	found=true,  err=nil  -> out is populated
//	err != nil            -> no evidence, and the error says why
//
// op names the operation for the diagnostic (e.g. "virtualNetworks.get").
func (d *Driver) armGetInto(op, resourceGroup, providerPath, apiVersion string,
	out any) (bool, error) {
	url, err := d.armURL(resourceGroup, providerPath, apiVersion)
	if err != nil {
		return false, &armReadError{Op: op, Cause: "scope", Detail: err.Error()}
	}
	return d.armGetURLInto(op, url, out)
}

// armGetURLInto is armGetInto for a URL the caller already built (list
// endpoints, sub-resource paths, non-standard query strings).
func (d *Driver) armGetURLInto(op, url string, out any) (bool, error) {
	st, body, err := d.doARM("GET", url, nil)
	if err != nil {
		return false, &armReadError{Op: op, Cause: "transport", Status: st, Detail: err.Error()}
	}
	if st == 404 {
		return false, nil // authoritative absence — evidence, not a failure
	}
	if st < 200 || st > 299 {
		return false, &armReadError{Op: op, Cause: "http", Status: st,
			Code: azErrCode(body), Detail: azErrMessage(body)}
	}
	if out != nil {
		if jerr := json.Unmarshal(body, out); jerr != nil {
			// a garbled 200 is NOT a well-formed absence: refuse to let a
			// decision-gating parse read a short body as reality (D87).
			return false, &armReadError{Op: op, Cause: "body", Status: st}
		}
	}
	return true, nil
}

// azReadWhy renders a one-line cause for the DISCOVER paths, which collect
// diagnostics as plain strings rather than errors (a partial enumeration is a
// fact, never a failure — D242). Same information, same bounds as
// armReadError: status, the provider's own code, a trimmed message.
func azReadWhy(status int, body []byte, err error) string {
	if err != nil {
		return fmt.Sprintf("no answer — %v", err)
	}
	e := &armReadError{Cause: "http", Status: status,
		Code: azErrCode(body), Detail: azErrMessage(body)}
	return strings.TrimPrefix(e.Error(), ": ")
}
