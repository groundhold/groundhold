package provider

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// errorclass.go is the SHARED provider-error classifier (D237, API-drift #4).
// Every driver classified provider HTTP errors ad-hoc, with a copy-pasted ladder
// that lumped 429 (throttle), 503 (again-later) and 403 (permission) into a
// TERMINAL `failed`. But an HTTP status is evidence about the CHANNEL, not about
// the RESOURCE: only the provider saying "I understood you and the answer is no"
// (a clean 4xx refusal) may produce a terminal `failed`. A rate-limit, a server
// error, or a live 403 is a statement about the wire — under never-fabricate it
// must be `unknown`, with the providerId preserved so a retry or reconcile can
// still land or observe the resource. This file is the one place the wire fact ->
// outcome mapping lives, so the mapping is identical across aws/gcp/azure and the
// transient/ambiguous/auth code vocabulary is auditable in one table.
//
// The classifier is PURE: per-cloud adapters extract the normalized error code
// (AWS nested XML <Code>, GCP JSON error.status/reason, Azure JSON error.code)
// and hand it here; the status+code table is shared. It never touches the network.

// ErrorClass is the closed classification of a provider response.
type ErrorClass int

const (
	// ClassOK: a 2xx — not an error. The caller proceeds/polls. Success is never
	// INFERRED by the classifier.
	ClassOK ErrorClass = iota
	// ClassTransient: the provider rate-limited/throttled the request at the door
	// (429, or a throttle/rate-limit code on any status). The mutation almost
	// certainly did NOT land, so a plain retry is safe — no reconcile needed.
	// Maps to `unknown`, providerId preserved.
	ClassTransient
	// ClassAmbiguous: a transport error, a 5xx, a timeout/internal code, or an
	// unreadable body after a mutating request — the mutation MAY have landed, so
	// the safe move is reconcile (a blind retry could double-create a
	// non-idempotent resource). Maps to `unknown`, providerId preserved. Anything
	// not provably a pure rate-limit lands here — the fail-closed default.
	ClassAmbiguous
	// ClassDenied: an authenticated-but-forbidden (401/403, or an auth code) at
	// MUTATION time. NOT `failed`: IAM is eventually consistent, so a live 403 can
	// be stale, and it can arrive after a prior step of a compound mutation
	// already landed — calling it failed would fabricate "nothing landed" and
	// orphan the resource (the D62 phantom class). Maps to `unknown`, providerId
	// preserved. It does NOT emit provider-permission-denied — that code is
	// reserved for an AUTHORITATIVE preflight (D75); a live 403 is not
	// authoritative. The distinct class only flavors the reason so the operator
	// checks IAM rather than waits out a throttle.
	ClassDenied
	// ClassTerminal: any other 4xx — a clean, deterministic refusal (bad request,
	// malformed, a conflict the driver did not special-case). The ONLY class that
	// maps to `failed`.
	ClassTerminal
)

// Unknown reports whether the class maps to the four-valued `unknown` outcome
// (transient, ambiguous, or denied — everything that is not a proven terminal
// refusal). This is what a driver's mutation ladder tests to decide whether to
// return unknown+pid instead of a terminal failed.
func (c ErrorClass) Unknown() bool {
	return c == ClassTransient || c == ClassAmbiguous || c == ClassDenied
}

// Retryable reports whether a plain retry (no reconcile) is safe: only a pure
// rate-limit, where the mutation provably did not land. apply maps this to the
// provider-again-later code; everything else unknown maps to reconcile-required.
func (c ErrorClass) Retryable() bool { return c == ClassTransient }

// transientCodes: the throttle/rate-limit family. Rejected at the door => the
// mutation did not land => a plain retry is safe. Matched case-insensitively as
// substrings (providers spell these many ways). Keep this the single source of
// truth; a new throttle spelling is added here, nowhere else.
var transientCodes = []string{
	"throttl",               // AWS Throttling / ThrottlingException / ThrottledException
	"requestlimitexceeded",  // AWS
	"requestthrottled",      // AWS RequestThrottled(Exception)
	"toomanyrequests",       // Azure / generic 429
	"slowdown",              // AWS S3 SlowDown
	"provisionedthroughput", // AWS ProvisionedThroughputExceededException
	"resource_exhausted",    // GCP RESOURCE_EXHAUSTED
	"ratelimitexceeded",     // GCP rateLimitExceeded / userRateLimitExceeded
	"rate_limit",            // GCP RATE_LIMIT_EXCEEDED
	"quotaexceeded",         // GCP quotaExceeded
	"requeststhrottled",     // Azure Subscription/ResourceRequestsThrottled
}

// ambiguousCodes: server-internal / timeout family. The mutation MAY have landed
// => reconcile, do not blind-retry.
var ambiguousCodes = []string{
	"requesttimeout",      // AWS RequestTimeout
	"requestexpired",      // AWS RequestExpired
	"internalerror",       // AWS InternalError
	"internalfailure",     // AWS InternalFailure
	"internalservererror", // Azure InternalServerError
	"internal",            // GCP INTERNAL (also matches the above, harmless)
	"deadline_exceeded",   // GCP DEADLINE_EXCEEDED
	"aborted",             // GCP ABORTED
	"unavailable",         // GCP UNAVAILABLE / AWS+Azure ServiceUnavailable (substring)
	"backenderror",        // GCP backendError
	"servertimeout",       // Azure ServerTimeout
	"gatewaytimeout",      // Azure GatewayTimeout
	"operationtimedout",   // Azure OperationTimedOut
	"retryableerror",      // Azure RetryableError
}

// authCodes: authentication/authorization refusals that can ride a non-401/403
// status (e.g. AWS returns AccessDenied on a 400, GCP PERMISSION_DENIED on a
// 403). Mapped to ClassDenied -> unknown.
var authCodes = []string{
	"accessdenied",                    // AWS AccessDenied / AccessDeniedException
	"unauthorizedoperation",           // AWS
	"authfailure",                     // AWS AuthFailure
	"unrecognizedclient",              // AWS UnrecognizedClientException
	"invalidclienttoken",              // AWS InvalidClientTokenId
	"invalidaccesskeyid",              // AWS
	"signaturedoesnotmatch",           // AWS
	"expiredtoken",                    // AWS ExpiredToken
	"tokenrefreshrequired",            // AWS
	"permission_denied",               // GCP PERMISSION_DENIED
	"unauthenticated",                 // GCP UNAUTHENTICATED
	"access_token_scope",              // GCP ACCESS_TOKEN_SCOPE_INSUFFICIENT
	"authorizationfailed",             // Azure AuthorizationFailed / LinkedAuthorizationFailed
	"authorizationpermissionmismatch", // Azure
	"authenticationfailed",            // Azure
	"invalidauthenticationtoken",      // Azure
	"expiredauthenticationtoken",      // Azure
	"forbidden",                       // Azure Forbidden
}

func matchesAny(lc string, set []string) bool {
	for _, s := range set {
		if strings.Contains(lc, s) {
			return true
		}
	}
	return false
}

// Classify maps a provider response to an ErrorClass. status is the HTTP status
// (0 if none), code is the normalized provider error code ("" if none),
// transportErr is a non-nil network/transport error. Pure and deterministic.
// Precedence: transport, then 2xx, then the code tables (a code can only WIDEN a
// would-be terminal to unknown, never narrow an unknown to terminal), then the
// status ladder. The fail-closed default for any non-2xx we do not recognize is
// Ambiguous, never Terminal — an unknown new provider code is classified too
// pessimistically (unknown), never too optimistically (a fabricated failed).
func Classify(status int, code string, transportErr error) ErrorClass {
	if transportErr != nil {
		return ClassAmbiguous
	}
	if status >= 200 && status < 300 {
		return ClassOK
	}
	lc := strings.ToLower(strings.TrimSpace(code))
	if lc != "" {
		switch {
		case matchesAny(lc, transientCodes):
			return ClassTransient
		case matchesAny(lc, authCodes):
			return ClassDenied
		case matchesAny(lc, ambiguousCodes):
			return ClassAmbiguous
		}
	}
	switch {
	case status == 429 || status == 408:
		return ClassTransient
	case status == 401 || status == 403:
		return ClassDenied
	case status >= 500:
		return ClassAmbiguous // server error — may have landed; reconcile, not failed
	case status >= 400:
		return ClassTerminal // a clean, deterministic refusal
	}
	// A non-2xx below 400 (a 3xx surfacing here — e.g. a 301 to a wrong-region
	// host) is a deterministic addressing problem a retry/reconcile cannot fix,
	// not an ambiguous "may have landed": terminal, never a fabricated pass.
	return ClassTerminal
}

// MutationResult turns a classified provider response into the CreateResult a
// mutation (create/delete/claim/update) must return for a NON-terminal outcome,
// or nil for ClassOK and ClassTerminal — so a caller can insert it before its
// existing terminal `failed` branch without changing that branch's reason text:
//
//	default:
//	    if r := provider.MutationResult(st, code, nil, pid, "create"); r != nil {
//	        return *r
//	    }
//	    return provider.CreateResult{Status: "failed", Reason: ...existing...}
//
// pid is the deterministic providerId when known (preserved on every unknown so
// reconcile keeps the handle); what names the operation ("create bucket").
//
// retryAfterSeconds is an OPTIONAL trailing arg (D243): a driver that captured the
// provider's Retry-After header on a throttle passes it so converge waits exactly
// that long instead of a blind exponential backoff. It is variadic so the ~123
// existing call sites compile unchanged; a driver opts in per site as its throttle
// path is enhanced. Only meaningful for ClassTransient; ignored otherwise.
func MutationResult(status int, code string, transportErr error, pid, what string, retryAfterSeconds ...int) *CreateResult {
	class := Classify(status, code, transportErr)
	if !class.Unknown() {
		return nil // ClassOK or ClassTerminal — caller proceeds or fails with its own text
	}
	var why string
	switch class {
	case ClassTransient:
		why = "transient (throttled) — retry"
	case ClassDenied:
		why = "permission denied — grant the permission, then reconcile"
	default: // ClassAmbiguous
		why = "may have landed — reconcile"
	}
	detail := code
	if transportErr != nil {
		detail = transportErr.Error()
	}
	reason := fmt.Sprintf("%s outcome unknown: %s", what, why)
	if detail != "" {
		reason = fmt.Sprintf("%s (HTTP %d %s): %s", what, status, strings.TrimSpace(detail), why)
	}
	ra := 0
	if class == ClassTransient && len(retryAfterSeconds) > 0 && retryAfterSeconds[0] > 0 {
		ra = retryAfterSeconds[0]
	}
	return &CreateResult{ProviderID: pid, Status: "unknown", Reason: reason,
		Retryable: class.Retryable(), RetryAfterSeconds: ra}
}

// RetryAfterFrom reads and parses the Retry-After response header (D243) — the
// one-line way a driver whose HTTP helper surfaces headers opts a throttle path
// into honoring the provider's hint: pass RetryAfterFrom(resp.Header, d.Now()) as
// MutationResult's trailing arg. 0 (fall back to backoff) when absent/unparseable.
func RetryAfterFrom(h http.Header, now time.Time) int {
	if h == nil {
		return 0
	}
	return ParseRetryAfter(h.Get("Retry-After"), now)
}

// ParseRetryAfter parses an HTTP Retry-After header value (D243) into whole
// seconds: either delta-seconds ("120") or an HTTP-date, relative to now. Returns
// 0 for an empty/unparseable value or a past date — 0 means "no hint", and the
// caller falls back to its own backoff. Pure (now is injected).
func ParseRetryAfter(v string, now time.Time) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n < 0 {
			return 0
		}
		return n
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return int(d.Round(time.Second) / time.Second)
		}
	}
	return 0
}
