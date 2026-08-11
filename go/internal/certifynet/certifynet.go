// Package certifynet is an executable adversarial honesty harness for provider
// drivers (D87). It certifies the four-valued honesty invariants MECHANICALLY —
// not with a per-driver "fault at step N -> verdict X" table (which would just
// re-encode the driver's own bugs), but by deriving the expected verdict SHAPE
// from two wire facts the invariants actually depend on: whether a mutation was
// sent, and what adversarial fault the transport injected.
//
// Method (record-then-perturb, per adversarial review):
//  1. Run an operation (create|delete) once against the driver's own golden happy
//     server, recording the request trace and the baseline providerId.
//  2. For each request in the trace, replay the op serving happy up to that point
//     then injecting ONE adversarial fault (500, dropped-conn, garbled-200,
//     empty-body, foreign-tag) at it.
//  3. Assert only law-derived shape invariants on the returned CreateResult:
//     - an ambiguous fault after >=1 mutation was sent  -> Status unknown AND the
//     deterministic providerId is preserved (a partial never loses the handle).
//     - any fault must NEVER yield `succeeded` when the outcome is unprovable.
//     - a foreign-tag on an ownership read -> the driver REFUSES (failed) and
//     sends NO mutation afterward (never delete/adopt what isn't ours).
//
// Blind spots (by construction — cover these with the metamorphic round-trip in
// roundtrip.go, the goldens, and live tests): semantic field mis-mapping, silent
// missing steps, poll-loop false-success on a plausible-but-wrong 200, TOCTOU,
// eventual consistency. The harness catches "the driver lied about an ambiguous
// wire outcome"; it does not prove "the driver asked the cloud the right question".
//
// Ownership scope: the foreign-tag test certifies ownership refusal only where the
// ownership signal is a single echoed value the surgery can rewrite (AWS tags:
// >value< / "value"). Where ownership is a NON-echoed or composite signal — GCS's
// projectNumber (D82), a GCP VPC description marker — the same value poison does
// not model "not ours" (the driver keys on a different field), so that refusal
// stays certified by the driver's own ownership unit tests, not here. The MUTATION-
// honesty half is universal; the OWNERSHIP half is universal only for echoed-tag
// providers. This is a real limit, stated rather than papered over.
package certifynet

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"groundhold/internal/provider"
)

// Fault is one adversarial perturbation of a single response.
type Fault int

const (
	FaultNone       Fault = iota
	Fault500              // server error: a mutation "may have landed"
	FaultConnDrop         // transport error after the request left
	FaultGarbled200       // a truncated/unparseable 200 body
	FaultEmptyBody        // a 200 with an empty body (missing op-id / arn)
	FaultForeignTag       // surgery: rewrite an ownership tag value to a foreign one
	Fault429              // D237: throttle — transient, the mutation did not land
	Fault503              // D237: service unavailable — ambiguous, may have landed
	Fault403              // D237: live permission denied — unknown, NOT a terminal failed
)

func (f Fault) String() string {
	switch f {
	case FaultNone:
		return "none"
	case Fault500:
		return "http500"
	case FaultConnDrop:
		return "conn-drop"
	case FaultGarbled200:
		return "garbled200"
	case FaultEmptyBody:
		return "empty-body"
	case FaultForeignTag:
		return "foreign-tag"
	case Fault429:
		return "http429"
	case Fault503:
		return "http503"
	case Fault403:
		return "http403"
	}
	return "?"
}

// Role is the structural kind of a request — a fact about the PROTOCOL call, not
// an expected verdict. RoleMutateParsed vs RoleMutateOpaque distinguishes a
// mutation whose response body the driver CONSUMES (an op-id/arn/id it needs
// downstream) from one whose success is status-only: a garbled/empty body is
// ambiguous only for the former (S3 PutBucket is opake; ECS RegisterTaskDefinition
// is parsed for its arn).
type Role int

const (
	RoleRead         Role = iota // GET/Describe/List — never mutates
	RoleMutateOpaque             // mutates; success is status-only, body not consumed
	RoleMutateParsed             // mutates; the driver parses a needed id from the body
)

func (r Role) isMutation() bool { return r == RoleMutateOpaque || r == RoleMutateParsed }

// Classifier decides a request's Role, structurally (never by encoding expected
// verdicts). One per PROTOCOL family, shared across drivers; a driver may upgrade
// specific create actions to RoleMutateParsed.
type Classifier func(req *http.Request, body []byte) Role

// Op is one driver operation to certify. Happy returns a FRESH golden happy
// server (fresh so its internal state resets between the many fault replays); Run
// must invoke exactly one of Create/Delete on the provided provider. A delete op's
// happy server must report OUR ownership tags so the baseline delete succeeds.
type Op struct {
	Name  string // "create" | "delete"
	Happy func() *httptest.Server
	Run   func(p provider.Provider) provider.CreateResult
}

// Probe wires a single driver into the harness. New builds the provider pointed at
// the happy server with the scripted transport injected; Classify decides mutation
// vs read structurally (per protocol); OwnerTagValue is the ownership tag value the
// happy server echoes (rewritten by FaultForeignTag).
type Probe struct {
	Name          string
	New           func(happyURL string, rt http.RoundTripper) provider.Provider
	Classify      Classifier
	OwnerTagValue string
	// DeterministicID is true when the providerId is a deterministic function of
	// the request (a chosen name: S3 bucket, RDS id, ECS service name) — so it is
	// knowable even if the create response is lost, and MUST be preserved on an
	// ambiguous outcome. False for server-assigned ids (AWS vpc-xxx/subnet-xxx):
	// a lost create response there genuinely loses the handle, so unknown-without-
	// pid is honest UNTIL the id-yielding call has succeeded.
	DeterministicID bool
	// AssertTransient opts a driver into the D237 structured-error faults
	// (429/503/403 on mutations must be unknown, never a terminal failed). It is
	// a per-driver readiness flag for an INCREMENTAL migration: a driver whose
	// create/delete/claim ladders route through provider.MutationResult sets it
	// true and the harness then locks the invariant; an un-migrated driver leaves
	// it false (its old ladder still maps those to failed) and is a tracked TODO,
	// never a silent claim of coverage.
	AssertTransient bool
	// ObserveAbsent runs the driver's Observe for THIS probe's resource, at the
	// providerId its ops already use. Supplying it opts the service into the
	// F-LC3 absence property (D517) and the harness then locks it; leaving it nil
	// is an un-migrated service the ratchet counts. Unlike a boolean flag it
	// cannot claim coverage it does not have — the only way to assert the
	// property is to hand the harness something it can run.
	ObserveAbsent func(p provider.Provider) ([]provider.Observation, []string, error)
	// GoneCode is the not-found code THIS service's API returns (D522) —
	// "NoSuchEntity", "FileSystemNotFound", "NonExistentQueue". Empty means the
	// generic "NotFound". A correct driver matches on its own service's code, so
	// an estate that always said "NotFound" failed correct drivers.
	GoneCode string
	// GoneEmptyList marks a service whose read is a COLLECTION query, where
	// absence is an EMPTY COLLECTION rather than an error — MSK's
	// ListClustersV2, WAF's ListWebACLs. Those reads are correct and were
	// failing a gate that answered 404 to a call whose API never 404s (D523).
	// The estate then answers 200 with an empty document, which unmarshals to
	// an empty slice under any field name.
	GoneEmptyList bool
	Ops           []Op
}

// TestingT is the minimal testing surface (mirrors provider.CertifyDriver so this
// package need not import "testing").
type TestingT interface {
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Helper()
}

type record struct {
	idx     int
	role    Role
	host    string
	hasAuth bool
}

// scriptRT records the trace, counts mutations, and injects one fault.
type scriptRT struct {
	inner    http.RoundTripper
	classify Classifier
	faultAt  int // -1 = baseline
	fault    Fault
	ownerTag string

	n         int
	mutSent   int
	mutLanded int
	trace     []record
	mutAfter  int  // mutations sent at index > faultAt
	poisoned  bool // FaultForeignTag actually rewrote an ownership tag in the body
}

func peekBody(req *http.Request) []byte {
	if req.Body == nil {
		return nil
	}
	b, _ := io.ReadAll(req.Body)
	restoreBody(req, b)
	return b
}

// restoreBody re-seats a request's body from bytes already read. It is called BEFORE
// classification and again AFTER it (D392): a Classifier that reaches for the request
// instead of the peeked bytes — req.ParseForm() is the easy mistake — drains the body
// the driver has not sent yet, and the driver then fails with "ContentLength=N with
// Body length 0". That reads as a driver bug and is not one. Re-seating afterwards
// makes the whole Certify family immune to it rather than leaving it to each author.
func restoreBody(req *http.Request, b []byte) {
	req.Body = io.NopCloser(bytes.NewReader(b))
	if len(b) > 0 {
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	}
}

func (s *scriptRT) RoundTrip(req *http.Request) (*http.Response, error) {
	i := s.n
	s.n++
	body := peekBody(req)
	role := s.classify(req, body)
	restoreBody(req, body) // see restoreBody: classification must not cost the driver its body
	rec := record{idx: i, role: role, host: req.URL.Host,
		hasAuth: req.Header.Get("Authorization") != "" || req.Header.Get("X-Amz-Date") != ""}
	s.trace = append(s.trace, rec)
	if role.isMutation() {
		s.mutSent++
		if s.faultAt >= 0 && i > s.faultAt {
			s.mutAfter++
		}
	}
	if i == s.faultAt {
		return s.inject(req, body)
	}
	resp, err := s.inner.RoundTrip(req)
	if err == nil && role.isMutation() && resp.StatusCode/100 == 2 {
		s.mutLanded++
	}
	return resp, err
}

func mkResp(req *http.Request, code int, body string) *http.Response {
	return &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": {"application/xml"}},
		Request:    req,
	}
}

func (s *scriptRT) inject(req *http.Request, body []byte) (*http.Response, error) {
	switch s.fault {
	case Fault500:
		return mkResp(req, 500, `<Error><Code>InternalError</Code></Error>`), nil
	case FaultConnDrop:
		return nil, fmt.Errorf("injected connection drop")
	case FaultGarbled200:
		// a truncated body that starts like a real response but does not parse
		return mkResp(req, 200, `<Resp><trunc`), nil
	case FaultEmptyBody:
		return mkResp(req, 200, ``), nil
	case Fault429:
		// D237: a throttle. Status alone classifies as transient regardless of
		// the body's shape; a code-carrying body is exercised by the per-cloud
		// adapter's golden tests, not here.
		return mkResp(req, 429, `{"error":{"message":"rate limited"}}`), nil
	case Fault503:
		return mkResp(req, 503, `{"error":{"message":"service unavailable"}}`), nil
	case Fault403:
		return mkResp(req, 403, `{"error":{"message":"permission denied"}}`), nil
	case FaultForeignTag:
		// serve the happy response, then rewrite the ownership tag value so the
		// resource looks like it belongs to someone else.
		resp, err := s.inner.RoundTrip(req)
		if err != nil {
			return resp, err
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		poisoned := strings.ReplaceAll(string(b), ">"+s.ownerTag+"<", ">someone-else<")
		if poisoned != string(b) {
			s.poisoned = true // the surgery actually hit an ownership tag
		}
		resp.Body = io.NopCloser(strings.NewReader(poisoned))
		resp.ContentLength = int64(len(poisoned))
		return resp, nil
	}
	return s.inner.RoundTrip(req)
}

// faultsFor returns the faults worth injecting at a request of the given role.
// v1 scope: the UNIVERSAL laws only.
//   - Mutation: a lost response (500/drop) is always ambiguous. A garbled/empty
//     response is ambiguous ONLY where the driver parses it (mutationBodyParsed).
//   - Read: only the ownership-poison test (foreign-tag). Generic read 500/garbled
//     is deliberately out of v1: a transient failure on a POLL read is legitimately
//     retried and succeeds, so it cannot be judged without per-driver poll/ownership
//     role distinction. (Ownership-read honesty is covered by foreign-tag + the
//     metamorphic round-trip.)
//
// faultsAt selects the faults to inject at trace position i. Mutation faults are
// role-based; the foreign-tag ownership test applies ONLY to a read that occurs
// BEFORE any mutation in this op — that is where the driver proves ownership. A
// post-mutation read (a poll/drain) that merely echoes the tag is not an ownership
// gate, so poisoning it is not a violation.
func faultsAt(trace []record, i int, transient bool) []Fault {
	// D237 transient faults (429/503/403 -> unknown) are added only for drivers
	// migrated onto provider.MutationResult (Probe.AssertTransient). The universal
	// faults below always apply.
	tf := func(base ...Fault) []Fault {
		if transient {
			return append(base, Fault429, Fault503, Fault403)
		}
		return base
	}
	switch trace[i].role {
	case RoleMutateParsed:
		return tf(Fault500, FaultConnDrop, FaultGarbled200, FaultEmptyBody)
	case RoleMutateOpaque:
		return tf(Fault500, FaultConnDrop)
	default: // RoleRead
		for j := 0; j < i; j++ {
			if trace[j].role.isMutation() {
				return nil // a post-mutation read is not an ownership gate
			}
		}
		return []Fault{FaultForeignTag}
	}
}
