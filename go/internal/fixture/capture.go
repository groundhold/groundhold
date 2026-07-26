package fixture

import (
	"bytes"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"

	"groundhold/internal/provider"
)

// capture.go is the recording half of the harness (D234): it runs ONLY where
// real credentials exist (the canary, GCP first; the AWS sandbox later) — never
// on a dev host with stray/client creds. A Recorder wraps the driver's OWN HTTP
// transport, so the request captured is exactly the request the driver sends
// (not a hand-approximation), and it tees the verbatim response bytes back so the
// driver still parses them. BuildFixture then assembles a `provenance: live`
// fixture — recorded exchange + the parser's observations (to be HUMAN-REVIEWED
// in the capture PR, which is what breaks the circularity: without review the
// expected block is just the driver's assumption again).

// Exchange is one recorded request/response.
type Exchange struct {
	Method  string
	Path    string
	Query   map[string]string
	Status  int
	Headers map[string]string
	Body    []byte
}

// Recorder is an http.RoundTripper that records every exchange while delegating
// to a real transport. Safe for concurrent use.
type Recorder struct {
	under     http.RoundTripper
	mu        sync.Mutex
	Exchanges []Exchange
}

// NewRecorder wraps a transport (nil = http.DefaultTransport).
func NewRecorder(under http.RoundTripper) *Recorder {
	if under == nil {
		under = http.DefaultTransport
	}
	return &Recorder{under: under}
}

// Client returns an *http.Client to inject as the driver's HTTP field, so the
// driver's real calls flow through the recorder.
func (r *Recorder) Client() *http.Client { return &http.Client{Transport: r} }

func (r *Recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.under.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	body, rerr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if rerr != nil {
		return resp, rerr
	}
	// tee: hand the driver a fresh reader over the same bytes
	resp.Body = io.NopCloser(bytes.NewReader(body))

	q := map[string]string{}
	for k := range req.URL.Query() {
		q[k] = req.URL.Query().Get(k)
	}
	hdr := map[string]string{}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		hdr["content-type"] = ct
	}
	r.mu.Lock()
	r.Exchanges = append(r.Exchanges, Exchange{
		Method: req.Method, Path: req.URL.Path, Query: q,
		Status: resp.StatusCode, Headers: hdr, Body: body,
	})
	r.mu.Unlock()
	return resp, nil
}

// Meta is the capture context BuildFixture stamps onto a live fixture. CapturedBy
// MUST identify the canary run (e.g. "canary-gcp@<run-id>") — Load refuses a
// `live` fixture without it. Redact maps literal account-specifics (project ids,
// numbers, ARNs) to placeholders; every applied replacement is recorded in the
// fixture's scrubbed list so the redaction is auditable.
type Meta struct {
	Provider, Service, Operation, Variant string
	CapturedBy, CapturedAt, APIVersion    string
	Redact                                map[string]string // literal -> placeholder
}

// BuildFixture assembles a live-provenance fixture from a recorded exchange and
// the observations the driver parsed from it. The observations become the
// expected block — flagged for human review in the PR. The shape signature is
// computed from the (scrubbed) response bytes.
func BuildFixture(meta Meta, ex Exchange, obs []provider.Observation) (*Fixture, error) {
	body, scrubbed := scrub(ex.Body, meta.Redact)
	path := ex.Path
	for lit, ph := range meta.Redact {
		path = strings.ReplaceAll(path, lit, ph)
	}
	shape, hash, err := ShapeOf(body)
	if err != nil {
		return nil, err
	}
	f := &Fixture{
		Schema:   "groundhold/fixture/v1",
		Provider: meta.Provider, Service: meta.Service,
		Operation: meta.Operation, Variant: meta.Variant,
		Provenance: ProvenanceLive,
		CapturedAt: meta.CapturedAt, CapturedBy: meta.CapturedBy, APIVersion: meta.APIVersion,
		Shape: shape, ShapeHash: hash,
	}
	f.Request.Method, f.Request.Path, f.Request.Query = ex.Method, path, ex.Query
	f.Response.Status, f.Response.Headers, f.Response.Raw = ex.Status, ex.Headers, body
	for _, o := range obs {
		f.Expected.Observations = append(f.Expected.Observations,
			ExpectedObs{Path: o.Path, Value: o.Value, Derivation: o.Derivation})
	}
	f.Scrubbed = scrubbed
	return f, nil
}

// scrub applies literal redactions to the raw bytes, returning the scrubbed body
// and the sorted list of placeholders applied (for the fixture's audit trail).
func scrub(raw []byte, redact map[string]string) ([]byte, []string) {
	if len(redact) == 0 {
		return raw, nil
	}
	s := string(raw)
	var applied []string
	for lit, ph := range redact {
		if strings.Contains(s, lit) {
			s = strings.ReplaceAll(s, lit, ph)
			applied = append(applied, ph)
		}
	}
	sort.Strings(applied)
	return []byte(s), applied
}
