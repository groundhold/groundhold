// Package reach is the post-apply REACHABILITY PROBE (Layer 1 of the
// org-boundary work). An apply/converge that stands up a PUBLIC EDGE (a
// cdn.distribution with a public/OAC origin, a function.serverless with a
// public Function URL) must not report a bare "APPLIED" while the edge
// silently returns 403 — the Acme "APPLIED ≠ works" pain. This is the
// OUTCOME half of the thesis loop: an HTTPS GET against the applied edge,
// classified FOUR-VALUED, surfaced as a measured observation.
//
// Determinism boundary: this is a NETWORK side-effect and lives OUTSIDE the
// deterministic verifier core. It is never called from apply.Apply (the
// executor stays network-free) — only from the apply VERB and the converge
// porcelain, AFTER a run concludes. Its result is emitted as an ordinary
// measured observation (observedAt=--at), exactly like an outcome probe
// (D59); it never enters a hashed apply receipt.
//
// The honesty core is the whole point (get it EXACTLY right):
//   - 2xx/3xx  -> reachable: the public path is CONFIRMED end-to-end. The
//     ONLY case that earns a green success claim.
//   - 401/403  -> denied: a DISTINCT diagnosed outcome (an org boundary / RCP
//     denying the principal, D326). NOT success, NOT unknown. It must PREVENT
//     announcing clean end-to-end success and must NEVER read as
//     "no public IP / not-configured".
//   - connection refused / DNS / TLS / timeout / any other status -> unknown:
//     unreachable-FROM-HERE (a firewalled CI runner, DNS/edge propagation lag,
//     not-yet-live). Explicitly NOT a failure and NOT a denial. The cause is
//     always NAMED (never a bare "unreachable", D306).
//   - no public output to target -> nothing measured, nothing emitted (like
//     "probe.failed is never an observation").
package reach

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Verdict is the reachability outcome. THREE disjoint states, never two (D696):
// the edge served the public path, the probe did not establish it, or the edge
// answered with something that has no second reading.
//
// The two-state shape folded "I could not confirm this" into the same bucket as
// "this is broken", and the field reported what that costs: a deployment gate
// probing through a rate-limited endpoint took a 429, found no expected phrase,
// fell through to "skipped", changed its mind between runs and shipped an image
// built without a key. The probe did not fail — collapsing a third state into a
// second did.
//
// There is still no "denied" verdict: a 403 to an anonymous probe is ambiguous
// (a missing grant, an auth-gated path, an org guardrail), so blaming a cause
// belongs to a Layer-2 DECLARED constraint, not to the probe. Failing is for
// answers that admit no alternative explanation, not for answers we dislike.
type Verdict string

const (
	Reachable Verdict = "reachable"
	Unknown   Verdict = "unknown"
	// Failing: the edge is there and what it returned is a failure. A 5xx, or a
	// TLS layer that did not complete. Neither is a policy and neither is a
	// vantage-point artefact.
	Failing Verdict = "failing"
	// Skipped is not classified from an answer — it is what the CALLER records
	// when the probe did not run at all (--no-reachability). It lives here so the
	// published closed set has one home.
	Skipped Verdict = "skipped"
)

// ReportedVerdicts is the CLOSED SET a machine reader can see in the `reachability`
// field of applyResult and convergeResult, sorted.
//
// D696: the published schema listed `denied`, which no code path can produce (it was
// removed when a 403 became ambiguous), and of course did not list `failing`. A
// consumer generating types from the schema got one value that never arrives and
// missed one that does. The set has one home now and a gate holds the schema to it —
// the same fix as every other published closed set that drifted (D329/D330/D338).
var ReportedVerdicts = []string{
	string(Failing), string(Reachable), string(Skipped), string(Unknown)}

// Checked names what the measurement COVERED, and rides on every result (D696).
//
// Asked for from the field, with the incident that motivated it: a function that
// would not start answered HTTP 200 carrying {"errorType":"Runtime.InvalidEntrypoint"},
// and a smoke gate keyed on the status class passed it as clean. A dead API looked
// healthy. The boundary is deliberate — the CONTENT contract belongs to whoever owns
// the service, and this probe does not read bodies — but a reader must not have to
// infer the boundary from silence. `--no-reachability` already says "the edge was NOT
// probed"; this says what a probe that DID run actually measured.
const Checked = "reachability and HTTP status class only — the response body was " +
	"not inspected, so a 2xx carrying an error payload reads here as reachable"

// Classify maps an HTTP GET result to the reachability verdict with a NAMED
// cause. err != nil means no usable HTTP response was seen (unreachable from
// here): always unknown, cause naming the failure kind. A 401/403 means the edge
// answered but denied an ANONYMOUS request — genuinely AMBIGUOUS (a missing
// grant, an auth-gated-by-design path, or an org guardrail), so it is unknown
// with a distinct cause, NEVER a confident accusation. Any other non-2xx/3xx
// status is also unknown. Only 2xx/3xx is reachable — a 403 never reads as
// success, and unreachable-from-here never reads as a denial.
func Classify(status int, err error) (Verdict, string) {
	if err != nil {
		if failingTransport(err) {
			return Failing, networkCause(err)
		}
		return Unknown, networkCause(err)
	}
	switch {
	case status >= 200 && status < 400:
		return Reachable, fmt.Sprintf("HTTP %d — the public path answered", status)
	case status == 401 || status == 403:
		return Unknown, fmt.Sprintf("edge returned HTTP %d to an anonymous "+
			"request — the public path is not anonymously reachable (ambiguous: a "+
			"missing grant action, an auth-gated path, or an org guardrail)", status)
	case status >= 500:
		// D696: the edge answered, and 5xx is the edge saying it failed. No
		// policy reads this way and no vantage point produces it.
		return Failing, fmt.Sprintf("edge returned HTTP %d — it answered, and what "+
			"it answered is a failure; no policy and no vantage point explains a 5xx",
			status)
	default:
		return Unknown, fmt.Sprintf("edge responded HTTP %d — reachable at the "+
			"network layer but not confirming the public path; not a proven success",
			status)
	}
}

// failingTransport separates a transport failure that admits no second reading from
// one that does (D696).
//
// FAILING: the TLS layer did not complete — a certificate that does not verify, or a
// handshake that broke. An expired or wrong-name certificate is not a policy and not a
// propagation delay; the edge is there and the connection to it is broken.
//
// UNKNOWN, deliberately, and this is where this implementation stops short of what
// the field asked for: NXDOMAIN, connection refused and timeouts. Each has a live
// second reading MINUTES AFTER A CREATE — DNS propagation, an edge still
// provisioning, a firewalled vantage point — and a probe that runs right after apply
// would turn those into confident accusations. This project refuses confident
// accusations in the other direction just as firmly; making them here to satisfy a
// tidier state machine would be the same error wearing the opposite sign. Bounding
// propagation is a policy decision (how long is too long), and a policy belongs in a
// DECLARED constraint, not compiled into a prober.
func failingTransport(err error) bool {
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return true
	}
	var recErr tls.RecordHeaderError
	return errors.As(err, &recErr)
}

// networkCause names the transport failure so a human/agent never sees a bare
// "unreachable" (D306): DNS, connection refused, TLS or timeout — each a
// distinct unreachable-FROM-HERE cause, none of them a denial.
func networkCause(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "DNS resolution failed (" + dnsErr.Name + ") — the edge name does " +
			"not resolve from here yet (propagation delay, or split-horizon DNS)"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "the request timed out — no answer from the edge within the budget " +
			"(a firewalled vantage point, or the edge is not yet live)"
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return "TLS certificate verification failed — the edge is answering but " +
			"its certificate is not yet trusted/valid from here"
	}
	var recErr tls.RecordHeaderError
	if errors.As(err, &recErr) {
		return "TLS handshake failed — the edge did not speak TLS as expected"
	}
	if strings.Contains(err.Error(), "connection refused") {
		return "connection refused — nothing is listening at the edge from here yet"
	}
	if strings.Contains(strings.ToLower(err.Error()), "tls") ||
		strings.Contains(strings.ToLower(err.Error()), "certificate") {
		return "TLS error contacting the edge: " + err.Error()
	}
	return "could not reach the edge from here: " + err.Error()
}

// Getter performs the edge GET. Injectable so conformance/tests drive canned
// outcomes without a real network, and production uses a real HTTP client.
type Getter interface {
	Get(rawURL string) (status int, err error)
}

// httpGetter is the production getter: a short-timeout HTTPS GET that does NOT
// follow redirects (a 3xx IS a reachable edge, not a hop to chase).
type httpGetter struct{ client *http.Client }

func (g httpGetter) Get(rawURL string) (int, error) {
	resp, err := g.client.Get(rawURL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// DefaultGetter returns the deterministic fake getter when
// GROUNDHOLD_REACHABILITY_FAKE is set (the conformance/test injection point,
// mirroring the fake provider's fail-key style) — otherwise a real HTTPS
// getter. Production is ALWAYS real; only an explicit env var swaps it out.
func DefaultGetter() Getter {
	if v, ok := os.LookupEnv("GROUNDHOLD_REACHABILITY_FAKE"); ok {
		return FakeGetter(v)
	}
	return httpGetter{client: &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

// FakeGetter is the deterministic getter for conformance/tests. The spec value
// is a status code ("200","301","403"...) or a named transport failure
// ("refused","dns","tls","timeout"). It returns the same outcome for every URL.
func FakeGetter(spec string) Getter { return fakeGetter(spec) }

type fakeGetter string

func (f fakeGetter) Get(string) (int, error) {
	switch string(f) {
	case "refused":
		return 0, &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}
	case "dns":
		return 0, &net.DNSError{Name: "edge.example", Err: "no such host", IsNotFound: true}
	case "tls":
		return 0, &tls.CertificateVerificationError{Err: errors.New("x509: certificate signed by unknown authority")}
	case "timeout":
		return 0, timeoutErr{}
	}
	if code, err := strconv.Atoi(string(f)); err == nil {
		return code, nil
	}
	return 0, fmt.Errorf("unrecognized GROUNDHOLD_REACHABILITY_FAKE %q", string(f))
}

// timeoutErr is a net.Error whose Timeout() is true (a canned deadline).
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "context deadline exceeded (fake timeout)" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// Target is one public edge to probe: the capability that owns it, the derived
// URL, and the output name it was derived from (for the honest evidence line).
type Target struct {
	Capability string
	URL        string
	OutputName string
}

// edgeCand is one candidate output that may carry a capability's public edge:
// the output name and whether its value is a full URL (kept as-is) or a bare
// host (wrapped into https://<host>/).
type edgeCand struct {
	name    string
	fullURL bool
}

// edgeOutputs maps a capability TYPE to the ORDERED candidate output names whose
// value is its public edge, and whether emitting a target additionally requires
// the edge to be PUBLICLY exposed. It is CROSS-CLOUD: one vocabulary type is
// fulfilled by different clouds whose output names are per-cloud honest and
// differ (AWS Lambda functionUrl vs GCP Cloud Functions url; GCP Cloud Run uri
// vs Azure Container Apps fqdn), so a type carries MULTIPLE candidate names —
// the first present, usable one wins and the probe never needs to know which
// cloud built the edge. Adding a cloud is a data edit here (e.g. Azure's fqdn),
// never a change to Targets/Classify.
//
// gatePublic distinguishes two honesty models for "nothing measured on a
// private edge":
//   - false: output-PRESENCE is the gate. AWS CloudFront's domainName / Lambda's
//     functionUrl (and GCP Cloud Functions' url) exist ONLY for a real public
//     edge (a private function has no URL output), so a present output already
//     means public — no separate signal needed.
//   - true: the URL output exists even when the edge is PRIVATE (a Cloud Run
//     service always has a *.run.app uri regardless of ingress), so a target is
//     emitted only when the caller says the edge is publicly exposed. An
//     internal (ingress=internal) service yields NO target — the exact mirror of
//     AWS's no-public-output "nothing measured", never a false unknown.
func edgeOutputs(capType string) (cands []edgeCand, gatePublic bool, ok bool) {
	switch capType {
	case "capability.cdn.distribution":
		// AWS CloudFront: a bare edge host. GCP has no cdn.distribution fronting
		// edge (a refused gap), so nothing else lists here.
		return []edgeCand{{"domainName", false}}, false, true
	case "capability.function.serverless":
		// AWS Lambda functionUrl / GCP Cloud Functions gen2 url — both full URLs.
		//
		// This used to say they are "PUBLIC-only outputs (present only for a public
		// function), so output-presence is the gate", and that was simply untrue of
		// AWS (D537): a Function URL exists with AuthType AWS_IAM, which is the
		// CORRECT shape behind CloudFront/OAC — present, and deliberately private.
		// The probe therefore measured an origin whose 403 to an anonymous GET IS
		// the origin working, and reported the run BLOCKED. A field partner turned
		// the probe off over it and quoted our own rule: a signal that is always
		// red stops being a signal.
		//
		// Gated on exposure now, which D534 made a true input by measuring AuthType.
		return []edgeCand{{"functionUrl", true}, {"url", true}}, true, true
	case "capability.workload.container":
		// GCP Cloud Run uri (full *.run.app URL); Azure Container Apps fqdn (a
		// bare host) slots in here later. The uri exists regardless of ingress, so
		// a target is gated on public exposure — an internal service is private.
		return []edgeCand{{"uri", true}, {"fqdn", false}}, true, true
	}
	return nil, false, false
}

// Targets derives the edge URLs from the applied resources' OUTPUTS (D316) — no
// hand-passed target. capTypes maps capability id -> vocabulary type; outputs
// maps capability id -> (output name -> value); public maps capability id ->
// whether the edge is publicly exposed (consulted ONLY for types whose URL
// output exists even when private, e.g. Cloud Run). A capability is a target
// ONLY when its type has a public edge, any required public-exposure gate is
// satisfied, AND a backing output is present and usable. The result is sorted by
// capability for a deterministic order.
func Targets(capTypes map[string]string, outputs map[string]map[string]any, public map[string]bool) []Target {
	var ts []Target
	for capID, capType := range capTypes {
		cands, gatePublic, ok := edgeOutputs(capType)
		if !ok {
			continue
		}
		if gatePublic && !public[capID] {
			// the edge's URL output exists regardless of exposure, but it is not
			// public -> deliberately private, nothing measured (never a false
			// unknown), mirroring AWS's no-public-output.
			continue
		}
		outs := outputs[capID]
		if outs == nil {
			continue
		}
		for _, cand := range cands {
			raw, present := outs[cand.name]
			if !present {
				continue
			}
			s, _ := raw.(string)
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			u := s
			if !cand.fullURL {
				u = "https://" + strings.TrimSuffix(s, "/") + "/"
			}
			if _, err := url.ParseRequestURI(u); err != nil {
				continue // a malformed edge value is not a target we can honestly probe
			}
			ts = append(ts, Target{Capability: capID, URL: u, OutputName: cand.name})
			break // the first present, usable candidate wins
		}
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Capability < ts[j].Capability })
	return ts
}

// CapResult is one edge's reachability outcome, in three disjoint states.
type CapResult struct {
	Capability string  `json:"capability"`
	URL        string  `json:"url"`
	Verdict    Verdict `json:"verdict"`
	Cause      string  `json:"cause"`
	Status     int     `json:"status,omitempty"`
	// Checked names the SCOPE of the measurement, on every result including the
	// clean ones (D696) — a reader keying on `verdict` alone must be able to see,
	// in the same object, what "reachable" did and did not establish.
	Checked string `json:"checked"`
}

// Probe GETs every target and classifies it four-valued. Pure given the
// getter — the ONE network step, isolated for the httptest golden.
func Probe(g Getter, targets []Target) []CapResult {
	out := make([]CapResult, 0, len(targets))
	for _, t := range targets {
		status, err := g.Get(t.URL)
		v, cause := Classify(status, err)
		out = append(out, CapResult{Capability: t.Capability, URL: t.URL,
			Verdict: v, Cause: cause, Status: status, Checked: Checked})
	}
	return out
}

// Overall folds per-edge verdicts to the run verdict, worst-first: one failing
// edge makes the run failing, else one unknown makes it unknown, else reachable.
// Failing outranks unknown because it carries strictly more knowledge — "this is
// broken" is a measurement, "I could not tell" is the absence of one. Empty
// results have no verdict (the caller reports nothing).
func Overall(results []CapResult) Verdict {
	worst := Reachable
	for _, r := range results {
		switch r.Verdict {
		case Failing:
			return Failing
		case Unknown:
			worst = Unknown
		}
	}
	return worst
}

// Fold assigns every result to its rollup bucket and returns the run verdict.
//
// It exists because two renderers — `converge`'s phase output and the `probe` verb —
// each had their own copy of "which verdict means what", and D696 had to add a third
// state to both. A meaning kept in two places is a meaning that will disagree in one
// of them; the prose stays per-verb, the CLASSIFICATION lives here.
//
// A failing edge is a VIOLATION (something was measured and it is wrong), never an
// unknown (nothing was established). That distinction is the whole of this entry.
func Fold(results []CapResult) (violated, unknown []string, verdict Verdict) {
	for _, r := range results {
		switch r.Verdict {
		case Failing:
			violated = append(violated, r.Capability+" public edge is failing")
		case Unknown:
			if IsAnonymousDenied(r) {
				unknown = append(unknown, r.Capability+" public edge not anonymously reachable")
			} else {
				unknown = append(unknown, r.Capability+" public edge unreachable-from-here")
			}
		}
	}
	return violated, unknown, Overall(results)
}

// IsAnonymousDenied reports whether an unknown result came from a 401/403 — the
// edge answered but denied an ANONYMOUS request. This case warrants the
// multi-cause anonymous-reachability remediation (distinct from a transport
// failure, which cannot name origin-policy/auth causes).
func IsAnonymousDenied(r CapResult) bool {
	return r.Verdict == Unknown && (r.Status == 401 || r.Status == 403)
}

// Observation is a measured reachability fact to fold into the observation
// stream (D59 shape). Only a REACHABLE edge is a conclusive measured fact
// (reachable=true, with evidence); an UNKNOWN edge — INCLUDING a 401/403
// anonymous denial, which is ambiguous — measured nothing conclusive and is
// NEVER an observation (surfaced and exit-signalled only). A DECLARED
// anonymous-reachability constraint (Layer 2) is what turns a 403 into a real
// recorded violation.
type Observation struct {
	Capability string
	Value      bool
	Evidence   string
}

// Observations builds the observation set: one per reachable edge, none for
// unknown. Layer 2 (a declarable guardrail-dependency) consumes reachable=true
// as evidence the public path is confirmed; absence stays unknown and blocks.
func Observations(results []CapResult) []Observation {
	var obs []Observation
	for _, r := range results {
		switch r.Verdict {
		case Reachable:
			obs = append(obs, Observation{Capability: r.Capability, Value: true,
				Evidence: fmt.Sprintf("GET %s -> %s", r.URL, r.Cause)})
		case Failing:
			// D696: a confirmed failure is a MEASUREMENT — at this instant the edge
			// did not serve the public path — so it enters the observation stream as
			// false, with its evidence, where a declared constraint can be violated
			// by it. Unknown still records nothing: absence of knowledge is not a
			// reading, and writing one would be the collapse this entry undoes.
			obs = append(obs, Observation{Capability: r.Capability, Value: false,
				Evidence: fmt.Sprintf("GET %s -> %s", r.URL, r.Cause)})
		}
	}
	return obs
}

// AnonymousRemediation is the operator-facing text for a 401/403 — an edge that
// denied an ANONYMOUS probe. It is MULTI-CAUSE and NON-ACCUSATORY: Layer 1
// measured a denial but must NOT blame one cause. Blaming an org RCP is a false
// accusation (the client's live 403 was a missing grant action, not an RCP),
// and a 403 is EXPECTED on an auth-gated public API. Naming which cause applies
// is an environment decision.
const AnonymousRemediation = "the edge returned HTTP 401/403 to an anonymous " +
	"request — the public path is not anonymously reachable. Likely causes: " +
	"(a) the origin's resource policy does not permit the caller — e.g. an AWS " +
	"Lambda Function URL created after the Oct-2025 change requires BOTH " +
	"lambda:InvokeFunctionUrl AND lambda:InvokeFunction in the grant; (b) the " +
	"path requires authentication (a 403 to an unauthenticated probe is expected " +
	"— use --no-reachability or declare the expectation); (c) an org guardrail/RCP " +
	"denies the principal. Groundhold measured the denial; determining which " +
	"cause applies is an environment decision."
