package reach

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestClassifyHTTP is the httptest golden: a real HTTP round-trip through the
// production getter for each status class, pinning the verdict and that the
// cause is NAMED (never bare). The honesty crux: a 403 is unknown (an ambiguous
// anonymous denial), never a success and never a confident accusation.
func TestClassifyHTTP(t *testing.T) {
	cases := []struct {
		status int
		want   Verdict
	}{
		{200, Reachable},
		{204, Reachable},
		{301, Reachable}, // a redirect IS a reachable edge (not chased)
		{302, Reachable},
		{401, Unknown}, // an anonymous denial is AMBIGUOUS — never a confident accusation
		{403, Unknown},
		{404, Unknown}, // answered, but not confirming the public path
		// D696: a 5xx is the edge saying it failed. No policy reads that way and no
		// vantage point produces it, so it is the third state — not the absence of
		// knowledge that `unknown` means.
		{500, Failing},
		{503, Failing},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tc.status) }))
		g := httpGetter{client: &http.Client{Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			}}}
		status, err := g.Get(srv.URL)
		srv.Close()
		v, cause := Classify(status, err)
		if v != tc.want {
			t.Errorf("status %d: verdict = %q, want %q", tc.status, v, tc.want)
		}
		if strings.TrimSpace(cause) == "" {
			t.Errorf("status %d: cause is empty — must always be named", tc.status)
		}
		// a 403 must NEVER read as success
		if tc.status == 403 && v == Reachable {
			t.Fatalf("403 classified reachable — a denial must never read as success")
		}
	}
}

// TestClassifyTransport pins the transport-failure branch. None of it is ever a
// DENIAL; D696 splits it by whether the failure admits a second reading.
//
// The three that stay unknown are the point of the test: minutes after a create,
// NXDOMAIN is propagation, a refused connection is an edge still provisioning, and a
// timeout is a firewalled vantage point. Calling any of them a confirmed failure would
// be a confident accusation — the same error this package refuses in the other
// direction, wearing the opposite sign.
func TestClassifyTransport(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want Verdict
	}{
		{"refused", Unknown}, // an edge may still be provisioning
		{"dns", Unknown},     // propagation, or split-horizon DNS
		{"timeout", Unknown}, // a firewalled vantage point
		// A certificate that does not verify is not a policy and not a propagation
		// delay: the edge is there and the connection to it is broken.
		{"tls", Failing},
	} {
		status, err := FakeGetter(tc.spec).Get("https://edge.invalid/")
		v, cause := Classify(status, err)
		if v != tc.want {
			t.Errorf("%s: verdict = %q, want %q", tc.spec, v, tc.want)
		}
		if v == Reachable {
			t.Errorf("%s: a transport failure must never read as success", tc.spec)
		}
		if strings.TrimSpace(cause) == "" {
			t.Errorf("%s: cause is empty — never a bare 'unreachable' (D306)", tc.spec)
		}
	}
}

// TestClassifyRealRefused drives the PRODUCTION getter against a closed port so
// a real connection-refused error flows through networkCause, not only the fake.
func TestClassifyRealRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {}))
	addr := srv.URL
	srv.Close() // now nothing listens on that port
	g := httpGetter{client: &http.Client{Timeout: 2 * time.Second}}
	status, err := g.Get(addr)
	if err == nil {
		t.Skip("port was reused before the probe — environment-dependent")
	}
	v, cause := Classify(status, err)
	if v != Unknown {
		t.Fatalf("a refused connection must be unknown, got %q (%s)", v, cause)
	}
}

func TestTargetsFromOutputs(t *testing.T) {
	capTypes := map[string]string{
		"cdn": "capability.cdn.distribution",
		"fn":  "capability.function.serverless",
		"db":  "capability.database.relational", // not a public edge
	}
	outputs := map[string]map[string]any{
		"cdn": {"domainName": "d111.cloudfront.net"},
		"fn":  {"functionUrl": "https://abc.lambda-url.eu-central-1.on.aws/"},
		"db":  {"endpoint": "db.internal"},
	}
	// D537: a serverless edge is gated on DECLARED public exposure now, because a
	// Function URL exists for a private (AuthType AWS_IAM) function too. Passing
	// nil used to mean "probe it anyway"; it now means "nobody said it is public".
	ts := Targets(capTypes, outputs, map[string]bool{"fn": true})
	if len(ts) != 2 {
		t.Fatalf("expected 2 edge targets (cdn, fn), got %d: %+v", len(ts), ts)
	}
	// sorted by capability: cdn first
	if ts[0].Capability != "cdn" || ts[0].URL != "https://d111.cloudfront.net/" {
		t.Errorf("cdn target wrong: %+v", ts[0])
	}
	if ts[1].Capability != "fn" || ts[1].URL != "https://abc.lambda-url.eu-central-1.on.aws/" {
		t.Errorf("fn target wrong: %+v", ts[1])
	}
}

// TestTargetsCrossCloud: the cross-cloud recognition. GCP Cloud Run
// (workload.container) publishes its edge as `uri` and GCP Cloud Functions
// (function.serverless) as `url` — DIFFERENT output names than AWS's
// functionUrl/domainName — and Targets recognizes both via the multi-name
// candidate list. Azure's fqdn would slot in the same way.
func TestTargetsCrossCloud(t *testing.T) {
	capTypes := map[string]string{
		"cr":  "capability.workload.container",  // GCP Cloud Run -> uri
		"gfn": "capability.function.serverless", // GCP Cloud Functions -> url
		"cdn": "capability.cdn.distribution",    // AWS CloudFront -> domainName
	}
	outputs := map[string]map[string]any{
		"cr":  {"uri": "https://svc-abc123-ew.a.run.app"},
		"gfn": {"url": "https://fn-abc123-ew.a.run.app"},
		"cdn": {"domainName": "d111.cloudfront.net"},
	}
	// Cloud Run's uri and the serverless url both exist regardless of exposure, so
	// both are gated on the public map (D537 — a Lambda Function URL exists for an
	// AuthType AWS_IAM function too, which the old comment here got wrong). Only
	// the cdn domainName is output-presence gated: a distribution IS the public path.
	public := map[string]bool{"cr": true, "gfn": true}
	ts := Targets(capTypes, outputs, public)
	if len(ts) != 3 {
		t.Fatalf("expected 3 cross-cloud targets, got %d: %+v", len(ts), ts)
	}
	byCap := map[string]Target{}
	for _, tt := range ts {
		byCap[tt.Capability] = tt
	}
	if got := byCap["cr"]; got.URL != "https://svc-abc123-ew.a.run.app" || got.OutputName != "uri" {
		t.Errorf("cloud run target wrong: %+v", got)
	}
	if got := byCap["gfn"]; got.URL != "https://fn-abc123-ew.a.run.app" || got.OutputName != "url" {
		t.Errorf("cloud function target wrong: %+v", got)
	}
	if got := byCap["cdn"]; got.URL != "https://d111.cloudfront.net/" || got.OutputName != "domainName" {
		t.Errorf("cloudfront target wrong: %+v", got)
	}
}

// TestPublicGateSuppressesInternalContainer: an internal Cloud Run (its uri
// output is present, but network.publicExposure is false/absent) yields NO
// target — the exact mirror of AWS's no-public-output "nothing measured", never
// a false unknown.
func TestPublicGateSuppressesInternalContainer(t *testing.T) {
	capTypes := map[string]string{"cr": "capability.workload.container"}
	outputs := map[string]map[string]any{"cr": {"uri": "https://svc-abc123-ew.a.run.app"}}
	// public map empty -> internal
	if ts := Targets(capTypes, outputs, nil); len(ts) != 0 {
		t.Fatalf("internal container must yield no target, got %+v", ts)
	}
	// explicitly public -> a target
	if ts := Targets(capTypes, outputs, map[string]bool{"cr": true}); len(ts) != 1 {
		t.Fatalf("public container must yield one target, got %+v", ts)
	}
}

// TestTargetsAzureContainerAppFQDN: an Azure Container App fulfils
// workload.container and publishes its edge as the BARE `fqdn` output (not a full
// URL, and a DIFFERENT name than Cloud Run's uri) — Targets recognizes it via the
// existing multi-name candidate list and wraps it into https://<host>/. Like
// Cloud Run, the fqdn exists regardless of exposure, so a target is gated on the
// public map: a public app is probed, an internal one yields nothing (no false
// unknown). Proves the Azure edge needs NO reach-core change.
func TestTargetsAzureContainerAppFQDN(t *testing.T) {
	capTypes := map[string]string{"aca": "capability.workload.container"}
	outputs := map[string]map[string]any{
		"aca": {"fqdn": "app.happyhill-1a2b3c4d.westeurope.azurecontainerapps.io"},
	}
	// public -> one probed target on the wrapped https URL
	ts := Targets(capTypes, outputs, map[string]bool{"aca": true})
	if len(ts) != 1 {
		t.Fatalf("public Azure container app must yield one target, got %+v", ts)
	}
	if ts[0].OutputName != "fqdn" ||
		ts[0].URL != "https://app.happyhill-1a2b3c4d.westeurope.azurecontainerapps.io/" {
		t.Fatalf("azure fqdn target wrong: %+v", ts[0])
	}
	// internal (public map empty) -> nothing to probe
	if ts := Targets(capTypes, outputs, nil); len(ts) != 0 {
		t.Fatalf("internal Azure container app must yield no target, got %+v", ts)
	}
}

// TestNoOutputNoTarget: a public-edge capability with no backing output yields
// NO target — nothing measured, nothing emitted (probe.failed discipline).
func TestNoOutputNoTarget(t *testing.T) {
	ts := Targets(
		map[string]string{"cdn": "capability.cdn.distribution"},
		map[string]map[string]any{"cdn": {"distributionArn": "arn:..."}}, // no domainName
		nil,
	)
	if len(ts) != 0 {
		t.Fatalf("no domainName output => no target, got %+v", ts)
	}
}

// TestObservationsAndFold: only a reachable edge is a recorded measured fact; a
// 401/403 anonymous denial and a transport failure are BOTH unknown and record
// NOTHING (an ambiguous denial is not a conclusive measurement). A 403 carries
// the anonymous-denial marker so the fold can attach the multi-cause remediation.
func TestObservationsAndFold(t *testing.T) {
	results := []CapResult{
		{Capability: "a", Verdict: Reachable, URL: "https://a/", Cause: "HTTP 200"},
		{Capability: "b", Verdict: Unknown, Status: 403, URL: "https://b/", Cause: "HTTP 403 anon"},
		{Capability: "c", Verdict: Unknown, URL: "https://c/", Cause: "timeout"},
	}
	obs := Observations(results)
	if len(obs) != 1 {
		t.Fatalf("only reachable is an observation, got %d: %+v", len(obs), obs)
	}
	if obs[0].Capability != "a" || obs[0].Value != true {
		t.Errorf("reachable must record value true, got %+v", obs[0])
	}
	if !IsAnonymousDenied(results[1]) {
		t.Error("a 401/403 unknown must be flagged as an anonymous denial (for the remediation)")
	}
	if IsAnonymousDenied(results[2]) {
		t.Error("a transport-failure unknown is NOT an anonymous denial")
	}
	if Overall(results) != Unknown {
		t.Errorf("any unknown makes the run unknown, got %q", Overall(results))
	}
}
