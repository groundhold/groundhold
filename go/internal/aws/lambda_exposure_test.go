package aws

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"groundhold/internal/provider"
)

// D534, from the field, on live production. A Function URL with `AuthType:
// AWS_IAM` behind CloudFront/OAC is a CORRECT hardening: anonymous access is cut
// off deliberately, and only the CDN may call the origin through SigV4. The driver
// observed `network.publicExposure: true` for it anyway, because it treated "a
// Function URL exists" as "publicly exposed" without reading AuthType.
//
// The vocabulary is unambiguous and says the opposite. The attribute is
// "whether the function is invokable over public HTTPS by ANYONE (an
// UNAUTHENTICATED public endpoint)", and its aws.lambda mapping reads: "a Function
// URL with AuthType NONE plus a resource-based lambda:InvokeFunctionUrl grant to
// principal * (BOTH, or the function stays private)". The observation contradicted
// the mapping it claims to implement.
//
// The consequence was not cosmetic. Declaring the true value (`false`) would have
// created a diff against the observation, and the repair action deletes the
// Function URL — which is the CloudFront origin. The partner worked out that trap
// from the observations before acting, and wrote "do NOT silence the probe with a
// declaration".
func TestPublicExposureIsFalseWhenTheURLRequiresIAM(t *testing.T) {
	srv := lambdaExposureServer(t, "AWS_IAM", false)
	defer srv.Close()
	d := lambdaExposureDriver(srv)

	obs, diags, err := d.observeLambda("api", lambdaProviderID("eu-central-1", "000000000000", "api-abcdefgh"))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := obsValue(obs, "network.publicExposure")
	if !ok {
		t.Fatalf("publicExposure not observed at all: diags=%v", diags)
	}
	if got != false {
		t.Errorf("publicExposure = %v for a Function URL with AuthType AWS_IAM.\n"+
			"The vocabulary defines this as an UNAUTHENTICATED public endpoint; a URL "+
			"only the CDN may sign for is not one. Declaring the truth would plan the "+
			"deletion of the origin.", got)
	}
}

// AuthType NONE alone is not public either: the mapping requires the anonymous
// invoke grant too, and without it the world still cannot call the URL.
func TestPublicExposureNeedsBothTheAuthTypeAndTheGrant(t *testing.T) {
	srv := lambdaExposureServer(t, "NONE", false) // no principal:* grant
	defer srv.Close()
	d := lambdaExposureDriver(srv)

	obs, _, err := d.observeLambda("api", lambdaProviderID("eu-central-1", "000000000000", "api-abcdefgh"))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := obsValue(obs, "network.publicExposure"); ok && got != false {
		t.Errorf("publicExposure = %v with AuthType NONE and no anonymous grant — "+
			"the mapping requires BOTH", got)
	}
}

// The genuinely public shape must still read true, or the fix would hide a real
// exposure — the more dangerous direction of the same mistake.
func TestPublicExposureIsTrueWhenAnonymousInvokeIsGranted(t *testing.T) {
	srv := lambdaExposureServer(t, "NONE", true)
	defer srv.Close()
	d := lambdaExposureDriver(srv)

	obs, _, err := d.observeLambda("api", lambdaProviderID("eu-central-1", "000000000000", "api-abcdefgh"))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := obsValue(obs, "network.publicExposure")
	if !ok || got != true {
		t.Errorf("publicExposure = %v (observed=%v) for AuthType NONE with a "+
			"principal:* invoke grant — that IS a public endpoint", got, ok)
	}
}

func obsValue(obs []provider.Observation, path string) (any, bool) {
	for _, o := range obs {
		if o.Path == path {
			return o.Value, true
		}
	}
	return nil, false
}

// lambdaExposureServer answers only the routes AWS actually has, by EXACT path.
//
// D694: it used to match on `HasSuffix(path, "/policy")`, so it answered the policy
// read whatever API version the driver asked for — and the driver was asking
// `/2021-10-31`, a route Lambda does not have. Live AWS returned 404, the reader took
// that for "no resource policy", and every anonymously-invokable Function URL was
// observed as private. No test in this package could see it: a fixture that matches by
// suffix cannot tell a right route from a wrong one, which makes it a fixture for the
// shape of the request and not for the request.
func lambdaExposureServer(t *testing.T, authType string, anonGrant bool) *httptest.Server {
	t.Helper()
	const fn = "api-abcdefgh"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/2021-10-31/functions/" + fn + "/url":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"AuthType": authType, "FunctionUrl": "https://x.lambda-url.eu-central-1.on.aws/"})
		case "/2015-03-31/functions/" + fn + "/policy":
			if !anonGrant {
				http.Error(w, `{"Type":"User","message":"ResourceNotFoundException"}`, http.StatusNotFound)
				return
			}
			pol := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",` +
				`"Action":"lambda:InvokeFunctionUrl"}]}`
			_ = json.NewEncoder(w).Encode(map[string]any{"Policy": pol})
		case "/2015-03-31/functions/" + fn:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Configuration": map[string]any{
					"State": "Active", "Timeout": 30, "MemorySize": 128,
					"Role":        "arn:aws:iam::000000000000:role/x",
					"FunctionArn": "arn:aws:lambda:eu-central-1:000000000000:function:api-abcdefgh",
				},
				"Tags": map[string]any{
					"groundhold-capability": "api", "groundhold-environment": "prod"},
			})
		default:
			// AWS answers a route it does not have with a 4xx, which a reader can
			// mistake for "the thing you asked about does not exist". Here it is a
			// test failure by name, so a driver asking the wrong URL says so.
			t.Errorf("driver requested %s %s — Lambda has no such route", r.Method, r.URL.Path)
			http.Error(w, `{"message":"Missing Authentication Token"}`, http.StatusForbidden)
		}
	}))
}

func lambdaExposureDriver(srv *httptest.Server) *Driver {
	return newLambdaHonestyDriver(srv.URL, http.DefaultTransport)
}
