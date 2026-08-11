package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func readJSON6(r *http.Request) map[string]any {
	b, _ := io.ReadAll(r.Body)
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

func apigwAttrs() map[string]any {
	return map[string]any{
		"location.region": "eu-central-1",
		"protocol":        "http",
		"service.managed": true,
	}
}

func TestBuildApiGWv2Honors(t *testing.T) {
	p, err := BuildApiGWv2("prod", "front", apigwAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.ProtocolType != "HTTP" || !strings.HasPrefix(p.Name, "pv-") {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("front", "prod")
	if body["protocolType"] != "HTTP" || body["routeSelectionExpression"] != nil {
		t.Fatalf("http body must have no route-selection expr: %+v", body)
	}
	// D878: the wire is restJson1 camelCase. A PascalCase key is dropped by AWS and
	// the create 400s "Invalid protocol specified" — pin the exact key set so a
	// mutation back to Name/ProtocolType/Tags is caught at the desk, not on a real run.
	for _, k := range []string{"name", "protocolType", "tags"} {
		if _, ok := body[k]; !ok {
			t.Fatalf("createBody missing camelCase key %q (real AWS locationName): %+v", k, body)
		}
	}
	for _, k := range []string{"Name", "ProtocolType", "Tags"} {
		if _, ok := body[k]; ok {
			t.Fatalf("createBody emits PascalCase %q — AWS ignores it (D878): %+v", k, body)
		}
	}
}

func TestBuildApiGWv2WebSocket(t *testing.T) {
	a := apigwAttrs()
	a["protocol"] = "websocket"
	p, err := BuildApiGWv2("prod", "front", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	body := p.createBody("front", "prod")
	if body["protocolType"] != "WEBSOCKET" || body["routeSelectionExpression"] == nil {
		t.Fatalf("websocket body must carry a route-selection expr: %+v", body)
	}
}

func TestBuildApiGWv2Refusals(t *testing.T) {
	cases := map[string]map[string]any{
		"bad-protocol": {"protocol": "carrier-pigeon"},
		"unmanaged":    {"service.managed": false},
		"unknown-attr": {"api.tier": "x"},
	}
	for name, extra := range cases {
		a := apigwAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildApiGWv2("prod", "front", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := apigwAttrs()
	delete(a, "protocol")
	if _, err := BuildApiGWv2("prod", "front", a, nil, 1); err == nil {
		t.Error("missing protocol must refuse")
	}
}

func apigwServer(t *testing.T, capLabel, protocol string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/v2/apis"):
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`{"apiId":"a1b2c3d4e5","name":"pv","protocolType":"` + protocol + `","apiEndpoint":"https://a1b2c3d4e5.execute-api.eu-central-1.amazonaws.com"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/v2/apis/"):
				_, _ = w.Write([]byte(`{"apiId":"a1b2c3d4e5","name":"pv","protocolType":"` + protocol + `",` +
					`"tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"}}`))
			case r.Method == "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func apigwDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	d.APIGatewayBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteApiGWv2(t *testing.T) {
	srv := apigwServer(t, "front", "HTTP")
	defer srv.Close()
	d := apigwDriver(t, srv)
	res := d.createApiGWv2("eu-central-1", "000000000000", "prod", "front", apigwAttrs(), nil, 1)
	if res.Status != "succeeded" || res.ProviderID != "apigw:eu-central-1:000000000000:a1b2c3d4e5" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeApiGWv2("front", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eu-central-1" || got["protocol"] != "http" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteApiGWv2("front", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteApiGWv2ForeignRefused(t *testing.T) {
	srv := apigwServer(t, "someone-else", "HTTP")
	defer srv.Close()
	d := apigwDriver(t, srv)
	pid := apigwProviderID("eu-central-1", "000000000000", "a1b2c3d4e5")
	res := d.deleteApiGWv2("front", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign api must refuse delete, got %+v", res)
	}
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.apigateway.http on AWS API Gateway v2. A STATEFUL fake records the
// ProtocolType the create writes and reflects it on the get read.
func TestMetamorphicApiGWv2RoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		protocol string
		sent     string
		want     string
	}{
		{"http", "http", "HTTP", "http"},
		{"websocket", "websocket", "WEBSOCKET", "websocket"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var proto string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == "POST":
						proto = readJSON6(r)["protocolType"].(string)
						w.WriteHeader(201)
						_, _ = w.Write([]byte(`{"apiId":"a1b2c3d4e5","protocolType":"` + proto + `"}`))
					case r.Method == "GET":
						_, _ = w.Write([]byte(`{"apiId":"a1b2c3d4e5","protocolType":"` + proto + `",` +
							`"tags":{"groundhold-capability":"front","groundhold-environment":"prod"}}`))
					default:
						w.WriteHeader(200)
					}
				}))
			defer srv.Close()
			d := apigwDriver(t, srv)
			a := apigwAttrs()
			a["protocol"] = c.protocol
			res := d.createApiGWv2("eu-central-1", "000000000000", "prod", "front", a, nil, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			if proto != c.sent {
				t.Errorf("create sent ProtocolType %q, want %q", proto, c.sent)
			}
			obs, _, err := d.observeApiGWv2("front", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["protocol"] != c.want {
				t.Errorf("protocol round-trip: want %q got %v", c.want, got["protocol"])
			}
		})
	}
}

// apigwExistingServer: our API is already standing at our deterministic name, so the
// list-by-name scan finds it. Any mutation is the duplicate this fixture exists to catch.
func apigwExistingServer(t *testing.T, name, capLabel string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/v2/apis"):
				_, _ = w.Write([]byte(`{"items":[{"apiId":"a1b2c3d4e5","name":"` + name +
					`","protocolType":"HTTP","apiEndpoint":"https://a1b2c3d4e5.execute-api.eu-central-1.amazonaws.com",` +
					`"tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"}}]}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/v2/apis/"):
				_, _ = w.Write([]byte(`{"apiId":"a1b2c3d4e5","name":"` + name + `","protocolType":"HTTP",` +
					`"tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"}}`))
			default:
				t.Errorf("create-adoption must not %s %s — bind the existing api, never create",
					r.Method, r.URL.Path)
				w.WriteHeader(400)
			}
		}))
}

// TestCreateApiGWv2_AdoptsExistingOwned (D410): the bug this fixes. An ApiId is
// server-assigned and CreateApi carries no idempotency token, so before the by-name scan
// a converge against a lost ledger either minted a SECOND live endpoint or hard-failed
// on an estate that was already correct.
func TestCreateApiGWv2_AdoptsExistingOwned(t *testing.T) {
	name := ApiGWName("prod", "front", 1)
	srv := apigwExistingServer(t, name, sanitizeTag("front"))
	defer srv.Close()
	d := apigwDriver(t, srv)
	res := d.createApiGWv2("eu-central-1", "000000000000", "prod", "front", apigwAttrs(), nil, 1)
	if res.Status != "succeeded" ||
		res.ProviderID != apigwProviderID("eu-central-1", "000000000000", "a1b2c3d4e5") {
		t.Fatalf("must adopt the existing owned api (no CreateApi), got %+v", res)
	}
}

// TestCreateApiGWv2_ForeignAtOurNameRefused (D410): an api at our deterministic name
// whose tags are not ours must be refused, never adopted and never overwritten.
func TestCreateApiGWv2_ForeignAtOurNameRefused(t *testing.T) {
	name := ApiGWName("prod", "front", 1)
	srv := apigwExistingServer(t, name, "someone-else")
	defer srv.Close()
	d := apigwDriver(t, srv)
	res := d.createApiGWv2("eu-central-1", "000000000000", "prod", "front", apigwAttrs(), nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign api at our name must refuse, got %+v", res)
	}
}

func apigwRESTRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingApiGWv2 enrols apigateway in the D391 class gate — the enrolment
// that found the bug.
func TestAdoptsExistingApiGWv2(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	name := ApiGWName("prod", "front", 1)
	p := &certifynet.ExistingProbe{
		Name:           "aws/apigateway",
		Classify:       apigwRESTRole,
		ExistingServer: func() *httptest.Server { return apigwExistingServer(t, name, sanitizeTag("front")) },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.APIGatewayBaseURL = happyURL
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("apigateway", "front", "prod", apigwAttrs(), nil, "api", 1)
		},
		PID: apigwProviderID("eu-central-1", "000000000000", "a1b2c3d4e5"),
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
