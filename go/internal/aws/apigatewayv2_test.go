package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	if body["ProtocolType"] != "HTTP" || body["RouteSelectionExpression"] != nil {
		t.Fatalf("http body must have no route-selection expr: %+v", body)
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
	if body["ProtocolType"] != "WEBSOCKET" || body["RouteSelectionExpression"] == nil {
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
				_, _ = w.Write([]byte(`{"ApiId":"a1b2c3d4e5","Name":"pv","ProtocolType":"` + protocol + `","ApiEndpoint":"https://a1b2c3d4e5.execute-api.eu-central-1.amazonaws.com"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/v2/apis/"):
				_, _ = w.Write([]byte(`{"ApiId":"a1b2c3d4e5","Name":"pv","ProtocolType":"` + protocol + `",` +
					`"Tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"}}`))
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
						proto = readJSON6(r)["ProtocolType"].(string)
						w.WriteHeader(201)
						_, _ = w.Write([]byte(`{"ApiId":"a1b2c3d4e5","ProtocolType":"` + proto + `"}`))
					case r.Method == "GET":
						_, _ = w.Write([]byte(`{"ApiId":"a1b2c3d4e5","ProtocolType":"` + proto + `",` +
							`"Tags":{"groundhold-capability":"front","groundhold-environment":"prod"}}`))
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
