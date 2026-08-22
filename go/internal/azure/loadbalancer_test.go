package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"groundhold/internal/provider"
)

// JSON doubles for the ARM GET bodies (the reverse-map fixtures).
const (
	// L4 loadBalancer with a PUBLIC frontend -> publicExposure=true, inTransit=false.
	lbPublicJSON = `{"location":"eastus","tags":{},"properties":{"frontendIPConfigurations":[` +
		`{"name":"fe","properties":{"publicIPAddress":{"id":"/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/pip"}}}]}}`
	// L4 loadBalancer that is INTERNAL (private frontend only) -> publicExposure=false.
	lbInternalJSON = `{"location":"eastus","tags":{},"properties":{"frontendIPConfigurations":[` +
		`{"name":"fe","properties":{"privateIPAddress":"10.0.0.4","privateIPAllocationMethod":"Static"}}]}}`
	// L7 applicationGateway with a PUBLIC frontend AND an HTTPS listener ->
	// publicExposure=true, inTransit=true.
	agwHTTPSJSON = `{"location":"eastus","properties":{"frontendIPConfigurations":[` +
		`{"name":"fe","properties":{"publicIPAddress":{"id":"/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/agwpip"}}}],` +
		`"httpListeners":[{"name":"l1","properties":{"protocol":"Https"}}]}}`
)

// lbFake is the fake ARM control plane: it asserts the bearer on every call and
// routes subscription-scope LISTs and per-resource GETs for both LB types.
func lbFake(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer test-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			p := r.URL.Path
			switch {
			// per-resource GETs first (more specific paths).
			case strings.HasSuffix(p, "/loadBalancers/pv-lb"):
				_, _ = w.Write([]byte(lbPublicJSON))
			case strings.HasSuffix(p, "/loadBalancers/pv-lb-internal"):
				_, _ = w.Write([]byte(lbInternalJSON))
			case strings.HasSuffix(p, "/applicationGateways/pv-agw"):
				_, _ = w.Write([]byte(agwHTTPSJSON))
			// subscription-scope LISTs.
			case strings.HasSuffix(p, "/providers/Microsoft.Network/loadBalancers"):
				_, _ = w.Write([]byte(`{"value":[{"id":"/subscriptions/` + testSub +
					`/resourceGroups/rg1/providers/Microsoft.Network/loadBalancers/pv-lb","name":"pv-lb","location":"eastus"}]}`))
			case strings.HasSuffix(p, "/providers/Microsoft.Network/applicationGateways"):
				_, _ = w.Write([]byte(`{"value":[{"id":"/subscriptions/` + testSub +
					`/resourceGroups/rg1/providers/Microsoft.Network/applicationGateways/pv-agw","name":"pv-agw","location":"eastus"}]}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
}

func lbTestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	return d
}

func obsMap(t *testing.T, obs []provider.Observation) map[string]any {
	t.Helper()
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	return m
}

func TestObserveLoadBalancerL4Public(t *testing.T) {
	srv := lbFake(t)
	defer srv.Close()
	d := lbTestDriver(t, srv)

	obs, _, err := d.observeLoadBalancer("", lbProviderID(testSub, "rg1", "pv-lb"))
	if err != nil {
		t.Fatal(err)
	}
	got := obsMap(t, obs)
	if got["network.publicExposure"] != true {
		t.Fatalf("public L4 LB must expose publicExposure=true, got %+v", got)
	}
	if got["encryption.inTransit"] != false {
		t.Fatalf("an L4 LB does not terminate TLS: inTransit must be false, got %+v", got)
	}
	if got["service.managed"] != true {
		t.Fatalf("service.managed must be true, got %+v", got)
	}
}

func TestObserveLoadBalancerL4Internal(t *testing.T) {
	srv := lbFake(t)
	defer srv.Close()
	d := lbTestDriver(t, srv)

	obs, _, err := d.observeLoadBalancer("", lbProviderID(testSub, "rg1", "pv-lb-internal"))
	if err != nil {
		t.Fatal(err)
	}
	got := obsMap(t, obs)
	if got["network.publicExposure"] != false {
		t.Fatalf("internal LB (no public frontend) must be publicExposure=false, got %+v", got)
	}
}

func TestObserveAppGatewayHTTPS(t *testing.T) {
	srv := lbFake(t)
	defer srv.Close()
	d := lbTestDriver(t, srv)

	obs, _, err := d.observeLoadBalancer("", agwProviderID(testSub, "rg1", "pv-agw"))
	if err != nil {
		t.Fatal(err)
	}
	got := obsMap(t, obs)
	if got["network.publicExposure"] != true {
		t.Fatalf("public App Gateway must be publicExposure=true, got %+v", got)
	}
	if got["encryption.inTransit"] != true {
		t.Fatalf("an HTTPS-listener App Gateway must be inTransit=true, got %+v", got)
	}
}

func TestDiscoverLoadBalancers(t *testing.T) {
	srv := lbFake(t)
	defer srv.Close()
	d := lbTestDriver(t, srv)

	found, _, err := d.discoverLoadBalancers("eastus")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("expected 2 discovered (L4 + L7), got %d: %+v", len(found), found)
	}
	byPID := map[string]provider.Discovered{}
	for _, f := range found {
		if f.ResourceType != "capability.network.loadbalancer" {
			t.Fatalf("resource type = %q, want capability.network.loadbalancer", f.ResourceType)
		}
		byPID[f.ProviderID] = f
	}
	l4, ok := byPID[lbProviderID(testSub, "rg1", "pv-lb")]
	if !ok {
		t.Fatalf("L4 load balancer not discovered: %+v", byPID)
	}
	if obsMap(t, l4.Observations)["network.publicExposure"] != true {
		t.Fatalf("discovered L4 LB should be public, got %+v", l4.Observations)
	}
	l7, ok := byPID[agwProviderID(testSub, "rg1", "pv-agw")]
	if !ok {
		t.Fatalf("L7 app gateway not discovered: %+v", byPID)
	}
	if obsMap(t, l7.Observations)["encryption.inTransit"] != true {
		t.Fatalf("discovered HTTPS app gateway should be inTransit=true, got %+v", l7.Observations)
	}
}

// ---- FULL PROVISIONING: App Gateway create -> observe -> delete -------------

// agwProvisionFake is a stateful fake ARM control plane for the applicationGateways
// lifecycle: it asserts the bearer on every call, captures the PUT body, and serves
// a faithful GET (the PUT body with provisioningState=Succeeded injected) so
// observe/delete round-trip on what was created. putStatus tips the create into an
// ambiguous/failed branch.
type agwProvisionFake struct {
	mu        sync.Mutex
	putBody   []byte
	getDoc    string
	putStatus int // 0 => 200
}

func (f *agwProvisionFake) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.Contains(r.URL.Path, "/applicationGateways/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case "PUT":
			buf, _ := io.ReadAll(r.Body)
			f.putBody = buf
			if f.putStatus != 0 && f.putStatus != 200 {
				w.WriteHeader(f.putStatus)
				_, _ = w.Write([]byte(`{"error":"boom"}`))
				return
			}
			// build a faithful GET doc: the PUT body + provisioningState Succeeded.
			var m map[string]any
			_ = json.Unmarshal(buf, &m)
			if props, ok := m["properties"].(map[string]any); ok {
				props["provisioningState"] = "Succeeded"
			}
			out, _ := json.Marshal(m)
			f.getDoc = string(out)
			_, _ = w.Write([]byte(f.getDoc))
		case "GET":
			if f.getDoc == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(f.getDoc))
		case "DELETE":
			f.getDoc = ""
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
}

func agwProvisionDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 5 * time.Second
	return d
}

// A PUBLIC HTTP App Gateway: create assembles the composite, observe reads
// publicExposure=true / inTransit=false, delete round-trips through ownership.
func TestCreateAppGatewayPublicHTTP(t *testing.T) {
	f := &agwProvisionFake{}
	srv := f.server(t)
	defer srv.Close()
	d := agwProvisionDriver(t, srv)

	attrs := map[string]any{
		"location.region":        "eastus",
		"network.publicExposure": true,
		"encryption.inTransit":   false,
		"service.managed":        true,
	}
	impl := map[string]any{
		"resource_group": "rg1",
		"subnetId":       "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vn/subnets/agw",
		"publicIpId":     "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/pip",
		"backendFqdns":   []any{"app.example.com"},
	}
	res := d.Create("loadbalancer", "edge", "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("public HTTP gateway create must succeed, got %+v", res)
	}
	if !strings.HasPrefix(res.ProviderID, "appgateway:") {
		t.Fatalf("providerId must be appgateway-kind, got %q", res.ProviderID)
	}
	// assert the body shape: public frontend, Http listener, backend target.
	body := string(f.putBody)
	for _, want := range []string{`"publicIPAddress"`, `"protocol":"Http"`,
		`"requestRoutingRules"`, `"backendAddressPools"`, `"app.example.com"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("App Gateway body missing %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "keyVaultSecretId") || strings.Contains(body, `"Https"`) {
		t.Fatalf("HTTP gateway must not carry an SSL cert or Https listener:\n%s", body)
	}

	obs, _, err := d.observeLoadBalancer("", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := obsMap(t, obs)
	if got["network.publicExposure"] != true {
		t.Fatalf("observe must see publicExposure=true, got %+v", got)
	}
	if got["encryption.inTransit"] != false {
		t.Fatalf("HTTP gateway observe must see inTransit=false, got %+v", got)
	}

	del := d.Delete("loadbalancer", "edge", "prod", res.ProviderID, "k")
	if del.Status != "succeeded" {
		t.Fatalf("owned gateway delete must succeed, got %+v", del)
	}
}

// A PUBLIC HTTPS App Gateway: the Https listener + SSL cert REFERENCE case. The
// body carries keyVaultSecretId (a REFERENCE, never cert bytes) and an Https
// listener; observe reads inTransit=true.
func TestCreateAppGatewayHTTPSCert(t *testing.T) {
	f := &agwProvisionFake{}
	srv := f.server(t)
	defer srv.Close()
	d := agwProvisionDriver(t, srv)

	attrs := map[string]any{
		"location.region":        "eastus",
		"network.publicExposure": true,
		"encryption.inTransit":   true,
		"service.managed":        true,
	}
	impl := map[string]any{
		"resource_group":   "rg1",
		"subnetId":         "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vn/subnets/agw",
		"publicIpId":       "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/pip",
		"sslCertificateId": "https://kv.vault.azure.net/secrets/tls-cert/abc123",
		"backendIps":       []any{"10.0.1.4"},
	}
	res := d.Create("loadbalancer", "edge", "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("HTTPS gateway create must succeed, got %+v", res)
	}
	body := string(f.putBody)
	for _, want := range []string{`"protocol":"Https"`, `"sslCertificates"`,
		`"keyVaultSecretId":"https://kv.vault.azure.net/secrets/tls-cert/abc123"`,
		`"sslCertificate"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("HTTPS App Gateway body missing %s:\n%s", want, body)
		}
	}
	// the cert is a REFERENCE — no key material (PEM/private-key markers) in the body.
	for _, forbidden := range []string{"BEGIN CERTIFICATE", "PRIVATE KEY", `"data":`, `"password":`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("cert material leaked into the body (%s):\n%s", forbidden, body)
		}
	}

	obs, _, err := d.observeLoadBalancer("", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	if obsMap(t, obs)["encryption.inTransit"] != true {
		t.Fatalf("HTTPS gateway observe must see inTransit=true, got %+v", obs)
	}
}

// Missing required operands are REFUSED (never half-built): no subnet; public with
// no publicIpId; inTransit with no cert reference.
func TestCreateAppGatewayMissingOperandRefused(t *testing.T) {
	d := NewDriver(testSub)
	d.token = "test-token"
	base := map[string]any{"resource_group": "rg1"}

	cases := []struct {
		name  string
		attrs map[string]any
		impl  map[string]any
		want  string
	}{
		{"no subnet",
			map[string]any{"location.region": "eastus", "network.publicExposure": false},
			map[string]any{"resource_group": "rg1"}, "subnetId"},
		{"public without publicIpId",
			map[string]any{"location.region": "eastus", "network.publicExposure": true},
			map[string]any{"resource_group": "rg1", "subnetId": "/s/rg/n"}, "publicIpId"},
		{"inTransit without cert",
			map[string]any{"location.region": "eastus", "network.publicExposure": true, "encryption.inTransit": true},
			map[string]any{"resource_group": "rg1", "subnetId": "/s/rg/n", "publicIpId": "/s/rg/pip"}, "sslCertificateId"},
	}
	_ = base
	for _, c := range cases {
		res := d.Create("loadbalancer", "edge", "prod", c.attrs, c.impl, "k", 1)
		if res.Status != "failed" || !strings.Contains(res.Reason, c.want) {
			t.Fatalf("%s: expected failed refusal mentioning %q, got %+v", c.name, c.want, res)
		}
		// Validate refuses identically (the pure builder).
		if err := d.Validate("loadbalancer", "edge", "prod", c.attrs, c.impl, 1); err == nil ||
			!strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: Validate must refuse mentioning %q, got %v", c.name, c.want, err)
		}
	}
}

// An ambiguous create (5xx on the PUT) is `unknown` WITH the providerId — never a
// silent success and never a bare failure that loses the id (four-valued, D29/D87).
func TestCreateAppGatewayAmbiguousUnknown(t *testing.T) {
	f := &agwProvisionFake{putStatus: 503}
	srv := f.server(t)
	defer srv.Close()
	d := agwProvisionDriver(t, srv)

	attrs := map[string]any{"location.region": "eastus", "network.publicExposure": true}
	impl := map[string]any{
		"resource_group": "rg1",
		"subnetId":       "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vn/subnets/agw",
		"publicIpId":     "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/pip",
	}
	res := d.Create("loadbalancer", "edge", "prod", attrs, impl, "k", 1)
	if res.Status != "unknown" {
		t.Fatalf("a 5xx create must be unknown (may have landed), got %+v", res)
	}
	if !strings.HasPrefix(res.ProviderID, "appgateway:") {
		t.Fatalf("an ambiguous create must still carry the providerId, got %q", res.ProviderID)
	}
}

// Delete refuses a FOREIGN gateway (ownership tags do not match) — it never deletes
// a resource it does not own.
func TestDeleteAppGatewayForeignRefused(t *testing.T) {
	f := &agwProvisionFake{
		getDoc: `{"location":"eastus","tags":{"groundhold-capability":"someone-else","groundhold-environment":"prod"},` +
			`"properties":{"provisioningState":"Succeeded","frontendIPConfigurations":[],"httpListeners":[]}}`,
	}
	srv := f.server(t)
	defer srv.Close()
	d := agwProvisionDriver(t, srv)

	del := d.Delete("loadbalancer", "edge", "prod", agwProviderID(testSub, "rg1", "pv-agw-foreign"), "k")
	if del.Status != "failed" || !strings.Contains(del.Reason, "not ours") {
		t.Fatalf("foreign gateway delete must refuse, got %+v", del)
	}
}

// The L4 loadBalancers path stays observe-only: a loadbalancer-kind providerId is
// refused on delete (the driver provisions the L7 gateway, never the L4 resource).
func TestDeleteL4LoadBalancerRefused(t *testing.T) {
	d := NewDriver(testSub)
	d.token = "test-token"
	del := d.Delete("loadbalancer", "edge", "prod", lbProviderID(testSub, "rg1", "pv-lb"), "k")
	if del.Status != "failed" || !strings.Contains(del.Reason, "observe-only") {
		t.Fatalf("L4 loadBalancers delete must refuse as observe-only, got %+v", del)
	}
}

// ClassifyChange: sku/subnet/region immutable (replacement), backend pool mutable.
func TestClassifyLoadBalancerChange(t *testing.T) {
	d := NewDriver(testSub)
	for _, c := range []struct {
		path, want string
	}{
		{"sku", "immutable"},
		{"subnetId", "immutable"},
		{"location.region", "immutable"},
		{"network.publicExposure", "immutable"},
		{"backendFqdns", "mutable"},
		{"backendIps", "mutable"},
		{"encryption.inTransit", "caveated"},
		{"service.managed", "unsupported"},
	} {
		if got, _ := d.ClassifyChange("loadbalancer", c.path, nil, nil, nil); got != c.want {
			t.Fatalf("ClassifyChange(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

// D1195. `encryption.inTransit` was true when ANY listener spoke Https, so a gateway
// with an Http:80 listener forwarding cleartext and an Https:443 listener beside it
// measured as encrypted. The middle case is the defect; the others are the controls
// that keep this fixture from passing by blocking everything.
func TestAppGatewayInTransitNeedsEveryListenerEncrypted(t *testing.T) {
	inTransit := func(t *testing.T, body string) bool {
		t.Helper()
		var doc agwDoc
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			t.Fatalf("fixture does not parse: %v", err)
		}
		for _, o := range reverseMapAppGateway(doc) {
			if o.Path == "encryption.inTransit" {
				v, _ := o.Value.(bool)
				return v
			}
		}
		t.Fatal("no encryption.inTransit observation at all — the fixture is measuring nothing")
		return false
	}

	const self = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/g"
	for _, tc := range []struct {
		name, body string
		want       bool
		why        string
	}{
		{"only https", `{"properties":{"httpListeners":[
			{"name":"l443","properties":{"protocol":"Https"}}]}}`, true,
			"the control: one TLS front door and nothing else is encrypted"},

		{"http beside https", `{"properties":{"httpListeners":[
			{"name":"l443","properties":{"protocol":"Https"}},
			{"name":"l80","properties":{"protocol":"Http"}}]}}`, false,
			"THE DEFECT: a cleartext front door beside a TLS one is not encrypted"},

		{"http redirects to the https listener", `{"properties":{"httpListeners":[
			{"name":"l443","properties":{"protocol":"Https"}},
			{"name":"l80","properties":{"protocol":"Http"}}],
			"redirectConfigurations":[{"name":"r1","properties":{"targetListener":{"id":"` + self + `/httpListeners/l443"}}}],
			"requestRoutingRules":[{"properties":{"httpListener":{"id":"` + self + `/httpListeners/l80"},
				"redirectConfiguration":{"id":"` + self + `/redirectConfigurations/r1"}}}]}}`, true,
			"a plaintext listener whose only job is to send the caller to TLS is not a data path"},

		{"http redirects to another plaintext listener", `{"properties":{"httpListeners":[
			{"name":"l443","properties":{"protocol":"Https"}},
			{"name":"l80","properties":{"protocol":"Http"}},
			{"name":"l8080","properties":{"protocol":"Http"}}],
			"redirectConfigurations":[{"name":"r1","properties":{"targetListener":{"id":"` + self + `/httpListeners/l8080"}}}],
			"requestRoutingRules":[{"properties":{"httpListener":{"id":"` + self + `/httpListeners/l80"},
				"redirectConfiguration":{"id":"` + self + `/redirectConfigurations/r1"}}}]}}`, false,
			"a redirect that lands on cleartext is not a TLS front door"},

		{"no listeners at all", `{"properties":{"httpListeners":[]}}`, false,
			"nothing to speak TLS: absence is not encryption"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := inTransit(t, tc.body); got != tc.want {
				t.Errorf("encryption.inTransit = %v, want %v — %s", got, tc.want, tc.why)
			}
		})
	}
}
