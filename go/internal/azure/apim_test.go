package azure

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

func readBodyMapAz(r *http.Request) map[string]any {
	b, _ := io.ReadAll(r.Body)
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

func apimAttrs() map[string]any {
	return map[string]any{
		"location.region": "eastus",
		"protocol":        "http",
		"service.managed": true,
	}
}

func apimImpl() map[string]any {
	return map[string]any{
		"resource_group":  "rg1",
		"publisher_email": "ops@example.com",
		"publisher_name":  "Example Ops",
	}
}

func TestBuildAPIMHonors(t *testing.T) {
	p, err := BuildAPIM("prod", "front", apimAttrs(), apimImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Region != "eastus" || p.PublisherEmail != "ops@example.com" || !apimNameOK.MatchString(p.Name) {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody(map[string]any{})
	props := body["properties"].(map[string]any)
	if props["publisherEmail"] != "ops@example.com" || body["sku"].(map[string]any)["name"] != "Consumption" {
		t.Fatalf("body = %+v", body)
	}
}

func TestBuildAPIMRefusals(t *testing.T) {
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"websocket-refused": {map[string]any{"protocol": "websocket"}, apimImpl()}, // APIM has no websocket API
		"bad-protocol":      {map[string]any{"protocol": "carrier-pigeon"}, apimImpl()},
		"unmanaged":         {map[string]any{"service.managed": false}, apimImpl()},
		"unknown-attr":      {map[string]any{"api.tier": "x"}, apimImpl()},
		"no-publisher":      {map[string]any{}, map[string]any{"resource_group": "rg1"}}, // publisher email/name required
		"bad-email":         {map[string]any{}, map[string]any{"resource_group": "rg1", "publisher_email": "notanemail", "publisher_name": "x"}},
	}
	for name, c := range cases {
		a := apimAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildAPIM("prod", "front", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := apimAttrs()
	delete(a, "location.region")
	if _, err := BuildAPIM("prod", "front", a, apimImpl(), 1); err == nil {
		t.Error("missing location.region must refuse")
	}
}

func apimServer(t *testing.T, capLabel string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded"}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func apimDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteAPIM(t *testing.T) {
	srv := apimServer(t, "front")
	defer srv.Close()
	d := apimDriver(t, srv)
	res := d.createAPIM("prod", "front", apimAttrs(), apimImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "apim:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeAPIM("front", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eastus" || got["protocol"] != "http" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteAPIM("front", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteAPIMForeignRefused(t *testing.T) {
	srv := apimServer(t, "someone-else")
	defer srv.Close()
	d := apimDriver(t, srv)
	pid := apimProviderID(testSub, "rg1", apimServiceName("prod", "front", 1))
	res := d.deleteAPIM("front", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign service must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessAPIM(t *testing.T) {
	pid := apimProviderID(testSub, "rg1", apimServiceName("prod", "front", 1))
	p := &certifynet.Probe{
		// AssertTransient left false — D237 TODO: this driver's create/delete ladder
		// still maps 429/503/403 to terminal failed (and drops the providerId); it must
		// route through provider.MutationResult before the transient invariant can lock.
		Name:            "azure/apim",
		Classify:        armRole,
		OwnerTagValue:   "front",
		AssertTransient: true, // D237
		DeterministicID: true,
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.BaseURL = happyURL
			d.HTTP = &http.Client{Transport: rt}
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return apimServer(t, "front") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("apim", "front", "prod", apimAttrs(), apimImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return apimServer(t, "front") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("apim", "front", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.apigateway.http on Azure APIM. The service is HTTP; the round-trip
// asserts observe reports the region the create wrote (via the substrate location).
func TestMetamorphicAPIMRoundTrip(t *testing.T) {
	for _, region := range []string{"eastus", "westeurope"} {
		t.Run(region, func(t *testing.T) {
			var loc string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch r.Method {
					case "PUT":
						body := readBodyMapAz(r)
						loc, _ = body["location"].(string)
						w.WriteHeader(200)
						_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
					case "GET":
						_, _ = w.Write([]byte(`{"location":"` + loc + `","tags":{"groundhold-capability":"front","groundhold-environment":"prod"},` +
							`"properties":{"provisioningState":"Succeeded"}}`))
					default:
						w.WriteHeader(200)
					}
				}))
			defer srv.Close()
			d := apimDriver(t, srv)
			a := apimAttrs()
			a["location.region"] = region
			res := d.createAPIM("prod", "front", a, apimImpl(), 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeAPIM("front", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["location.region"] != region {
				t.Errorf("region round-trip: want %q got %v", region, got["location.region"])
			}
		})
	}
}
