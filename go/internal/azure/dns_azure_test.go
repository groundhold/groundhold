package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func azDNSAttrs() map[string]any {
	return map[string]any{
		"zone.domain":            "example.com",
		"network.publicExposure": true,
		"service.managed":        true,
	}
}

func TestBuildAzureDNSHonorsAndForksType(t *testing.T) {
	pub, err := BuildAzureDNS("prod", "apex", azDNSAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if pub.Domain != "example.com" || !pub.Public {
		t.Fatalf("plan = %+v", pub)
	}
	if !strings.Contains(pub.providerPath(), "Microsoft.Network/dnsZones/") {
		t.Fatalf("public zone must use dnsZones: %s", pub.providerPath())
	}
	// private forks to a DIFFERENT resource type + API version
	pa := azDNSAttrs()
	pa["network.publicExposure"] = false
	priv, _ := BuildAzureDNS("prod", "apex", pa, nil, 1)
	if !strings.Contains(priv.providerPath(), "Microsoft.Network/privateDnsZones/") {
		t.Fatalf("private zone must use privateDnsZones: %s", priv.providerPath())
	}
	if priv.apiVersion() == pub.apiVersion() {
		t.Fatal("public and private zones use different API versions")
	}
}

func TestBuildAzureDNSRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"zone.domain": "example.com", "network.publicExposure": true, "service.managed": true}
	}
	cases := map[string]map[string]any{
		"unmanaged":     {"service.managed": false},
		"dnssec-v0-gap": {"dnssec.enabled": true},
		"record-attr":   {"records.a": "1.2.3.4"},
		"bad-domain":    {"zone.domain": "not a domain"},
	}
	for name, extra := range cases {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildAzureDNS("prod", "apex", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	if _, err := BuildAzureDNS("prod", "apex",
		map[string]any{"network.publicExposure": true, "service.managed": true}, nil, 1); err == nil {
		t.Error("missing zone.domain must refuse")
	}
}

func azDNSServer(t *testing.T, tagCap string, capturedPath *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				if capturedPath != nil {
					*capturedPath = r.URL.Path
				}
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"global",` +
					`"tags":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded"}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func azDNSDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteAzureDNSPublic(t *testing.T) {
	var path string
	srv := azDNSServer(t, "apex", &path)
	defer srv.Close()
	d := azDNSDriver(t, srv)
	res := d.createAzureDNS("prod", "apex", azDNSAttrs(), map[string]any{"resource_group": "rg1"}, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "adns:"+testSub+":rg1:pub:") {
		t.Fatalf("create: %+v", res)
	}
	if !strings.Contains(path, "/dnsZones/") {
		t.Fatalf("public create must PUT dnsZones, got %s", path)
	}
	got := map[string]any{}
	obs, _, err := d.observeAzureDNS("apex", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["zone.domain"] != "example.com" || got["network.publicExposure"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteAzureDNS("apex", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestCreateAzureDNSPrivateUsesPrivateType(t *testing.T) {
	var path string
	srv := azDNSServer(t, "apex", &path)
	defer srv.Close()
	d := azDNSDriver(t, srv)
	a := azDNSAttrs()
	a["network.publicExposure"] = false
	res := d.createAzureDNS("prod", "apex", a, map[string]any{"resource_group": "rg1"}, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "adns:"+testSub+":rg1:priv:") {
		t.Fatalf("create: %+v", res)
	}
	if !strings.Contains(path, "/privateDnsZones/") {
		t.Fatalf("private create must PUT privateDnsZones, got %s", path)
	}
	obs, _, _ := d.observeAzureDNS("apex", res.ProviderID)
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["network.publicExposure"] != false {
		t.Fatalf("private zone must observe publicExposure=false: %+v", got)
	}
}

func TestDeleteAzureDNSForeignRefused(t *testing.T) {
	srv := azDNSServer(t, "someone-else", nil)
	defer srv.Close()
	d := azDNSDriver(t, srv)
	res := d.deleteAzureDNS("apex", "prod", "adns:"+testSub+":rg1:pub:example.com")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign zone must refuse delete, got %+v", res)
	}
}
