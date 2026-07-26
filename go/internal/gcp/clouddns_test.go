package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func dnsAttrs() map[string]any {
	return map[string]any{
		"zone.domain":            "example.com",
		"network.publicExposure": true,
		"dnssec.enabled":         true,
		"service.managed":        true,
	}
}

func TestBuildCloudDNSHonors(t *testing.T) {
	p, err := BuildCloudDNSZone("acme-prod", "prod", "apex", dnsAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.DNSName != "example.com." || !p.Public || !p.DNSSEC {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("apex", "prod")
	if body["visibility"] != "public" ||
		body["dnssecConfig"].(map[string]any)["state"] != "on" {
		t.Fatalf("body = %+v", body)
	}
}

func TestBuildCloudDNSRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"zone.domain": "example.com", "network.publicExposure": true, "service.managed": true}
	}
	cases := map[string]map[string]any{
		"unmanaged":      {"service.managed": false},
		"record-attr":    {"records.a": "1.2.3.4"}, // records are data, not attrs
		"bad-domain":     {"zone.domain": "not a domain"},
		"dnssec-private": {"network.publicExposure": false, "dnssec.enabled": true},
	}
	for name, extra := range cases {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildCloudDNSZone("acme-prod", "prod", "apex", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// missing domain
	if _, err := BuildCloudDNSZone("acme-prod", "prod", "apex",
		map[string]any{"network.publicExposure": true, "service.managed": true}, nil, 1); err == nil {
		t.Error("missing zone.domain must refuse")
	}
	// a PRIVATE zone (no dnssec) is fine
	if _, err := BuildCloudDNSZone("acme-prod", "prod", "apex",
		map[string]any{"zone.domain": "internal.example.com", "network.publicExposure": false, "service.managed": true}, nil, 1); err != nil {
		t.Errorf("private zone should build: %v", err)
	}
}

func dnsServer(t *testing.T, tagCap, visibility, dnssec string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/managedZones"):
				_, _ = w.Write([]byte(`{"name":"x","dnsName":"example.com."}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"name":"x","dnsName":"example.com.",` +
					`"visibility":"` + visibility + `",` +
					`"labels":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"dnssecConfig":{"state":"` + dnssec + `"}}`))
			case r.Method == "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func dnsDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.DNSBaseURL = srv.URL
	return d
}

func TestCreateObserveDeleteCloudDNS(t *testing.T) {
	srv := dnsServer(t, "apex", "public", "on")
	defer srv.Close()
	d := dnsDriver(t, srv)
	res := d.createCloudDNS("prod", "apex", dnsAttrs(), nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "gdns:acme-prod:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeCloudDNS("apex", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["zone.domain"] != "example.com" || got["network.publicExposure"] != true ||
		got["dnssec.enabled"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteCloudDNS("apex", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteCloudDNSForeignRefused(t *testing.T) {
	srv := dnsServer(t, "someone-else", "public", "off")
	defer srv.Close()
	d := dnsDriver(t, srv)
	res := d.deleteCloudDNS("apex", "prod", "gdns:acme-prod:x")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign zone must refuse delete, got %+v", res)
	}
}
