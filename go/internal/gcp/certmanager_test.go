package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func cmAttrs() map[string]any {
	return map[string]any{
		"location.region":   "global",
		"domain":            "app.example.com",
		"validation.method": "dns",
		"auto.renew":        true,
		"service.managed":   true,
	}
}

func cmImpl() map[string]any {
	return map[string]any{"dns_authorization": "projects/acme-prod/locations/global/dnsAuthorizations/auth1"}
}

func TestBuildCertManagerHonors(t *testing.T) {
	p, err := BuildCertManager("acme-prod", "prod", "web", cmAttrs(), cmImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Location != "global" || p.Domain != "app.example.com" || p.DNSAuthorization == "" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("web", "prod")
	m := body["managed"].(map[string]any)
	if len(m["dnsAuthorizations"].([]any)) != 1 || m["domains"].([]any)[0] != "app.example.com" {
		t.Fatalf("body = %+v", m)
	}
}

func TestBuildCertManagerRefusals(t *testing.T) {
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"email-refused":  {map[string]any{"validation.method": "email"}, cmImpl()}, // GCP has no email validation
		"bad-validation": {map[string]any{"validation.method": "carrier-pigeon"}, cmImpl()},
		"bad-domain":     {map[string]any{"domain": "not a domain"}, cmImpl()},
		"no-autorenew":   {map[string]any{"auto.renew": false}, cmImpl()},
		"unmanaged":      {map[string]any{"service.managed": false}, cmImpl()},
		"unknown-attr":   {map[string]any{"cert.tier": "x"}, cmImpl()},
		"no-dnsauth":     {map[string]any{}, map[string]any{}}, // DNS validation needs a DnsAuthorization
	}
	for name, c := range cases {
		a := cmAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildCertManager("acme-prod", "prod", "web", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := cmAttrs()
	delete(a, "location.region")
	if _, err := BuildCertManager("acme-prod", "prod", "web", a, cmImpl(), 1); err == nil {
		t.Error("missing location.region must refuse")
	}
}

func cmServer(t *testing.T, capLabel, domain string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "certificateId="):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/global/operations/op1"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/global/operations/opdel"}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/global/certificates/x",` +
					`"labels":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
					`"managed":{"domains":["` + domain + `"],"state":"PROVISIONING"}}`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func cmDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.CertManagerBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteCertManager(t *testing.T) {
	srv := cmServer(t, "web", "app.example.com")
	defer srv.Close()
	d := cmDriver(t, srv)
	res := d.createCertManager("prod", "web", cmAttrs(), cmImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "gcert:acme-prod:global:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeCertManager("web", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "global" || got["domain"] != "app.example.com" ||
		got["validation.method"] != "dns" || got["auto.renew"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteCertManager("web", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteCertManagerForeignRefused(t *testing.T) {
	srv := cmServer(t, "someone-else", "app.example.com")
	defer srv.Close()
	d := cmDriver(t, srv)
	pid := certManagerProviderID("acme-prod", "global", CertManagerCertID("acme-prod", "prod", "web", 1))
	res := d.deleteCertManager("web", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign certificate must refuse delete, got %+v", res)
	}
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.certificate.tls on GCP Certificate Manager. A STATEFUL fake records the
// domain the create writes and reflects it on the certificate read.
func TestMetamorphicCertManagerRoundTrip(t *testing.T) {
	for _, domain := range []string{"a.example.com", "b.example.com"} {
		t.Run(domain, func(t *testing.T) {
			var got string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "certificateId="):
						body, _ := io.ReadAll(r.Body)
						var doc struct {
							Managed struct {
								Domains []string `json:"domains"`
							} `json:"managed"`
						}
						_ = json.Unmarshal(body, &doc)
						if len(doc.Managed.Domains) > 0 {
							got = doc.Managed.Domains[0]
						}
						_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/global/operations/op1"}`))
					case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
						_, _ = w.Write([]byte(`{"done":true}`))
					case r.Method == "GET":
						_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"web","groundhold-environment":"prod"},` +
							`"managed":{"domains":["` + got + `"],"state":"ACTIVE"}}`))
					default:
						w.WriteHeader(404)
					}
				}))
			defer srv.Close()
			d := cmDriver(t, srv)
			a := cmAttrs()
			a["domain"] = domain
			res := d.createCertManager("prod", "web", a, cmImpl(), 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeCertManager("web", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			m := map[string]any{}
			for _, o := range obs {
				m[o.Path] = o.Value
			}
			if m["domain"] != domain {
				t.Errorf("domain round-trip: want %q got %v", domain, m["domain"])
			}
		})
	}
}
