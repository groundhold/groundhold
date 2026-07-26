package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for capability.dns.zone on
// GCP Cloud DNS. A STATEFUL fake records what createCloudDNS writes (visibility,
// dnssec state, dnsName) and reflects it on the observe read; the test varies
// (public, dnssec) and asserts observe reverse-maps what create was given. A driver
// that inverted visibility or dropped the DNSSEC state fails here with no fault
// injected.
func metamorphicDNSServer(t *testing.T) *httptest.Server {
	t.Helper()
	var visibility, dnssec, dnsName string
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/managedZones"):
				body, _ := io.ReadAll(r.Body)
				var doc struct {
					DNSName      string `json:"dnsName"`
					Visibility   string `json:"visibility"`
					DnssecConfig struct {
						State string `json:"state"`
					} `json:"dnssecConfig"`
				}
				_ = json.Unmarshal(body, &doc)
				visibility, dnssec, dnsName = doc.Visibility, doc.DnssecConfig.State, doc.DNSName
				_, _ = w.Write([]byte(`{"name":"x"}`))
			case r.Method == "GET":
				b, _ := json.Marshal(map[string]any{
					"name":         "x",
					"dnsName":      dnsName,
					"visibility":   visibility,
					"labels":       map[string]any{"groundhold-capability": "apex", "groundhold-environment": "prod"},
					"dnssecConfig": map[string]any{"state": dnssec},
				})
				_, _ = w.Write(b)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestMetamorphicCloudDNSRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		public bool
		dnssec bool
	}{
		{"public-dnssec", true, true},
		{"public-nodnssec", true, false},
		{"private", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicDNSServer(t)
			defer srv.Close()
			d := dnsDriver(t, srv)
			attrs := map[string]any{
				"zone.domain":            "example.com",
				"network.publicExposure": c.public,
				"dnssec.enabled":         c.dnssec,
				"service.managed":        true,
			}
			res := d.createCloudDNS("prod", "apex", attrs, nil, 1)
			if res.Status != "succeeded" {
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
			if got["zone.domain"] != "example.com" {
				t.Errorf("domain not reflected: %+v", got)
			}
			if got["network.publicExposure"] != c.public {
				t.Errorf("public %v not reflected: %+v", c.public, got)
			}
			if got["dnssec.enabled"] != c.dnssec {
				t.Errorf("dnssec %v not reflected: %+v", c.dnssec, got)
			}
		})
	}
}
