package aws

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for capability.dns.zone on
// AWS Route 53. A STATEFUL fake records what createRoute53 writes (the zone Name and
// the PrivateZone flag from the CreateHostedZone XML) and reflects it on
// GetHostedZone; the test varies public/private and asserts observe reverse-maps
// what create was given. A driver that inverted the PrivateZone->publicExposure
// mapping fails here with no fault injected.
func metamorphicR53Server(t *testing.T) *httptest.Server {
	t.Helper()
	var name, privateZone string
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && r.URL.Path == "/2013-04-01/hostedzone":
				body, _ := io.ReadAll(r.Body)
				var doc struct {
					Name   string `xml:"Name"`
					Config struct {
						PrivateZone bool `xml:"PrivateZone"`
					} `xml:"HostedZoneConfig"`
				}
				_ = xml.Unmarshal(body, &doc)
				name = doc.Name
				if doc.Config.PrivateZone {
					privateZone = "true"
				} else {
					privateZone = "false"
				}
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`<CreateHostedZoneResponse><HostedZone>` +
					`<Id>/hostedzone/Z123ABC</Id><Name>` + name + `</Name>` +
					`</HostedZone></CreateHostedZoneResponse>`))
			case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/2013-04-01/tags/"):
				_, _ = w.Write([]byte(`<ChangeTagsForResourceResponse></ChangeTagsForResourceResponse>`))
			case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/2013-04-01/hostedzone/"):
				_, _ = w.Write([]byte(`<GetHostedZoneResponse><HostedZone>` +
					`<Id>/hostedzone/Z123ABC</Id><Name>` + name + `</Name>` +
					`<Config><PrivateZone>` + privateZone + `</PrivateZone></Config>` +
					`</HostedZone></GetHostedZoneResponse>`))
			default:
				_, _ = w.Write([]byte(`<ok/>`))
			}
		}))
}

func TestMetamorphicRoute53RoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		public bool
	}{
		{"public", true},
		{"private", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicR53Server(t)
			defer srv.Close()
			d := r53Driver(t, srv)
			attrs := map[string]any{
				"zone.domain":            "example.com",
				"network.publicExposure": c.public,
				"service.managed":        true,
			}
			var impl map[string]any
			if !c.public {
				impl = map[string]any{"vpc_id": "vpc-123", "vpc_region": "eu-central-1"}
			}
			res := d.createRoute53("prod", "apex", attrs, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeRoute53("apex", res.ProviderID)
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
		})
	}
}
