package gcp

import (
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for capability.monitoring.uptime
// on a GCP uptime check. The stateful uptimeServer records the config createUptimeCheck
// writes and reflects it on observe; the test varies the protocol/period and asserts
// observe reverse-maps each. A driver that inverted useSsl or dropped the period fails
// here with no fault injected.
func TestMetamorphicUptimeCheckRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		protocol string
		period   string
	}{
		{"https-1m", "https", "60s"},
		{"http-5m", "http", "300s"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := uptimeServer(t)
			defer srv.Close()
			d := uptimeDriver(t, srv)
			attrs := map[string]any{
				"check.target":    "api.example.com",
				"check.protocol":  c.protocol,
				"check.path":      "/healthz",
				"check.period":    c.period,
				"service.managed": true,
			}
			res := d.createUptimeCheck("api", "prod", attrs, nil, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeUptimeCheck("api", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["check.protocol"] != c.protocol {
				t.Errorf("protocol not reflected: %+v", got)
			}
			if got["check.period"] != c.period {
				t.Errorf("period not reflected: %+v", got)
			}
		})
	}
}
