package gcp

import (
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for capability.monitoring.alert
// on a GCP alerting policy. The stateful alertServer records the condition
// createAlertPolicy writes and reflects it on observe; the test varies the
// comparison / threshold / notify and asserts observe reverse-maps each. A driver
// that inverted the comparison or dropped the notification channel fails here with no
// fault injected.
func TestMetamorphicAlertPolicyRoundTrip(t *testing.T) {
	cases := []struct {
		name       string
		comparison string
		threshold  float64
		notify     bool
	}{
		{"gt-notify", "greater-than", 80, true},
		{"lt-silent", "less-than", 5, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := alertServer(t)
			defer srv.Close()
			d := alertDriver(t, srv)
			attrs := map[string]any{
				"alert.metric":     "compute.googleapis.com/instance/cpu/utilization",
				"alert.threshold":  c.threshold,
				"alert.comparison": c.comparison,
				"alert.notify":     c.notify,
				"service.managed":  true,
			}
			impl := map[string]any{"resource_type": "gce_instance"} // D897: filter needs resource.type
			if c.notify {
				impl = alertImpl()
			}
			res := d.createAlertPolicy("cpu", "prod", attrs, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeAlertPolicy("cpu", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["alert.comparison"] != c.comparison {
				t.Errorf("comparison not reflected: %+v", got)
			}
			if got["alert.threshold"] != c.threshold {
				t.Errorf("threshold not reflected: %+v", got)
			}
			if got["alert.notify"] != c.notify {
				t.Errorf("notify %v not reflected: %+v", c.notify, got)
			}
		})
	}
}
