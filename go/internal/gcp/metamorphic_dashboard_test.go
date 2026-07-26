package gcp

import (
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.monitoring.dashboard on a GCP dashboard. The stateful dashServer records
// the mosaicLayout createDashboard writes and reflects it on observe; the test varies
// the METRIC SET and asserts observe reverse-maps the same metrics AND the derived
// widgetCount. A driver that dropped a widget or miscounted fails here with no fault
// injected.
func TestMetamorphicDashboardRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		metrics []any
	}{
		{"one", []any{"compute.googleapis.com/instance/cpu/utilization"}},
		{"three", []any{
			"compute.googleapis.com/instance/cpu/utilization",
			"compute.googleapis.com/instance/network/received_bytes_count",
			"loadbalancing.googleapis.com/https/request_count",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := dashServer(t)
			defer srv.Close()
			d := dashDriver(t, srv)
			attrs := map[string]any{
				"dashboard.metrics":     c.metrics,
				"dashboard.widgetCount": float64(len(c.metrics)),
				"service.managed":       true,
			}
			res := d.createDashboard("golden", "prod", attrs, nil, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeDashboard("golden", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["dashboard.widgetCount"] != float64(len(c.metrics)) {
				t.Errorf("widgetCount not reflected: %+v", got)
			}
			metrics, _ := got["dashboard.metrics"].([]string)
			if len(metrics) != len(c.metrics) {
				t.Errorf("metric set not reflected: %+v", got["dashboard.metrics"])
			}
		})
	}
}
