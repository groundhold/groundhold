package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for capability.monitoring.logmetric
// on a GCP log-based metric. A stateful fake records the name/filter/valueExtractor the
// create writes and reflects them on observe; the test varies the kind (counter vs gauge)
// and asserts observe reverse-maps the same filter and kind. A driver that dropped the
// filter or mislabelled a gauge as a counter fails here with no fault injected.
func metamorphicLogMetricServer(t *testing.T) *httptest.Server {
	t.Helper()
	var name, filter, extractor string
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "POST":
				body, _ := io.ReadAll(r.Body)
				var doc struct {
					Name           string `json:"name"`
					Filter         string `json:"filter"`
					ValueExtractor string `json:"valueExtractor"`
				}
				_ = json.Unmarshal(body, &doc)
				name, filter, extractor = doc.Name, doc.Filter, doc.ValueExtractor
				_, _ = w.Write([]byte(`{"name":"` + name + `"}`))
			case "GET":
				b, _ := json.Marshal(map[string]any{
					"name": name, "description": "groundhold-managed lm (prod)",
					"filter": filter, "valueExtractor": extractor,
				})
				_, _ = w.Write(b)
			default:
				w.WriteHeader(200)
			}
		}))
}

func TestMetamorphicLogMetricRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		kind string
		impl map[string]any
	}{
		{"counter", "counter", nil},
		{"gauge", "gauge", map[string]any{"value_field": "latency_ms"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicLogMetricServer(t)
			defer srv.Close()
			d := logMetricDriver(t, srv)
			attrs := map[string]any{
				"metric.name":     "req_" + c.name,
				"metric.filter":   "severity>=WARNING",
				"metric.kind":     c.kind,
				"service.managed": true,
			}
			res := d.createLogMetric("lm", "prod", attrs, c.impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeLogMetric("lm", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["metric.filter"] != "severity>=WARNING" {
				t.Errorf("filter not reflected: %+v", got)
			}
			if got["metric.kind"] != c.kind {
				t.Errorf("kind %v not reflected: %+v", c.kind, got)
			}
		})
	}
}
