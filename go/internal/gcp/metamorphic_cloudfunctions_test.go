package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Weapon 2 (D87) for Cloud Functions (Gen 2) — the metamorphic write/read
// round-trip. A STATEFUL fake records what the create WRITES (serviceConfig
// ingressSettings + minInstanceCount) and reflects it on functions.get; the
// backing Cloud Run IAM is stateful too (the allUsers invoker binding appears
// only after a public create's setIamPolicy). The test asserts
// observeCloudFunction reverse-maps the SAME semantic attributes create was
// given. publicExposure is the TWO-gate reverse map (ingress AND invoker IAM), so
// a driver that inverts the ingress test, or drops the IAM gate, fails here.
//
// Round-trippers exercised through the wire: network.publicExposure (ingress +
// backing invoker IAM) and replicas.minimum (minInstanceCount). location.region
// is asserted but providerId-derived (read from the pid, not the wire), so it is
// held constant, not a wire round-tripper.
func metamorphicCloudFunctionServer(t *testing.T) *httptest.Server {
	t.Helper()
	var (
		ingress      string
		minInstances int
		granted      bool
	)
	const backing = "projects/acme-prod/locations/europe-central2/services/api-run"
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			// backing Cloud Run IAM (public exposure's second gate)
			case strings.HasSuffix(p, ":getIamPolicy"):
				if granted {
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[` +
						`{"role":"roles/run.invoker","members":["allUsers"]}]}`))
				} else {
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[]}`))
				}
			case strings.HasSuffix(p, ":setIamPolicy"):
				granted = true
				_, _ = w.Write([]byte(`{"etag":"e2"}`))
			// Cloud Functions LRO ({done,error})
			case strings.Contains(p, "/operations/"):
				_, _ = w.Write([]byte(`{"name":"op","done":true}`))
			// ---- create writes ----
			case r.Method == "POST" && strings.Contains(p, "/functions"):
				raw, _ := io.ReadAll(r.Body)
				var body struct {
					ServiceConfig struct {
						IngressSettings  string `json:"ingressSettings"`
						MinInstanceCount int    `json:"minInstanceCount"`
					} `json:"serviceConfig"`
				}
				_ = json.Unmarshal(raw, &body)
				ingress = body.ServiceConfig.IngressSettings
				minInstances = body.ServiceConfig.MinInstanceCount
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-central2/operations/op-create"}`))
			// ---- observe reads reflect the recorded state ----
			case r.Method == "GET" && strings.Contains(p, "/functions/"):
				resp := map[string]any{
					"labels": map[string]any{
						"groundhold-capability": "api", "groundhold-environment": "prod"},
					"serviceConfig": map[string]any{
						"ingressSettings":  ingress,
						"minInstanceCount": minInstances,
						"service":          backing,
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
			case r.Method == "GET" && strings.Contains(p, "/services/"):
				// the backing Cloud Run service (observe reads invokerIamDisabled)
				_, _ = w.Write([]byte(`{"invokerIamDisabled":false}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
}

func TestMetamorphicCloudFunctionRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		public   bool
		replicas int
	}{
		{"public-min2", true, 2},
		{"private-min1", false, 1},
		{"public-min1", true, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicCloudFunctionServer(t)
			defer srv.Close()
			d := cfDriver(t, srv)
			d.PollInterval = 0

			attrs := cfAttrs()
			attrs["network.publicExposure"] = c.public
			attrs["replicas.minimum"] = float64(c.replicas)
			res := d.createCloudFunction("api", "prod", attrs, cfImpl(), 1)
			if res.Status != "succeeded" {
				t.Fatalf("create failed: %+v", res)
			}
			obs, diags, err := d.observeCloudFunction("api", res.ProviderID)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			// the metamorphic invariant: Observe reverse-maps what Create wrote.
			if got["network.publicExposure"] != c.public {
				t.Errorf("public-exposure round-trip broke: wrote %v, observed %v (diags %v)", c.public, got["network.publicExposure"], diags)
			}
			if got["replicas.minimum"] != float64(c.replicas) {
				t.Errorf("replicas.minimum round-trip broke: wrote %v, observed %v", c.replicas, got["replicas.minimum"])
			}
			// location.region is providerId-derived (read from the pid, not the
			// wire) — held constant, not a wire round-tripper.
			if got["location.region"] != "europe-central2" {
				t.Errorf("region round-trip broke: observed %v", got["location.region"])
			}
		})
	}
}
