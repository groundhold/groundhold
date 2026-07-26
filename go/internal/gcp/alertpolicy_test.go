package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func alertAttrs() map[string]any {
	return map[string]any{
		"alert.metric":     "compute.googleapis.com/instance/cpu/utilization",
		"alert.threshold":  float64(80),
		"alert.comparison": "greater-than",
		"alert.notify":     true,
		"service.managed":  true,
	}
}

func alertImpl() map[string]any {
	return map[string]any{"notification_channel": "projects/acme-prod/notificationChannels/123"}
}

func TestBuildAlertPolicyHonors(t *testing.T) {
	p, err := BuildAlertPolicy("acme-prod", "prod", "cpu", alertAttrs(), alertImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Comparison != "COMPARISON_GT" || p.Threshold != 80 || !p.Notify || p.Channel == "" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("cpu", "prod")
	cond := body["conditions"].([]any)[0].(map[string]any)["conditionThreshold"].(map[string]any)
	if !strings.Contains(cond["filter"].(string), "cpu/utilization") || cond["comparison"] != "COMPARISON_GT" {
		t.Fatalf("body = %+v", cond)
	}
	if _, ok := body["notificationChannels"]; !ok {
		t.Fatalf("notify=true must set notificationChannels")
	}
}

func TestBuildAlertPolicyRefusals(t *testing.T) {
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"notify-no-channel": {map[string]any{"alert.notify": true}, nil}, // silent alert claiming to notify
		"bad-comparison":    {map[string]any{"alert.comparison": "sideways"}, alertImpl()},
		"unmanaged":         {map[string]any{"service.managed": false}, alertImpl()},
		"compound-attr":     {map[string]any{"alert.conditions": "a AND b"}, alertImpl()}, // no compound logic
		"bad-threshold":     {map[string]any{"alert.threshold": "high"}, alertImpl()},
	}
	for name, c := range cases {
		a := alertAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildAlertPolicy("acme-prod", "prod", "cpu", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// missing metric / threshold / comparison
	for _, drop := range []string{"alert.metric", "alert.threshold", "alert.comparison"} {
		a := alertAttrs()
		delete(a, drop)
		if _, err := BuildAlertPolicy("acme-prod", "prod", "cpu", a, alertImpl(), 1); err == nil {
			t.Errorf("missing %s must refuse", drop)
		}
	}
	// a NON-notifying alert (notify=false) needs no channel
	a := alertAttrs()
	a["alert.notify"] = false
	if _, err := BuildAlertPolicy("acme-prod", "prod", "cpu", a, nil, 1); err != nil {
		t.Errorf("a non-notifying alert should build without a channel: %v", err)
	}
}

// alertServer is a STATEFUL fake: create records the condition, get reflects it.
func alertServer(t *testing.T) *httptest.Server {
	t.Helper()
	var stored map[string]any
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/alertPolicies"):
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &stored)
				stored["name"] = "projects/acme-prod/alertPolicies/98765"
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/alertPolicies/98765"}`))
			case r.Method == "GET":
				b, _ := json.Marshal(stored)
				_, _ = w.Write(b)
			case r.Method == "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func alertDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.MonitoringBaseURL = srv.URL
	return d
}

func TestCreateObserveDeleteAlertPolicy(t *testing.T) {
	srv := alertServer(t)
	defer srv.Close()
	d := alertDriver(t, srv)
	res := d.createAlertPolicy("cpu", "prod", alertAttrs(), alertImpl(), 1)
	if res.Status != "succeeded" || res.ProviderID != "galert:acme-prod:98765" {
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
	if got["alert.metric"] != "compute.googleapis.com/instance/cpu/utilization" ||
		got["alert.threshold"] != float64(80) || got["alert.comparison"] != "greater-than" ||
		got["alert.notify"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteAlertPolicy("cpu", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteAlertPolicyForeignRefused(t *testing.T) {
	// a server that reports a foreign owner
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_, _ = w.Write([]byte(`{"userLabels":{"groundhold-capability":"someone-else","groundhold-environment":"prod"},` +
				`"conditions":[{"conditionThreshold":{"filter":"metric.type=\"x\"","comparison":"COMPARISON_GT","thresholdValue":1}}]}`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d := alertDriver(t, srv)
	res := d.deleteAlertPolicy("cpu", "prod", "galert:acme-prod:98765")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign alert must refuse delete, got %+v", res)
	}
}

// alertOwnedServer reports OUR labels so the harness delete baseline succeeds; the
// POST parses a server-assigned id, GET/DELETE behave.
func alertOwnedServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/alertPolicies/98765"}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"userLabels":{"groundhold-capability":"cpu","groundhold-environment":"prod"},` +
					`"conditions":[{"conditionThreshold":{"filter":"metric.type=\"x\"","comparison":"COMPARISON_GT","thresholdValue":1}}],` +
					`"notificationChannels":["projects/acme-prod/notificationChannels/123"]}`))
			case r.Method == "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}
