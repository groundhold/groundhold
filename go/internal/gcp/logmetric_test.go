package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func logMetricAttrs() map[string]any {
	return map[string]any{
		"metric.name":     "app_error_count",
		"metric.filter":   "severity>=ERROR",
		"metric.kind":     "counter",
		"service.managed": true,
	}
}

func TestBuildLogMetricHonors(t *testing.T) {
	p, err := BuildLogMetric("acme-prod", "prod", "errors", logMetricAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "app_error_count" || p.Filter != "severity>=ERROR" || p.IsGauge ||
		p.Description != "groundhold-managed errors (prod)" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody()
	if body["metricDescriptor"].(map[string]any)["valueType"] != "INT64" {
		t.Fatalf("counter body = %+v", body)
	}
	// gauge with a value field builds + sets a valueExtractor
	g := logMetricAttrs()
	g["metric.kind"] = "gauge"
	gp, err := BuildLogMetric("acme-prod", "prod", "lat", g, map[string]any{"value_field": "latency_ms"}, 1)
	if err != nil || !gp.IsGauge || gp.ValueField != "latency_ms" {
		t.Fatalf("gauge plan: %+v err=%v", gp, err)
	}
	if _, ok := gp.createBody()["valueExtractor"]; !ok {
		t.Fatalf("gauge must set a valueExtractor")
	}
}

func TestBuildLogMetricRefusals(t *testing.T) {
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"gauge-no-field": {map[string]any{"metric.kind": "gauge"}, nil}, // gauge needs value_field
		"bad-kind":       {map[string]any{"metric.kind": "histogram"}, nil},
		"empty-filter":   {map[string]any{"metric.filter": ""}, nil},
		"bad-name":       {map[string]any{"metric.name": "not a name!!"}, nil},
		"unmanaged":      {map[string]any{"service.managed": false}, nil},
		"unknown-attr":   {map[string]any{"metric.buckets": "10"}, nil},
	}
	for name, c := range cases {
		a := logMetricAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildLogMetric("acme-prod", "prod", "errors", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	for _, drop := range []string{"metric.name", "metric.filter", "metric.kind"} {
		a := logMetricAttrs()
		delete(a, drop)
		if _, err := BuildLogMetric("acme-prod", "prod", "errors", a, nil, 1); err == nil {
			t.Errorf("missing %s must refuse", drop)
		}
	}
}

func logMetricServer(t *testing.T, description string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/metrics"):
				_, _ = w.Write([]byte(`{"name":"app_error_count"}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"name":"app_error_count","description":"` + description + `",` +
					`"filter":"severity>=ERROR","metricDescriptor":{"valueType":"INT64"}}`))
			case r.Method == "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func logMetricDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.LoggingBaseURL = srv.URL
	return d
}

func TestCreateObserveDeleteLogMetric(t *testing.T) {
	srv := logMetricServer(t, "groundhold-managed errors (prod)")
	defer srv.Close()
	d := logMetricDriver(t, srv)
	res := d.createLogMetric("errors", "prod", logMetricAttrs(), nil, 1)
	if res.Status != "succeeded" || res.ProviderID != "glogmetric:acme-prod:app_error_count" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeLogMetric("errors", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["metric.name"] != "app_error_count" || got["metric.filter"] != "severity>=ERROR" ||
		got["metric.kind"] != "counter" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteLogMetric("errors", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteLogMetricForeignRefused(t *testing.T) {
	srv := logMetricServer(t, "some other team's metric")
	defer srv.Close()
	d := logMetricDriver(t, srv)
	res := d.deleteLogMetric("errors", "prod", "glogmetric:acme-prod:app_error_count")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign metric must refuse delete, got %+v", res)
	}
}
