package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func dashAttrs() map[string]any {
	return map[string]any{
		"dashboard.metrics": []any{
			"compute.googleapis.com/instance/cpu/utilization",
			"loadbalancing.googleapis.com/https/request_count",
		},
		"dashboard.widgetCount": float64(2),
		"service.managed":       true,
	}
}

func TestBuildDashboardHonors(t *testing.T) {
	p, err := BuildDashboard("acme-prod", "prod", "golden", dashAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Metrics) != 2 || p.DisplayName != "groundhold golden (prod)" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody()
	tiles := body["mosaicLayout"].(map[string]any)["tiles"].([]any)
	if len(tiles) != 2 {
		t.Fatalf("expected 2 tiles, got %d", len(tiles))
	}
	filter := tiles[0].(map[string]any)["widget"].(map[string]any)["xyChart"].(map[string]any)["dataSets"].([]any)[0].(map[string]any)["timeSeriesQuery"].(map[string]any)["timeSeriesFilter"].(map[string]any)["filter"].(string)
	if !strings.Contains(filter, "cpu/utilization") {
		t.Fatalf("filter = %s", filter)
	}
}

func TestBuildDashboardRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"widgetcount-lie": {"dashboard.widgetCount": float64(5)}, // 2 metrics != 5
		"empty-metrics":   {"dashboard.metrics": []any{}},
		"bad-metric":      {"dashboard.metrics": []any{"not a metric!!"}},
		"unmanaged":       {"service.managed": false},
		"layout-attr":     {"dashboard.layout": "custom"}, // no free-form layout
	}
	for name, extra := range cases {
		a := dashAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildDashboard("acme-prod", "prod", "golden", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := dashAttrs()
	delete(a, "dashboard.metrics")
	if _, err := BuildDashboard("acme-prod", "prod", "golden", a, nil, 1); err == nil {
		t.Error("missing dashboard.metrics must refuse")
	}
}

func dashServer(t *testing.T) *httptest.Server {
	t.Helper()
	var stored map[string]any
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/dashboards"):
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &stored)
				stored["name"] = "projects/acme-prod/dashboards/abc123"
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/dashboards/abc123"}`))
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

func dashDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.DashboardBaseURL = srv.URL
	return d
}

func TestCreateObserveDeleteDashboard(t *testing.T) {
	srv := dashServer(t)
	defer srv.Close()
	d := dashDriver(t, srv)
	res := d.createDashboard("golden", "prod", dashAttrs(), nil, 1)
	if res.Status != "succeeded" || res.ProviderID != "gdash:acme-prod:abc123" {
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
	if got["dashboard.widgetCount"] != float64(2) {
		t.Fatalf("widgetCount: %+v", got)
	}
	metrics, _ := got["dashboard.metrics"].([]string)
	if len(metrics) != 2 {
		t.Fatalf("metrics not reflected: %+v", got["dashboard.metrics"])
	}
	if del := d.deleteDashboard("golden", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteDashboardForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_, _ = w.Write([]byte(`{"displayName":"someone else's board","mosaicLayout":{"tiles":[]}}`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d := dashDriver(t, srv)
	res := d.deleteDashboard("golden", "prod", "gdash:acme-prod:abc123")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign dashboard must refuse delete, got %+v", res)
	}
}

// dashOwnedServer reports our displayName so the harness delete baseline succeeds.
func dashOwnedServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/dashboards/abc123"}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"displayName":"groundhold golden (prod)","mosaicLayout":{"tiles":[` +
					`{"widget":{"xyChart":{"dataSets":[{"timeSeriesQuery":{"timeSeriesFilter":{"filter":"metric.type=\"x\""}}}]}}}]}}`))
			case r.Method == "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

// TestCreateDashboardAdoptsExisting pins D255: a dashboard whose displayName is
// ours already exists -> createDashboard BINDS it (no POST) instead of minting a
// duplicate (the id is server-assigned, so a blind POST would duplicate).
func TestCreateDashboardAdoptsExisting(t *testing.T) {
	want := dashDisplayName("golden", "prod")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"dashboards":[{"name":"projects/acme-prod/dashboards/existing123","displayName":"` + want + `"}]}`))
			return
		}
		t.Errorf("adoption must not %s — bind the existing dashboard, never create", r.Method)
		w.WriteHeader(400)
	}))
	defer srv.Close()
	d := dashDriver(t, srv)
	res := d.createDashboard("golden", "prod", dashAttrs(), nil, 1)
	if res.Status != "succeeded" || res.ProviderID != "gdash:acme-prod:existing123" {
		t.Fatalf("must adopt the existing dashboard by displayName, got %+v", res)
	}
}
