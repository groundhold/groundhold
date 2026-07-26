package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func azDashAttrs() map[string]any {
	return map[string]any{
		"dashboard.metrics":     []any{"Percentage CPU", "Network In Total"},
		"dashboard.widgetCount": float64(2),
		"service.managed":       true,
	}
}

func azDashImpl() map[string]any {
	return map[string]any{
		"resource_group":  "rg1",
		"target_resource": "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
	}
}

func TestBuildAzureDashboardHonors(t *testing.T) {
	p, err := BuildAzureDashboard("prod", "golden", azDashAttrs(), azDashImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Metrics) != 2 || p.Target == "" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody(map[string]any{})
	parts := body["properties"].(map[string]any)["lenses"].(map[string]any)["0"].(map[string]any)["parts"].(map[string]any)
	if len(parts) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(parts))
	}
}

func TestBuildAzureDashboardRefusals(t *testing.T) {
	noTarget := map[string]any{"resource_group": "rg1"}
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"widgetcount-lie": {map[string]any{"dashboard.widgetCount": float64(7)}, azDashImpl()},
		"empty-metrics":   {map[string]any{"dashboard.metrics": []any{}}, azDashImpl()},
		"no-target":       {nil, noTarget},
		"unmanaged":       {map[string]any{"service.managed": false}, azDashImpl()},
		"layout-attr":     {map[string]any{"dashboard.layout": "custom"}, azDashImpl()},
	}
	for name, c := range cases {
		a := azDashAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildAzureDashboard("prod", "golden", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := azDashAttrs()
	delete(a, "dashboard.metrics")
	if _, err := BuildAzureDashboard("prod", "golden", a, azDashImpl(), 1); err == nil {
		t.Error("missing dashboard.metrics must refuse")
	}
}

func azDashServer(t *testing.T) *httptest.Server {
	t.Helper()
	var stored map[string]any
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &stored)
				w.WriteHeader(201)
				b, _ := json.Marshal(stored)
				_, _ = w.Write(b)
			case "GET":
				if stored == nil {
					w.WriteHeader(404)
					return
				}
				b, _ := json.Marshal(stored)
				_, _ = w.Write(b)
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func azDashDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteAzureDashboard(t *testing.T) {
	srv := azDashServer(t)
	defer srv.Close()
	d := azDashDriver(t, srv)
	res := d.createAzureDashboard("prod", "golden", azDashAttrs(), azDashImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "azdash:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeAzureDashboard("golden", res.ProviderID)
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
	set := map[string]bool{}
	for _, m := range metrics {
		set[m] = true
	}
	if len(metrics) != 2 || !set["Percentage CPU"] || !set["Network In Total"] {
		t.Fatalf("metrics not reflected: %+v", got["dashboard.metrics"])
	}
	if del := d.deleteAzureDashboard("golden", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteAzureDashboardForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"someone-else","groundhold-environment":"prod"},"properties":{"lenses":{}}}`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d := azDashDriver(t, srv)
	res := d.deleteAzureDashboard("golden", "prod", "azdash:"+testSub+":rg1:pv-dash-golden-prod-abcd1234")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign dashboard must refuse delete, got %+v", res)
	}
}

// azDashOwnedServer reports our tags + a part so the harness delete baseline reaches DELETE.
func azDashOwnedServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
		case "GET":
			_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"golden","groundhold-environment":"prod"},` +
				`"properties":{"lenses":{"0":{"parts":{"0":{"metadata":{"inputs":[{"value":{"chart":{"metrics":[{"name":"Percentage CPU"}]}}}]}}}}}}}`))
		case "DELETE":
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
}
