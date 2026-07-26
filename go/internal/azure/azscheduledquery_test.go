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

func azSQAttrs() map[string]any {
	return map[string]any{
		"metric.name":     "app_error_count",
		"metric.filter":   "AppLogs | where Level == 'Error'",
		"metric.kind":     "counter",
		"service.managed": true,
	}
}

func azSQImpl() map[string]any {
	return map[string]any{
		"resource_group": "rg1",
		"scope":          "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/law1",
	}
}

func TestBuildAzureScheduledQueryHonors(t *testing.T) {
	p, err := BuildAzureScheduledQuery("prod", "errors", azSQAttrs(), azSQImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.DisplayName != "app_error_count" || p.Query != "AppLogs | where Level == 'Error'" || p.IsGauge || p.Scope == "" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody(map[string]any{})
	crit := body["properties"].(map[string]any)["criteria"].(map[string]any)["allOf"].([]any)[0].(map[string]any)
	if crit["timeAggregation"] != "Count" {
		t.Fatalf("counter must Count: %+v", crit)
	}
	// gauge measures a column
	g := azSQAttrs()
	g["metric.kind"] = "gauge"
	gp, err := BuildAzureScheduledQuery("prod", "lat", g,
		map[string]any{"resource_group": "rg1", "scope": azSQImpl()["scope"], "value_field": "DurationMs"}, 1)
	if err != nil || gp.MeasureColumn != "DurationMs" {
		t.Fatalf("gauge plan: %+v err=%v", gp, err)
	}
}

func TestBuildAzureScheduledQueryRefusals(t *testing.T) {
	noScope := map[string]any{"resource_group": "rg1"}
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"gauge-no-field": {map[string]any{"metric.kind": "gauge"}, azSQImpl()},
		"bad-kind":       {map[string]any{"metric.kind": "histogram"}, azSQImpl()},
		"empty-filter":   {map[string]any{"metric.filter": ""}, azSQImpl()},
		"no-scope":       {nil, noScope},
		"unmanaged":      {map[string]any{"service.managed": false}, azSQImpl()},
	}
	for name, c := range cases {
		a := azSQAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildAzureScheduledQuery("prod", "errors", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	for _, drop := range []string{"metric.name", "metric.filter", "metric.kind"} {
		a := azSQAttrs()
		delete(a, drop)
		if _, err := BuildAzureScheduledQuery("prod", "errors", a, azSQImpl(), 1); err == nil {
			t.Errorf("missing %s must refuse", drop)
		}
	}
}

func azSQServer(t *testing.T) *httptest.Server {
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

func azSQDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteAzureScheduledQuery(t *testing.T) {
	srv := azSQServer(t)
	defer srv.Close()
	d := azSQDriver(t, srv)
	res := d.createAzureScheduledQuery("prod", "errors", azSQAttrs(), azSQImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "azlm:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeAzureScheduledQuery("errors", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["metric.name"] != "app_error_count" || got["metric.filter"] != "AppLogs | where Level == 'Error'" ||
		got["metric.kind"] != "counter" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteAzureScheduledQuery("errors", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteAzureScheduledQueryForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"someone-else","groundhold-environment":"prod"},` +
				`"properties":{"displayName":"x","criteria":{"allOf":[{"query":"q"}]}}}`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d := azSQDriver(t, srv)
	res := d.deleteAzureScheduledQuery("errors", "prod", "azlm:"+testSub+":rg1:pv-lm-errors-prod-abcd1234")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign rule must refuse delete, got %+v", res)
	}
}

// azSQOwnedServer reports our tags + criteria so the harness delete baseline reaches DELETE.
func azSQOwnedServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
		case "GET":
			_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"errors","groundhold-environment":"prod"},` +
				`"properties":{"displayName":"app_error_count","criteria":{"allOf":[{"query":"q"}]}}}`))
		case "DELETE":
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
}
