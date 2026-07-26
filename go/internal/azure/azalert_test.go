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

func azAlertAttrs() map[string]any {
	return map[string]any{
		"alert.metric":     "Percentage CPU",
		"alert.threshold":  float64(80),
		"alert.comparison": "greater-than",
		"alert.notify":     true,
		"service.managed":  true,
	}
}

func azAlertImpl() map[string]any {
	return map[string]any{
		"resource_group":       "rg1",
		"target_resource":      "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
		"notification_channel": "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.Insights/actionGroups/ag1",
	}
}

func TestBuildAzureAlertHonors(t *testing.T) {
	p, err := BuildAzureAlert("prod", "cpu", azAlertAttrs(), azAlertImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.MetricName != "Percentage CPU" || p.Operator != "GreaterThan" || p.Threshold != 80 ||
		!p.Notify || p.ActionGroup == "" || p.Scope == "" {
		t.Fatalf("plan = %+v", p)
	}
}

func TestBuildAzureAlertRefusals(t *testing.T) {
	noChannel := map[string]any{"resource_group": "rg1", "target_resource": azAlertImpl()["target_resource"]}
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"no-target":         {nil, map[string]any{"resource_group": "rg1"}}, // Azure alert needs a scope
		"notify-no-channel": {map[string]any{"alert.notify": true}, noChannel},
		"bad-comparison":    {map[string]any{"alert.comparison": "sideways"}, azAlertImpl()},
		"unmanaged":         {map[string]any{"service.managed": false}, azAlertImpl()},
		"compound-attr":     {map[string]any{"alert.conditions": "a AND b"}, azAlertImpl()},
	}
	for name, c := range cases {
		a := azAlertAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildAzureAlert("prod", "cpu", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	for _, drop := range []string{"alert.metric", "alert.threshold", "alert.comparison"} {
		a := azAlertAttrs()
		delete(a, drop)
		if _, err := BuildAzureAlert("prod", "cpu", a, azAlertImpl(), 1); err == nil {
			t.Errorf("missing %s must refuse", drop)
		}
	}
	// a non-notifying alert (still needs a target) builds without a channel
	a := azAlertAttrs()
	a["alert.notify"] = false
	if _, err := BuildAzureAlert("prod", "cpu", a, noChannel, 1); err != nil {
		t.Errorf("a non-notifying alert should build without a channel: %v", err)
	}
}

func azAlertServer(t *testing.T) *httptest.Server {
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

func azAlertDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteAzureAlert(t *testing.T) {
	srv := azAlertServer(t)
	defer srv.Close()
	d := azAlertDriver(t, srv)
	res := d.createAzureAlert("prod", "cpu", azAlertAttrs(), azAlertImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "azalert:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeAzureAlert("cpu", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["alert.metric"] != "Percentage CPU" || got["alert.threshold"] != float64(80) ||
		got["alert.comparison"] != "greater-than" || got["alert.notify"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteAzureAlert("cpu", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteAzureAlertForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"someone-else","groundhold-environment":"prod"},` +
				`"properties":{"criteria":{"allOf":[{"metricName":"x","operator":"GreaterThan","threshold":1}]}}}`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d := azAlertDriver(t, srv)
	res := d.deleteAzureAlert("cpu", "prod", "azalert:"+testSub+":rg1:pv-alert-cpu-prod-abcd1234")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign alert must refuse delete, got %+v", res)
	}
}

// azAlertOwnedServer reports our tags + a criterion so the harness delete baseline
// reaches DELETE.
func azAlertOwnedServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
		case "GET":
			_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"cpu","groundhold-environment":"prod"},` +
				`"properties":{"criteria":{"allOf":[{"metricName":"Percentage CPU","operator":"GreaterThan","threshold":80}]},` +
				`"actions":[{"actionGroupId":"ag1"}]}}`))
		case "DELETE":
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
}
