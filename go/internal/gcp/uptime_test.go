package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func uptimeAttrs() map[string]any {
	return map[string]any{
		"check.target":    "api.example.com",
		"check.protocol":  "https",
		"check.path":      "/healthz",
		"check.period":    "60s",
		"service.managed": true,
	}
}

func TestBuildUptimeCheckHonors(t *testing.T) {
	p, err := BuildUptimeCheck("acme-prod", "prod", "api", uptimeAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "api.example.com" || p.IsTCP || !p.UseSsl || p.Port != 443 || p.PeriodSec != 60 {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("acme-prod", "api", "prod")
	if body["httpCheck"].(map[string]any)["useSsl"] != true || body["period"] != "60s" {
		t.Fatalf("body = %+v", body)
	}
	// tcp check with a port builds
	tp, err := BuildUptimeCheck("acme-prod", "prod", "api",
		map[string]any{"check.target": "db.internal", "check.protocol": "tcp", "check.period": "300s", "service.managed": true},
		map[string]any{"port": 5432}, 1)
	if err != nil || !tp.IsTCP || tp.Port != 5432 {
		t.Fatalf("tcp plan: %+v err=%v", tp, err)
	}
}

func TestBuildUptimeCheckRefusals(t *testing.T) {
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"bad-period":    {map[string]any{"check.period": "45s"}, nil}, // not 60/300/600/900
		"bad-protocol":  {map[string]any{"check.protocol": "carrier-pigeon"}, nil},
		"tcp-with-path": {map[string]any{"check.protocol": "tcp", "check.path": "/x"}, map[string]any{"port": 22}},
		"tcp-no-port":   {map[string]any{"check.protocol": "tcp", "check.path": ""}, nil},
		"unmanaged":     {map[string]any{"service.managed": false}, nil},
		"unknown-attr":  {map[string]any{"check.headers": "x"}, nil},
	}
	for name, c := range cases {
		a := uptimeAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildUptimeCheck("acme-prod", "prod", "api", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	for _, drop := range []string{"check.target", "check.protocol", "check.period"} {
		a := uptimeAttrs()
		delete(a, drop)
		if _, err := BuildUptimeCheck("acme-prod", "prod", "api", a, nil, 1); err == nil {
			t.Errorf("missing %s must refuse", drop)
		}
	}
}

func uptimeServer(t *testing.T) *httptest.Server {
	t.Helper()
	var stored map[string]any
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/uptimeCheckConfigs"):
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &stored)
				stored["name"] = "projects/acme-prod/uptimeCheckConfigs/xyz789"
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/uptimeCheckConfigs/xyz789"}`))
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

func uptimeDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.UptimeBaseURL = srv.URL
	return d
}

func TestCreateObserveDeleteUptimeCheck(t *testing.T) {
	srv := uptimeServer(t)
	defer srv.Close()
	d := uptimeDriver(t, srv)
	res := d.createUptimeCheck("api", "prod", uptimeAttrs(), nil, 1)
	if res.Status != "succeeded" || res.ProviderID != "guptime:acme-prod:xyz789" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeUptimeCheck("api", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["check.target"] != "api.example.com" || got["check.protocol"] != "https" ||
		got["check.path"] != "/healthz" || got["check.period"] != "60s" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteUptimeCheck("api", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteUptimeCheckForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_, _ = w.Write([]byte(`{"userLabels":{"groundhold-capability":"someone-else","groundhold-environment":"prod"},` +
				`"monitoredResource":{"labels":{"host":"x"}},"httpCheck":{"path":"/","useSsl":true},"period":"60s"}`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d := uptimeDriver(t, srv)
	res := d.deleteUptimeCheck("api", "prod", "guptime:acme-prod:xyz789")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign check must refuse delete, got %+v", res)
	}
}

// uptimeOwnedServer reports our labels so the harness delete baseline succeeds.
func uptimeOwnedServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/uptimeCheckConfigs/xyz789"}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"userLabels":{"groundhold-capability":"api","groundhold-environment":"prod"},` +
					`"monitoredResource":{"labels":{"host":"api.example.com"}},"httpCheck":{"path":"/healthz","useSsl":true},"period":"60s"}`))
			case r.Method == "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}
