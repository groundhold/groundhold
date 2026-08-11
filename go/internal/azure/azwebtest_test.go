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

func azWebtestAttrs() map[string]any {
	return map[string]any{
		"check.target":    "api.example.com",
		"check.protocol":  "https",
		"check.path":      "/healthz",
		"check.period":    "300s",
		"service.managed": true,
	}
}

func azWebtestImpl() map[string]any {
	return map[string]any{
		"resource_group":  "rg1",
		"location":        "westeurope", // D902: a web test is regional, never "global"
		"app_insights_id": "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.Insights/components/ai1",
	}
}

func TestBuildAzureWebtestHonors(t *testing.T) {
	p, err := BuildAzureWebtest("prod", "api", azWebtestAttrs(), azWebtestImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.URL != "https://api.example.com/healthz" || p.FrequencySec != 300 || p.AppInsightsID == "" {
		t.Fatalf("plan = %+v", p)
	}
}

// TestBuildAzureWebtestIsRegionalNotGlobal (D902): a web test is a REGIONAL resource —
// Azure refuses location "global" ("Unsupported location: global"). The create body must
// carry the operator's region, and a missing region must refuse rather than default to a
// value the platform rejects.
func TestBuildAzureWebtestIsRegionalNotGlobal(t *testing.T) {
	p, err := BuildAzureWebtest("prod", "api", azWebtestAttrs(), azWebtestImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	body := p.createBody(map[string]any{})
	if body["location"] != "westeurope" {
		t.Fatalf("web test location must be the region, got %v (a hardcoded \"global\" 400s)", body["location"])
	}
	// D902b: Azure requires the WebTest XML configuration, and it must carry the URL.
	cfg, ok := body["properties"].(map[string]any)["Configuration"].(map[string]any)
	if !ok || cfg["WebTest"] == "" {
		t.Fatal("createBody omits properties.Configuration.WebTest — Azure 400s the create without it")
	}
	if xml, _ := cfg["WebTest"].(string); !strings.Contains(xml, "https://api.example.com/healthz") || !strings.Contains(xml, "<WebTest") {
		t.Fatalf("WebTest XML does not carry the request URL: %v", cfg["WebTest"])
	}
	// a missing region must refuse, not fall back to "global"
	impl := azWebtestImpl()
	delete(impl, "location")
	if _, err := BuildAzureWebtest("prod", "api", azWebtestAttrs(), impl, 1); err == nil {
		t.Fatal("a web test with no location was accepted — it would be born global and rejected by Azure")
	}
}

func TestBuildAzureWebtestRefusals(t *testing.T) {
	noAI := map[string]any{"resource_group": "rg1"}
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"tcp-http-only":   {map[string]any{"check.protocol": "tcp"}, azWebtestImpl()}, // Azure HTTP-only
		"bad-period":      {map[string]any{"check.period": "60s"}, azWebtestImpl()},   // 300/600/900 only
		"bad-protocol":    {map[string]any{"check.protocol": "carrier-pigeon"}, azWebtestImpl()},
		"no-app-insights": {nil, noAI},
		"unmanaged":       {map[string]any{"service.managed": false}, azWebtestImpl()},
	}
	for name, c := range cases {
		a := azWebtestAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildAzureWebtest("prod", "api", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	for _, drop := range []string{"check.target", "check.protocol", "check.period"} {
		a := azWebtestAttrs()
		delete(a, drop)
		if _, err := BuildAzureWebtest("prod", "api", a, azWebtestImpl(), 1); err == nil {
			t.Errorf("missing %s must refuse", drop)
		}
	}
}

func azWebtestServer(t *testing.T) *httptest.Server {
	t.Helper()
	// D525: pre-seeded with the resource ALREADY STANDING under OUR ownership tags,
	// so CertifyCreateAdoptsExisting exercises the ADOPT path. Starting empty meant
	// the first GET 404'd and the driver simply CREATED one — a test named
	// "AdoptsExisting" that adopted nothing (D524).
	stored := map[string]any{
		"name": "gh-api-prod-1",
		"tags": map[string]any{
			"groundhold-capability":  "api",
			"groundhold-environment": "prod",
		},
		"properties": map[string]any{},
	}
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

func azWebtestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteAzureWebtest(t *testing.T) {
	srv := azWebtestServer(t)
	defer srv.Close()
	d := azWebtestDriver(t, srv)
	res := d.createAzureWebtest("prod", "api", azWebtestAttrs(), azWebtestImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "azwebtest:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeAzureWebtest("api", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["check.target"] != "api.example.com" || got["check.protocol"] != "https" ||
		got["check.path"] != "/healthz" || got["check.period"] != "300s" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteAzureWebtest("api", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteAzureWebtestForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"someone-else","groundhold-environment":"prod"},` +
				`"properties":{"Frequency":300,"Request":{"RequestUrl":"https://x/y"}}}`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d := azWebtestDriver(t, srv)
	res := d.deleteAzureWebtest("api", "prod", "azwebtest:"+testSub+":rg1:pv-webtest-api-prod-abcd1234")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign test must refuse delete, got %+v", res)
	}
}

// azWebtestOwnedServer reports our tags + a request URL so the harness delete baseline reaches DELETE.
func azWebtestOwnedServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
		case "GET":
			_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"api","groundhold-environment":"prod"},` +
				`"properties":{"Frequency":300,"Request":{"RequestUrl":"https://api.example.com/healthz"}}}`))
		case "DELETE":
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
}
