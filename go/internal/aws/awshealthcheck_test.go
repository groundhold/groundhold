package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func hcAttrs() map[string]any {
	return map[string]any{
		"check.target":    "api.example.com",
		"check.protocol":  "https",
		"check.path":      "/healthz",
		"check.period":    "30s",
		"service.managed": true,
	}
}

func TestBuildRoute53HealthCheckHonors(t *testing.T) {
	p, err := BuildRoute53HealthCheck("prod", "api", hcAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != "HTTPS" || p.FQDN != "api.example.com" || p.Port != 443 || p.Interval != 30 || p.CallerReference == "" {
		t.Fatalf("plan = %+v", p)
	}
	xml := p.createXML()
	if !strings.Contains(xml, "<Type>HTTPS</Type>") || !strings.Contains(xml, "<RequestInterval>30</RequestInterval>") ||
		!strings.Contains(xml, "<ResourcePath>/healthz</ResourcePath>") {
		t.Fatalf("xml = %s", xml)
	}
	// tcp with a port builds; a tcp xml has no ResourcePath
	tp, err := BuildRoute53HealthCheck("prod", "db",
		map[string]any{"check.target": "db.example.com", "check.protocol": "tcp", "check.period": "10s", "service.managed": true},
		map[string]any{"port": 5432}, 1)
	if err != nil || tp.Type != "TCP" || tp.Port != 5432 {
		t.Fatalf("tcp plan: %+v err=%v", tp, err)
	}
	if strings.Contains(tp.createXML(), "ResourcePath") {
		t.Fatalf("tcp xml must not carry a ResourcePath")
	}
}

func TestBuildRoute53HealthCheckRefusals(t *testing.T) {
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"bad-period":    {map[string]any{"check.period": "60s"}, nil}, // route53 = 10 or 30 only
		"bad-protocol":  {map[string]any{"check.protocol": "carrier-pigeon"}, nil},
		"tcp-with-path": {map[string]any{"check.protocol": "tcp", "check.path": "/x"}, map[string]any{"port": 22}},
		"tcp-no-port":   {map[string]any{"check.protocol": "tcp", "check.path": ""}, nil},
		"unmanaged":     {map[string]any{"service.managed": false}, nil},
	}
	for name, c := range cases {
		a := hcAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildRoute53HealthCheck("prod", "api", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	for _, drop := range []string{"check.target", "check.protocol", "check.period"} {
		a := hcAttrs()
		delete(a, drop)
		if _, err := BuildRoute53HealthCheck("prod", "api", a, nil, 1); err == nil {
			t.Errorf("missing %s must refuse", drop)
		}
	}
}

func r53hcServer(t *testing.T, tagCap string) *httptest.Server {
	t.Helper()
	hc := `<HealthCheck><Id>hc-123</Id><HealthCheckConfig>` +
		`<Type>HTTPS</Type><FullyQualifiedDomainName>api.example.com</FullyQualifiedDomainName>` +
		`<Port>443</Port><ResourcePath>/healthz</ResourcePath><RequestInterval>30</RequestInterval>` +
		`</HealthCheckConfig></HealthCheck>`
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && r.URL.Path == "/2013-04-01/healthcheck":
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`<CreateHealthCheckResponse>` + hc + `</CreateHealthCheckResponse>`))
			case strings.HasPrefix(r.URL.Path, "/2013-04-01/tags/") && r.Method == "POST":
				_, _ = w.Write([]byte(`<ChangeTagsForResourceResponse></ChangeTagsForResourceResponse>`))
			case strings.HasPrefix(r.URL.Path, "/2013-04-01/tags/") && r.Method == "GET":
				_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ResourceTagSet><Tags>` +
					`<Tag><Key>groundhold-capability</Key><Value>` + tagCap + `</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
					`</Tags></ResourceTagSet></ListTagsForResourceResponse>`))
			case strings.HasPrefix(r.URL.Path, "/2013-04-01/healthcheck/") && r.Method == "GET":
				_, _ = w.Write([]byte(`<GetHealthCheckResponse>` + hc + `</GetHealthCheckResponse>`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`<DeleteHealthCheckResponse></DeleteHealthCheckResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func r53hcDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Route53BaseURL = srv.URL
	return d
}

func TestCreateObserveDeleteRoute53HealthCheck(t *testing.T) {
	srv := r53hcServer(t, "api")
	defer srv.Close()
	d := r53hcDriver(t, srv)
	res := d.createRoute53HealthCheck("prod", "api", hcAttrs(), nil, 1)
	if res.Status != "succeeded" || res.ProviderID != "r53hc:hc-123" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeRoute53HealthCheck("api", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["check.target"] != "api.example.com" || got["check.protocol"] != "https" ||
		got["check.path"] != "/healthz" || got["check.period"] != "30s" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteRoute53HealthCheck("api", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteRoute53HealthCheckForeignRefused(t *testing.T) {
	srv := r53hcServer(t, "someone-else")
	defer srv.Close()
	d := r53hcDriver(t, srv)
	res := d.deleteRoute53HealthCheck("api", "prod", "r53hc:hc-123")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign check must refuse delete, got %+v", res)
	}
}
