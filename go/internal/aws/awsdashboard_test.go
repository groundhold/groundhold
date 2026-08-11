package aws

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func awsDashAttrs() map[string]any {
	return map[string]any{
		"dashboard.metrics":     []any{"AWS/EC2/CPUUtilization", "AWS/ELB/RequestCount"},
		"dashboard.widgetCount": float64(2),
		"service.managed":       true,
	}
}

func awsDashImpl() map[string]any { return map[string]any{"region": "eu-central-1"} }

func TestBuildCWDashboardHonors(t *testing.T) {
	p, err := BuildCWDashboard("prod", "golden", awsDashAttrs(), awsDashImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Metrics) != 2 || !dashNameOK.MatchString(p.DashboardName) || p.Region != "eu-central-1" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.body()
	if !strings.Contains(body, `"CPUUtilization"`) || !strings.Contains(body, `"AWS/EC2"`) ||
		!strings.Contains(body, `"eu-central-1"`) {
		t.Fatalf("body = %s", body)
	}
}

func TestBuildCWDashboardRefusals(t *testing.T) {
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"widgetcount-lie": {map[string]any{"dashboard.widgetCount": float64(9)}, awsDashImpl()},
		"empty-metrics":   {map[string]any{"dashboard.metrics": []any{}}, awsDashImpl()},
		"no-namespace":    {map[string]any{"dashboard.metrics": []any{"CPUUtilization"}}, awsDashImpl()},
		"no-region":       {nil, map[string]any{}},
		"unmanaged":       {map[string]any{"service.managed": false}, awsDashImpl()},
		"layout-attr":     {map[string]any{"dashboard.layout": "custom"}, awsDashImpl()},
	}
	for name, c := range cases {
		a := awsDashAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildCWDashboard("prod", "golden", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := awsDashAttrs()
	delete(a, "dashboard.metrics")
	if _, err := BuildCWDashboard("prod", "golden", a, awsDashImpl(), 1); err == nil {
		t.Error("missing dashboard.metrics must refuse")
	}
}

func cwDashServer(t *testing.T) *httptest.Server {
	t.Helper()
	body := ""
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			switch r.PostForm.Get("Action") {
			case "PutDashboard":
				body = r.PostForm.Get("DashboardBody")
				_, _ = w.Write([]byte(`<PutDashboardResponse><PutDashboardResult></PutDashboardResult></PutDashboardResponse>`))
			case "GetDashboard":
				// D700: before anything was put, the dashboard does NOT exist. The
				// fixture used to answer 200 with an empty body — a dashboard that
				// exists and is empty — which is a different world from an absent one,
				// and the create now reads this answer before deciding to write.
				if body == "" {
					w.WriteHeader(400)
					_, _ = w.Write([]byte(`<ErrorResponse><Error>` +
						`<Code>ResourceNotFoundException</Code></Error></ErrorResponse>`))
					return
				}
				_, _ = w.Write([]byte(`<GetDashboardResponse><GetDashboardResult><DashboardBody>` + body +
					`</DashboardBody></GetDashboardResult></GetDashboardResponse>`))
			case "DeleteDashboards":
				_, _ = w.Write([]byte(`<DeleteDashboardsResponse></DeleteDashboardsResponse>`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func cwDashDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.CloudWatchDashBaseURL = srv.URL
	return d
}

func TestCreateObserveDeleteCWDashboard(t *testing.T) {
	srv := cwDashServer(t)
	defer srv.Close()
	d := cwDashDriver(t, srv)
	res := d.createCWDashboard("prod", "golden", awsDashAttrs(), awsDashImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "cwdash:pv-golden-prod-") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeCWDashboard("golden", res.ProviderID)
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
	if len(metrics) != 2 || metrics[0] != "AWS/EC2/CPUUtilization" {
		t.Fatalf("metrics not reflected: %+v", got["dashboard.metrics"])
	}
	if del := d.deleteCWDashboard("golden", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// TestAdoptsExistingCWDashboard enrols cloudwatchdash in the D391 gate. PutDashboard is
// an UPSERT keyed by dashboard name: a re-run overwrites the body rather than making a
// second dashboard, so the identity bound is the whole property.
func TestAdoptsExistingCWDashboard(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:     "aws/cloudwatchdash",
		Classify: cwQueryRole,
		ExistingServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					body := make([]byte, r.ContentLength)
					_, _ = r.Body.Read(body)
					v, _ := url.ParseQuery(string(body))
					switch v.Get("Action") {
					case "PutDashboard":
						_, _ = w.Write([]byte(`<PutDashboardResponse><PutDashboardResult>` +
							`</PutDashboardResult></PutDashboardResponse>`))
					case "GetDashboard":
						// D700: the estate must contain OUR dashboard, not a stranger's.
						// This fixture served `{"widgets":[{},{}]}` — a foreign body — and
						// the probe passed anyway, because the create never read. It reads
						// now, and a foreign body is refused rather than overwritten, so
						// the fixture has to mean what the probe's own doc comment says:
						// the resource this create targets ALREADY EXISTS and is ours.
						plan, err := BuildCWDashboard("prod", "golden", awsDashAttrs(), awsDashImpl(), 1)
						if err != nil {
							w.WriteHeader(500)
							return
						}
						_, _ = w.Write([]byte(`<GetDashboardResponse><GetDashboardResult><DashboardBody>` +
							plan.body() + `</DashboardBody></GetDashboardResult></GetDashboardResponse>`))
					default:
						w.WriteHeader(400)
					}
				}))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.CloudWatchDashBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("cloudwatchdash", "golden", "prod", awsDashAttrs(), awsDashImpl(), "golden", 1)
		},
		// D700: zero. A dashboard whose content already IS what this contract
		// describes is bound without writing anything — the property in its
		// strongest form, and only reachable now that the create reads first.
		AllowedMutations: 0,
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
