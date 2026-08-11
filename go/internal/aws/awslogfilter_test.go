package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func cwLogFilterAttrs() map[string]any {
	return map[string]any{
		"metric.name":     "app_error_count",
		"metric.filter":   "ERROR",
		"metric.kind":     "counter",
		"service.managed": true,
	}
}

func cwLogFilterImpl() map[string]any {
	return map[string]any{"log_group": "/aws/lambda/app", "region": "eu-central-1"}
}

func TestBuildCWLogFilterHonors(t *testing.T) {
	p, err := BuildCWLogFilter("prod", "errors", cwLogFilterAttrs(), cwLogFilterImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.MetricName != "app_error_count" || p.FilterPattern != "ERROR" || p.MetricValue != "1" ||
		p.LogGroup != "/aws/lambda/app" || p.Region != "eu-central-1" {
		t.Fatalf("plan = %+v", p)
	}
	// gauge extracts a field into metricValue
	g := cwLogFilterAttrs()
	g["metric.kind"] = "gauge"
	gp, err := BuildCWLogFilter("prod", "lat", g,
		map[string]any{"log_group": "/aws/lambda/app", "region": "eu-central-1", "value_field": "latency"}, 1)
	if err != nil || gp.MetricValue != "$latency" {
		t.Fatalf("gauge plan: %+v err=%v", gp, err)
	}
}

func TestBuildCWLogFilterRefusals(t *testing.T) {
	full := cwLogFilterImpl
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"gauge-no-field": {map[string]any{"metric.kind": "gauge"}, full()},
		"bad-kind":       {map[string]any{"metric.kind": "histogram"}, full()},
		"empty-filter":   {map[string]any{"metric.filter": ""}, full()},
		"no-loggroup":    {nil, map[string]any{"region": "eu-central-1"}},
		"no-region":      {nil, map[string]any{"log_group": "/aws/lambda/app"}},
		"unmanaged":      {map[string]any{"service.managed": false}, full()},
	}
	for name, c := range cases {
		a := cwLogFilterAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildCWLogFilter("prod", "errors", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	for _, drop := range []string{"metric.name", "metric.filter", "metric.kind"} {
		a := cwLogFilterAttrs()
		delete(a, drop)
		if _, err := BuildCWLogFilter("prod", "errors", a, full(), 1); err == nil {
			t.Errorf("missing %s must refuse", drop)
		}
	}
}

func cwLogFilterServer(t *testing.T) *httptest.Server {
	t.Helper()
	fname, pattern, mname, mvalue := "", "", "", ""
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			target := r.Header.Get("X-Amz-Target")
			action := target[strings.LastIndex(target, ".")+1:]
			switch action {
			case "PutMetricFilter":
				body, _ := io.ReadAll(r.Body)
				var req struct {
					FilterName            string `json:"filterName"`
					FilterPattern         string `json:"filterPattern"`
					MetricTransformations []struct {
						MetricName  string `json:"metricName"`
						MetricValue string `json:"metricValue"`
					} `json:"metricTransformations"`
				}
				_ = json.Unmarshal(body, &req)
				fname, pattern = req.FilterName, req.FilterPattern
				if len(req.MetricTransformations) > 0 {
					mname, mvalue = req.MetricTransformations[0].MetricName, req.MetricTransformations[0].MetricValue
				}
				_, _ = w.Write([]byte(`{}`))
			case "DescribeMetricFilters":
				_, _ = w.Write([]byte(`{"metricFilters":[{"filterName":"` + fname + `","filterPattern":"` + pattern + `",` +
					`"metricTransformations":[{"metricName":"` + mname + `","metricValue":"` + mvalue + `"}]}]}`))
			case "DeleteMetricFilter":
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func cwLogFilterDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.LogsBaseURL = srv.URL
	return d
}

func TestCreateObserveDeleteCWLogFilter(t *testing.T) {
	srv := cwLogFilterServer(t)
	defer srv.Close()
	d := cwLogFilterDriver(t, srv)
	res := d.createCWLogFilter("prod", "errors", cwLogFilterAttrs(), cwLogFilterImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "cwlogfilter:eu-central-1:/aws/lambda/app:pv-errors-prod-") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeCWLogFilter("errors", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["metric.name"] != "app_error_count" || got["metric.filter"] != "ERROR" || got["metric.kind"] != "counter" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteCWLogFilter("errors", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// TestAdoptsExistingCWLogFilter enrols cwlogfilter in the D391 gate. PutMetricFilter is
// an UPSERT keyed by (log group, filter name) and the providerId is deterministic, so a
// re-run rewrites the filter in place — there is nothing to duplicate.
func TestAdoptsExistingCWLogFilter(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:           "aws/cwlogfilter",
		Classify:       cwLogsTargetRole,
		ExistingServer: func() *httptest.Server { return cwLogFilterServer(t) },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.LogsBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("cwlogfilter", "errors", "prod", cwLogFilterAttrs(), cwLogFilterImpl(), "errors", 1)
		},
		AllowedMutations: 1, // the upsert itself
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

func cwLogsTargetRole(req *http.Request, _ []byte) certifynet.Role {
	tgt := req.Header.Get("X-Amz-Target")
	switch tgt[strings.LastIndex(tgt, ".")+1:] {
	case "DescribeMetricFilters", "DescribeLogGroups", "ListTagsForResource":
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}
