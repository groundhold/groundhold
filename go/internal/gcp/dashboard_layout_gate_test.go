package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D1236. `dashboard.metrics` is a SET, and the vocabulary names its purpose: a contract
// constrains it with `subset-of` — "the dashboard charts only approved metrics". That
// makes UNDER-reporting the dangerous direction: omit a metric and the constraint reads
// SATISFIED over a dashboard charting something the allowlist never named. An empty set
// is a subset of everything.
//
// The driver decoded ONE of the API's four layouts (`mosaicLayout`) and ONE of its ~18
// widget kinds (`xyChart`). Measured against the two commonest real shapes, both
// returned `[]` for a dashboard charting one metric:
//
//	gridLayout + xyChart   -> []
//	mosaicLayout + scorecard -> []
//
// It now walks every layout and classifies every widget, and — this is the part that
// matters — a widget it cannot read makes it WITHHOLD the set rather than ship a
// partial one. A partial set is not a smaller truth; it is a different claim.

func dashboardObserve(t *testing.T, body string) (map[string]any, []string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/dashboards/") {
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":{"code":404}}`))
	}))
	defer srv.Close()
	d := NewDriver("acme-prod")
	d.DashboardBaseURL = srv.URL
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	obs, diags, err := d.observeDashboard("golden", gdashProviderID("acme-prod", "gh"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	return got, diags
}

const cpuFilter = `metric.type=\"compute.googleapis.com/instance/cpu/utilization\"`

// The two shapes that measured EMPTY. Both must now report the metric they chart.
func TestEveryLayoutAndReadableWidgetContributesItsMetric(t *testing.T) {
	for name, body := range map[string]string{
		"gridLayout + xyChart": `{"displayName":"d","gridLayout":{"widgets":[` +
			`{"xyChart":{"dataSets":[{"timeSeriesQuery":{"timeSeriesFilter":{"filter":"` + cpuFilter + `"}}}]}}]}}`,
		"mosaicLayout + xyChart": `{"displayName":"d","mosaicLayout":{"tiles":[{"widget":` +
			`{"xyChart":{"dataSets":[{"timeSeriesQuery":{"timeSeriesFilter":{"filter":"` + cpuFilter + `"}}}]}}}]}}`,
		"mosaicLayout + scorecard": `{"displayName":"d","mosaicLayout":{"tiles":[{"widget":` +
			`{"scorecard":{"timeSeriesQuery":{"timeSeriesFilter":{"filter":"` + cpuFilter + `"}}}}}]}}`,
		"rowLayout + xyChart": `{"displayName":"d","rowLayout":{"widgets":[` +
			`{"xyChart":{"dataSets":[{"timeSeriesQuery":{"timeSeriesFilter":{"filter":"` + cpuFilter + `"}}}]}}]}}`,
	} {
		got, diags := dashboardObserve(t, body)
		v, present := got["dashboard.metrics"]
		if !present {
			t.Errorf("%s: the set must be observed, got diags %v", name, diags)
			continue
		}
		list, _ := v.([]string)
		if len(list) != 1 || list[0] != "compute.googleapis.com/instance/cpu/utilization" {
			t.Errorf("%s: dashboard.metrics = %v, want the one metric it charts", name, list)
		}
	}
}

// A widget kind the driver cannot read makes the SET incomplete, so the set is withheld
// and the reason names the widget. This is the false-green: a partial set passes
// subset-of.
func TestAnUnreadableWidgetWithholdsTheWholeSet(t *testing.T) {
	body := `{"displayName":"d","mosaicLayout":{"tiles":[` +
		`{"widget":{"xyChart":{"dataSets":[{"timeSeriesQuery":{"timeSeriesFilter":{"filter":"` + cpuFilter + `"}}}]}}},` +
		`{"widget":{"pieChart":{"dataSets":[{"timeSeriesQuery":{"timeSeriesFilter":{"filter":"` + cpuFilter + `"}}}]}}}]}}`
	got, diags := dashboardObserve(t, body)
	if v, present := got["dashboard.metrics"]; present {
		t.Fatalf("one widget could not be read, so the SET is incomplete and must be "+
			"withheld — a partial set satisfies subset-of. Got %v", v)
	}
	var named bool
	for _, d := range diags {
		if strings.Contains(d, "dashboard.metrics not observed") && strings.Contains(d, "pieChart") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the withholding must name the widget it could not read: %v", diags)
	}
}

// An INERT widget charts nothing, so its presence is not a gap — the set still ships.
// Without this the fix would withhold on every dashboard carrying a text box.
func TestInertWidgetsDoNotWithholdTheSet(t *testing.T) {
	body := `{"displayName":"d","mosaicLayout":{"tiles":[` +
		`{"widget":{"text":{"content":"hello"}}},` +
		`{"widget":{"xyChart":{"dataSets":[{"timeSeriesQuery":{"timeSeriesFilter":{"filter":"` + cpuFilter + `"}}}]}}}]}}`
	got, diags := dashboardObserve(t, body)
	list, present := got["dashboard.metrics"].([]string)
	if !present || len(list) != 1 {
		t.Fatalf("a text widget charts nothing and must not withhold the set, got %v / %v",
			got["dashboard.metrics"], diags)
	}
}

// widgetCount counted the tiles of the ONE decoded layout, so a dashboard in any other
// reported ZERO widgets — a number, stated as measured, about a dashboard full of them.
func TestWidgetCountSeesEveryLayout(t *testing.T) {
	body := `{"displayName":"d","gridLayout":{"widgets":[{"text":{}},{"text":{}},{"text":{}}]}}`
	got, _ := dashboardObserve(t, body)
	if got["dashboard.widgetCount"] != float64(3) {
		t.Fatalf("widgetCount = %v, want 3 — the count must not depend on which layout "+
			"the dashboard happens to use", got["dashboard.widgetCount"])
	}
}

// A dashboard in no layout this driver knows must not report zero widgets as a fact.
func TestNoRecognisedLayoutWithholdsTheCountRatherThanReportingZero(t *testing.T) {
	got, diags := dashboardObserve(t, `{"displayName":"d"}`)
	if v, present := got["dashboard.widgetCount"]; present {
		t.Fatalf("with no recognised layout the count is unknown, not %v", v)
	}
	var named bool
	for _, d := range diags {
		if strings.Contains(d, "dashboard.widgetCount not observed") {
			named = true
		}
	}
	if !named {
		t.Fatalf("withholding the count must be diagnosed: %v", diags)
	}
}
