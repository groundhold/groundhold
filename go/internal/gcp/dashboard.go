// GCP Cloud Monitoring dashboard request building (D107): the semantic core of the
// GCP capability.monitoring.dashboard driver — the SAME vocabulary AWS CloudWatch
// dashboards and Azure Portal dashboards fulfil. A dashboard is a flat SET of metrics,
// each auto-rendered as one XyChart widget in a mosaic layout. Custom widget layout is
// refused (free-form canvas, not capability semantics). widgetCount = len(metrics);
// the driver refuses a declared count that contradicts. Ownership is a displayName
// marker (dashboards carry no labels).
package gcp

import (
	"fmt"
	"regexp"
)

const dashboardBaseURL = "https://monitoring.googleapis.com/v1"

var dashMetricOK = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]*$`)

// DashboardPlan is the attribute-derived shape a create assembles.
type DashboardPlan struct {
	DisplayName string
	Metrics     []string
}

// BuildDashboard maps capability.monitoring.dashboard attributes to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildDashboard(project, environment, capability string,
	attrs, impl map[string]any, generation int) (DashboardPlan, error) {
	p := DashboardPlan{DisplayName: dashDisplayName(capability, environment)}
	countSet, declaredCount := false, 0
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "dashboard.metrics":
			metrics, err := toStringListDash(raw)
			if err != nil {
				return DashboardPlan{}, fmt.Errorf("dashboard.metrics is not a list of strings: %v", err)
			}
			for _, m := range metrics {
				if !dashMetricOK.MatchString(m) {
					return DashboardPlan{}, fmt.Errorf("metric %q is not a valid metric type", m)
				}
			}
			p.Metrics = metrics
		case "dashboard.widgetCount":
			f, ok := toFloatDash(raw)
			if !ok {
				return DashboardPlan{}, fmt.Errorf("dashboard.widgetCount is not a number")
			}
			declaredCount = int(f)
			countSet = true
		case "service.managed":
			if raw != true {
				return DashboardPlan{}, fmt.Errorf("service.managed=false cannot be honored by Cloud Monitoring")
			}
		default:
			return DashboardPlan{}, fmt.Errorf(
				"attribute %s has no dashboard mapping — refusing rather than silently dropping it "+
					"(a hand-placed widget layout is free-form content, not capability semantics)", path)
		}
	}
	if len(p.Metrics) == 0 {
		return DashboardPlan{}, fmt.Errorf("a dashboard requires a non-empty dashboard.metrics set (an empty dashboard is useless)")
	}
	// widgetCount is derived (one widget per metric); a declared count that
	// contradicts is a false claim, refused.
	if countSet && declaredCount != len(p.Metrics) {
		return DashboardPlan{}, fmt.Errorf(
			"dashboard.widgetCount=%d contradicts the %d metrics (one widget per metric) — refusing a false claim",
			declaredCount, len(p.Metrics))
	}
	if !projectOK.MatchString(project) {
		return DashboardPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	return p, nil
}

// dashDisplayName is the deterministic ownership marker (dashboards carry no labels).
func dashDisplayName(capability, environment string) string {
	return "groundhold " + capability + " (" + environment + ")"
}

func (p DashboardPlan) createBody() map[string]any {
	tiles := make([]any, 0, len(p.Metrics))
	for i, m := range p.Metrics {
		tiles = append(tiles, map[string]any{
			"width": 6, "height": 4, "xPos": (i % 2) * 6, "yPos": (i / 2) * 4,
			"widget": map[string]any{
				"title": m,
				"xyChart": map[string]any{
					"dataSets": []any{map[string]any{
						"timeSeriesQuery": map[string]any{
							"timeSeriesFilter": map[string]any{
								"filter": `metric.type="` + m + `"`,
							},
						},
					}},
				},
			},
		})
	}
	return map[string]any{
		"displayName":  p.DisplayName,
		"mosaicLayout": map[string]any{"columns": 12, "tiles": tiles},
	}
}

func toStringListDash(raw any) ([]string, error) {
	if ss, ok := raw.([]string); ok {
		return ss, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("not a list")
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := it.(string)
		if !ok {
			return nil, fmt.Errorf("element %v is not a string", it)
		}
		out = append(out, s)
	}
	return out, nil
}

func toFloatDash(raw any) (float64, bool) {
	switch v := raw.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	}
	return 0, false
}
