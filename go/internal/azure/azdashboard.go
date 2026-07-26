// Azure Portal dashboard request building (D107): the Azure half of the
// capability.monitoring.dashboard driver — the SAME vocabulary GCP and AWS dashboards
// fulfil. A dashboard is a flat SET of metrics, each auto-rendered as one
// MonitorChartPart tile in a lens. Custom part layout is refused (free-form canvas).
// The honest Azure requirement: a chart tile is scoped to a target resource
// (implementation.target_resource), the same per-cloud need metric alerts carry (D106).
package azure

import (
	"regexp"
	"sort"
	"strconv"

	"fmt"
)

const portalDashAPIVersion = "2020-09-01-preview"

var azDashMetricOK = regexp.MustCompile(`^[A-Za-z0-9._/ -]+$`) // Azure metric names may contain spaces

// AzureDashPlan is the attribute-derived shape a create assembles.
type AzureDashPlan struct {
	Name    string
	Metrics []string
	Target  string // the resource the tiles chart (impl)
}

// BuildAzureDashboard maps capability.monitoring.dashboard attributes + impl to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildAzureDashboard(environment, capability string,
	attrs, impl map[string]any, generation int) (AzureDashPlan, error) {
	p := AzureDashPlan{Name: azResourceName("pv-dash", environment, capability, generation)}
	countSet, declaredCount := false, 0
	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "dashboard.metrics":
			metrics, err := toStringListDashAz(raw)
			if err != nil {
				return AzureDashPlan{}, fmt.Errorf("dashboard.metrics is not a list of strings: %v", err)
			}
			for _, m := range metrics {
				if !azDashMetricOK.MatchString(m) {
					return AzureDashPlan{}, fmt.Errorf("metric %q is not a valid metric name", m)
				}
			}
			p.Metrics = metrics
		case "dashboard.widgetCount":
			f, ok := toFloatDashAz(raw)
			if !ok {
				return AzureDashPlan{}, fmt.Errorf("dashboard.widgetCount is not a number")
			}
			declaredCount = int(f)
			countSet = true
		case "service.managed":
			if raw != true {
				return AzureDashPlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure Portal")
			}
		default:
			return AzureDashPlan{}, fmt.Errorf(
				"attribute %s has no dashboard mapping — refusing rather than silently dropping it "+
					"(a hand-placed tile layout is free-form content, not capability semantics)", path)
		}
	}
	if len(p.Metrics) == 0 {
		return AzureDashPlan{}, fmt.Errorf("a dashboard requires a non-empty dashboard.metrics set")
	}
	if countSet && declaredCount != len(p.Metrics) {
		return AzureDashPlan{}, fmt.Errorf(
			"dashboard.widgetCount=%d contradicts the %d metrics (one tile per metric) — refusing a false claim",
			declaredCount, len(p.Metrics))
	}
	p.Target, _ = impl["target_resource"].(string)
	if p.Target == "" {
		return AzureDashPlan{}, fmt.Errorf(
			"azure dashboard requires implementation.target_resource (the resource its chart tiles show)")
	}
	return p, nil
}

func (p AzureDashPlan) createBody(tags map[string]any) map[string]any {
	parts := map[string]any{}
	for i, m := range p.Metrics {
		parts[strconv.Itoa(i)] = map[string]any{
			"position": map[string]any{"x": (i % 2) * 6, "y": (i / 2) * 4, "rowSpan": 4, "colSpan": 6},
			"metadata": map[string]any{
				"type": "Extension/HubsExtension/PartType/MonitorChartPart",
				"inputs": []any{map[string]any{
					"name": "options",
					"value": map[string]any{"chart": map[string]any{
						"metrics": []any{map[string]any{
							"name":             m,
							"resourceMetadata": map[string]any{"id": p.Target},
						}},
					}},
				}},
			},
		}
	}
	return map[string]any{
		"location": "global",
		"tags":     tags,
		"properties": map[string]any{
			"lenses": map[string]any{"0": map[string]any{"order": 0, "parts": parts}},
		},
	}
}

func toStringListDashAz(raw any) ([]string, error) {
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

func toFloatDashAz(raw any) (float64, bool) {
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
