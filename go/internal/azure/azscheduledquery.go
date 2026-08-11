// Azure scheduled query rule request building (D109): the Azure half of the
// capability.monitoring.logmetric driver — the SAME vocabulary GCP log metrics and AWS
// metric filters fulfil. Azure has no continuous metric-from-logs primitive; its honest
// realization is a scheduled query rule that EVALUATES a KQL query (the opaque filter) on
// a schedule rather than streaming — an honest per-cloud shape difference. counter uses a
// Count aggregation; gauge measures a column (from impl). The query is scoped to a Log
// Analytics workspace / resource (implementation.scope).
package azure

import (
	"fmt"
	"regexp"
	"sort"
)

const scheduledQueryAPIVersion = "2023-03-15-preview"

var azLMNameOK = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// AzureSQPlan is the attribute-derived shape a create assembles.
type AzureSQPlan struct {
	Name          string
	DisplayName   string
	Query         string
	IsGauge       bool
	MeasureColumn string
	Scope         string
	Location      string // the rule's region — Azure rejects "global" for this type (D890)
}

// BuildAzureScheduledQuery maps capability.monitoring.logmetric attributes + impl to a
// plan. Every error is a preflight refusal, never a silent drop.
func BuildAzureScheduledQuery(environment, capability string,
	attrs, impl map[string]any, generation int) (AzureSQPlan, error) {
	p := AzureSQPlan{Name: azResourceName("pv-lm", environment, capability, generation)}
	kindSet := false
	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, ap := range paths {
		raw := attrs[ap]
		switch ap {
		case "metric.name":
			p.DisplayName, _ = raw.(string)
			if !azLMNameOK.MatchString(p.DisplayName) {
				return AzureSQPlan{}, fmt.Errorf("metric.name %q is not a valid metric name", p.DisplayName)
			}
		case "metric.filter":
			p.Query, _ = raw.(string)
			if p.Query == "" {
				return AzureSQPlan{}, fmt.Errorf("metric.filter must not be empty")
			}
		case "metric.kind":
			switch raw {
			case "counter":
				p.IsGauge = false
			case "gauge":
				p.IsGauge = true
			default:
				return AzureSQPlan{}, fmt.Errorf("metric.kind %v has no mapping", raw)
			}
			kindSet = true
		case "service.managed":
			if raw != true {
				return AzureSQPlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure Monitor")
			}
		default:
			return AzureSQPlan{}, fmt.Errorf(
				"attribute %s has no scheduled-query mapping — refusing rather than silently dropping it "+
					"(the KQL query is opaque data)", ap)
		}
	}
	if p.DisplayName == "" {
		return AzureSQPlan{}, fmt.Errorf("scheduled query rule requires metric.name")
	}
	if p.Query == "" {
		return AzureSQPlan{}, fmt.Errorf("scheduled query rule requires metric.filter")
	}
	if !kindSet {
		return AzureSQPlan{}, fmt.Errorf("scheduled query rule requires metric.kind")
	}
	if p.IsGauge {
		p.MeasureColumn, _ = impl["value_field"].(string)
		if p.MeasureColumn == "" {
			return AzureSQPlan{}, fmt.Errorf("a gauge scheduled query rule requires implementation.value_field (the column to measure)")
		}
	}
	p.Scope, _ = impl["scope"].(string)
	if p.Scope == "" {
		return AzureSQPlan{}, fmt.Errorf(
			"azure scheduled query rule requires implementation.scope (the Log Analytics workspace / resource id it queries)")
	}
	// D890: Microsoft.Insights/scheduledQueryRules is a REGIONAL resource — Azure 400s
	// "location 'global' is not available for resource type scheduledqueryrules". The
	// driver used to hard-code "global", so the rule was uncreatable. The region is
	// substrate the operator provides (like AWS cwlogfilter's impl.region), typically the
	// scope workspace's region; refuse rather than guess a region the rule cannot live in.
	p.Location, _ = impl["location"].(string)
	if p.Location == "" {
		return AzureSQPlan{}, fmt.Errorf(
			"azure scheduled query rule requires implementation.location (the region the rule lives in, " +
				"typically the scope workspace's region — the resource type does not support 'global')")
	}
	return p, nil
}

func (p AzureSQPlan) createBody(tags map[string]any) map[string]any {
	criterion := map[string]any{
		"query":           p.Query,
		"timeAggregation": "Count",
		"operator":        "GreaterThan",
		"threshold":       0,
		"failingPeriods":  map[string]any{"numberOfEvaluationPeriods": 1, "minFailingPeriodsToAlert": 1},
	}
	if p.IsGauge {
		criterion["timeAggregation"] = "Average"
		criterion["metricMeasureColumn"] = p.MeasureColumn
	}
	return map[string]any{
		"location": p.Location,
		"tags":     tags,
		"properties": map[string]any{
			"displayName":         p.DisplayName,
			"enabled":             true,
			"severity":            3,
			"scopes":              []any{p.Scope},
			"evaluationFrequency": "PT5M",
			"windowSize":          "PT5M",
			"criteria":            map[string]any{"allOf": []any{criterion}},
		},
	}
}
