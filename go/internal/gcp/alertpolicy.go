// GCP Cloud Monitoring alerting policy request building (D106): the semantic core of
// the GCP capability.monitoring.alert driver — the SAME vocabulary AWS CloudWatch
// alarms and Azure metric alerts fulfil. An alert is ONE metric crossing ONE
// threshold, in one direction, optionally notifying a channel. A compound condition
// (AND/OR) is refused (invariant #4). Ownership is userLabels; the policy id is
// server-assigned.
package gcp

import (
	"fmt"
	"regexp"
)

const monitoringBaseURL = "https://monitoring.googleapis.com/v3"

// alertMetricOK bounds a metric type before it is placed in a condition filter.
var alertMetricOK = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]*$`)

// AlertPolicyPlan is the attribute-derived shape a create assembles.
type AlertPolicyPlan struct {
	DisplayName string
	Metric      string
	Threshold   float64
	Comparison  string // COMPARISON_GT | COMPARISON_LT
	Notify      bool
	Channel     string // notification channel resource name (impl); required when Notify
}

// BuildAlertPolicy maps capability.monitoring.alert attributes + impl to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildAlertPolicy(project, environment, capability string,
	attrs, impl map[string]any, generation int) (AlertPolicyPlan, error) {
	p := AlertPolicyPlan{DisplayName: resourceName(project, environment, capability, generation, 63)}
	metricSet, threshSet, cmpSet := false, false, false
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "alert.metric":
			p.Metric, _ = raw.(string)
			metricSet = true
		case "alert.threshold":
			f, ok := toFloat(raw)
			if !ok {
				return AlertPolicyPlan{}, fmt.Errorf("alert.threshold is not a number")
			}
			p.Threshold = f
			threshSet = true
		case "alert.comparison":
			switch raw {
			case "greater-than":
				p.Comparison = "COMPARISON_GT"
			case "less-than":
				p.Comparison = "COMPARISON_LT"
			default:
				return AlertPolicyPlan{}, fmt.Errorf("alert.comparison %v has no mapping", raw)
			}
			cmpSet = true
		case "alert.notify":
			p.Notify, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return AlertPolicyPlan{}, fmt.Errorf("service.managed=false cannot be honored by Cloud Monitoring")
			}
		default:
			return AlertPolicyPlan{}, fmt.Errorf(
				"attribute %s has no alerting-policy mapping — refusing rather than silently dropping it "+
					"(a compound condition is a logical expression, refused; one alert = one threshold)", path)
		}
	}
	if !metricSet || !alertMetricOK.MatchString(p.Metric) {
		return AlertPolicyPlan{}, fmt.Errorf("alert.metric %q is missing or not a valid metric type", p.Metric)
	}
	if !threshSet {
		return AlertPolicyPlan{}, fmt.Errorf("alert requires alert.threshold")
	}
	if !cmpSet {
		return AlertPolicyPlan{}, fmt.Errorf("alert requires alert.comparison")
	}
	if p.Notify {
		p.Channel, _ = impl["notification_channel"].(string)
		if p.Channel == "" {
			return AlertPolicyPlan{}, fmt.Errorf(
				"alert.notify=true requires implementation.notification_channel — refusing to create a " +
					"SILENT alert that claims to notify")
		}
	}
	if !projectOK.MatchString(project) {
		return AlertPolicyPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	return p, nil
}

func (p AlertPolicyPlan) createBody(capability, environment string) map[string]any {
	body := map[string]any{
		"displayName": p.DisplayName,
		"combiner":    "OR",
		"enabled":     true,
		"conditions": []any{map[string]any{
			"displayName": p.DisplayName + "-cond",
			"conditionThreshold": map[string]any{
				"filter":         `metric.type="` + p.Metric + `"`,
				"comparison":     p.Comparison,
				"thresholdValue": p.Threshold,
				"duration":       "60s",
			},
		}},
		"userLabels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
	}
	if p.Notify && p.Channel != "" {
		body["notificationChannels"] = []any{p.Channel}
	}
	return body
}

// toFloat accepts the numeric forms a YAML/JSON candidate produces.
func toFloat(raw any) (float64, bool) {
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
