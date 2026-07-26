// Azure Monitor metric alert request building (D106): the Azure half of the
// capability.monitoring.alert driver — the SAME vocabulary GCP alerting policies and
// AWS CloudWatch alarms fulfil. A metric alert is ONE metric crossing ONE threshold,
// one direction, optionally notifying an action group. A compound (multi-criteria)
// alert is refused (invariant #4). The honest Azure-specific requirement: a metric
// alert MUST have a SCOPE (the target resource it watches), which rides in the
// implementation block — GCP/AWS alerts are not resource-scoped this way.
package azure

import (
	"fmt"
	"regexp"
	"sort"
)

const metricAlertAPIVersion = "2018-03-01"

var azAlertMetricOK = regexp.MustCompile(`^[A-Za-z0-9._/ -]+$`) // Azure metric names may contain spaces

// AzureAlertPlan is the attribute-derived shape a create assembles.
type AzureAlertPlan struct {
	Name        string
	MetricName  string
	Operator    string // GreaterThan | LessThan
	Threshold   float64
	Notify      bool
	ActionGroup string // action group id (impl); required when Notify
	Scope       string // target resource id (impl); required
}

// BuildAzureAlert maps capability.monitoring.alert attributes + impl to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildAzureAlert(environment, capability string,
	attrs, impl map[string]any, generation int) (AzureAlertPlan, error) {
	p := AzureAlertPlan{Name: azResourceName("pv-alert", environment, capability, generation)}
	metricSet, threshSet, cmpSet := false, false, false
	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "alert.metric":
			p.MetricName, _ = raw.(string)
			if !azAlertMetricOK.MatchString(p.MetricName) {
				return AzureAlertPlan{}, fmt.Errorf("alert.metric %q is not a valid metric name", p.MetricName)
			}
			metricSet = true
		case "alert.threshold":
			f, ok := toFloatAz(raw)
			if !ok {
				return AzureAlertPlan{}, fmt.Errorf("alert.threshold is not a number")
			}
			p.Threshold = f
			threshSet = true
		case "alert.comparison":
			switch raw {
			case "greater-than":
				p.Operator = "GreaterThan"
			case "less-than":
				p.Operator = "LessThan"
			default:
				return AzureAlertPlan{}, fmt.Errorf("alert.comparison %v has no mapping", raw)
			}
			cmpSet = true
		case "alert.notify":
			p.Notify, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return AzureAlertPlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure Monitor")
			}
		default:
			return AzureAlertPlan{}, fmt.Errorf(
				"attribute %s has no metric-alert mapping — refusing rather than silently dropping it "+
					"(a compound criteria is a logical expression, refused; one alert = one threshold)", path)
		}
	}
	if !metricSet {
		return AzureAlertPlan{}, fmt.Errorf("alert requires alert.metric")
	}
	if !threshSet {
		return AzureAlertPlan{}, fmt.Errorf("alert requires alert.threshold")
	}
	if !cmpSet {
		return AzureAlertPlan{}, fmt.Errorf("alert requires alert.comparison")
	}
	// Azure-specific honest requirement: a metric alert is always SCOPED to a target
	// resource (unlike GCP/AWS), which is topology — it rides in the impl block.
	p.Scope, _ = impl["target_resource"].(string)
	if p.Scope == "" {
		return AzureAlertPlan{}, fmt.Errorf(
			"azure metric alert requires implementation.target_resource (the resource id the alert " +
				"watches) — an Azure metric alert must be scoped to a target")
	}
	if p.Notify {
		p.ActionGroup, _ = impl["notification_channel"].(string)
		if p.ActionGroup == "" {
			return AzureAlertPlan{}, fmt.Errorf(
				"alert.notify=true requires implementation.notification_channel (an action group id) — " +
					"refusing to create a SILENT alert that claims to notify")
		}
	}
	return p, nil
}

func toFloatAz(raw any) (float64, bool) {
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
