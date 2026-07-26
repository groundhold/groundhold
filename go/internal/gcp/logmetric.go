// GCP Cloud Logging log-based metric request building (D109): the semantic core of the
// GCP capability.monitoring.logmetric driver — the SAME vocabulary AWS metric filters and
// Azure scheduled query rules fulfil. A log metric turns a log FILTER (opaque query data,
// passed through) into a metric. counter counts matching entries; gauge extracts a value
// via a valueExtractor (field from impl). The metric NAME is the id (author-provided);
// ownership is a description marker (log metrics carry no labels).
package gcp

import (
	"fmt"
	"regexp"
)

const loggingBaseURL = "https://logging.googleapis.com/v2"

var logMetricNameOK = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// LogMetricPlan is the attribute-derived shape a create assembles.
type LogMetricPlan struct {
	Name        string
	Filter      string
	IsGauge     bool
	ValueField  string
	Description string
}

// BuildLogMetric maps capability.monitoring.logmetric attributes + impl to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildLogMetric(project, environment, capability string,
	attrs, impl map[string]any, generation int) (LogMetricPlan, error) {
	p := LogMetricPlan{Description: logMetricDescription(capability, environment)}
	kindSet := false
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "metric.name":
			p.Name, _ = raw.(string)
			if !logMetricNameOK.MatchString(p.Name) {
				return LogMetricPlan{}, fmt.Errorf("metric.name %q is not a valid metric name", p.Name)
			}
		case "metric.filter":
			p.Filter, _ = raw.(string)
			if p.Filter == "" {
				return LogMetricPlan{}, fmt.Errorf("metric.filter must not be empty")
			}
		case "metric.kind":
			switch raw {
			case "counter":
				p.IsGauge = false
			case "gauge":
				p.IsGauge = true
			default:
				return LogMetricPlan{}, fmt.Errorf("metric.kind %v has no mapping", raw)
			}
			kindSet = true
		case "service.managed":
			if raw != true {
				return LogMetricPlan{}, fmt.Errorf("service.managed=false cannot be honored by Cloud Logging")
			}
		default:
			return LogMetricPlan{}, fmt.Errorf(
				"attribute %s has no log-metric mapping — refusing rather than silently dropping it "+
					"(the filter is opaque data; groundhold never builds operators over a log query)", path)
		}
	}
	if p.Name == "" {
		return LogMetricPlan{}, fmt.Errorf("log metric requires metric.name")
	}
	if p.Filter == "" {
		return LogMetricPlan{}, fmt.Errorf("log metric requires metric.filter")
	}
	if !kindSet {
		return LogMetricPlan{}, fmt.Errorf("log metric requires metric.kind")
	}
	if p.IsGauge {
		p.ValueField, _ = impl["value_field"].(string)
		if p.ValueField == "" {
			return LogMetricPlan{}, fmt.Errorf("a gauge log metric requires implementation.value_field (the field to extract)")
		}
	}
	if !projectOK.MatchString(project) {
		return LogMetricPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	return p, nil
}

func logMetricDescription(capability, environment string) string {
	return "groundhold-managed " + capability + " (" + environment + ")"
}

func (p LogMetricPlan) createBody() map[string]any {
	body := map[string]any{
		"name":        p.Name,
		"description": p.Description,
		"filter":      p.Filter,
	}
	if p.IsGauge {
		body["valueExtractor"] = "EXTRACT(jsonPayload." + p.ValueField + ")"
		body["metricDescriptor"] = map[string]any{"metricKind": "DELTA", "valueType": "DISTRIBUTION"}
	} else {
		body["metricDescriptor"] = map[string]any{"metricKind": "DELTA", "valueType": "INT64"}
	}
	return body
}
