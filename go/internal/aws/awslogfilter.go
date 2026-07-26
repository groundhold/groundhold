// CloudWatch Logs metric filter request building (D109): the semantic core of the AWS
// capability.monitoring.logmetric driver — the SAME vocabulary GCP log metrics and Azure
// scheduled query rules fulfil. A metric filter turns a filterPattern (opaque log query,
// passed through) over a log group into a CloudWatch metric. counter emits metricValue
// "1" per match; gauge emits "$field". CloudWatch Logs is the AWS JSON protocol, regional;
// the filter is content-addressed by (logGroup, filterName). The log group is impl.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var logFilterNameOK = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
var logGroupOK = regexp.MustCompile(`^[A-Za-z0-9_./#-]+$`)
var metricNameOK = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)

const logMetricNamespace = "groundhold/logmetrics"

// CWLogFilterPlan is the attribute-derived shape a create assembles.
type CWLogFilterPlan struct {
	FilterName    string
	MetricName    string
	FilterPattern string
	MetricValue   string // "1" (counter) or "$field" (gauge)
	IsGauge       bool
	LogGroup      string
	Region        string
}

func logFilterName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(logFilterBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "pv-" + slug + "-" + hex.EncodeToString(sum[:])[:8]
}

var logFilterBad = regexp.MustCompile(`[^a-z0-9-]+`)

// BuildCWLogFilter maps capability.monitoring.logmetric attributes + impl to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildCWLogFilter(environment, capability string,
	attrs, impl map[string]any, generation int) (CWLogFilterPlan, error) {
	p := CWLogFilterPlan{FilterName: logFilterName(environment, capability, generation), MetricValue: "1"}
	kindSet := false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "metric.name":
			p.MetricName, _ = raw.(string)
			if !metricNameOK.MatchString(p.MetricName) {
				return CWLogFilterPlan{}, fmt.Errorf("metric.name %q is not a valid metric name", p.MetricName)
			}
		case "metric.filter":
			p.FilterPattern, _ = raw.(string)
			if p.FilterPattern == "" {
				return CWLogFilterPlan{}, fmt.Errorf("metric.filter must not be empty")
			}
		case "metric.kind":
			switch raw {
			case "counter":
				p.IsGauge = false
			case "gauge":
				p.IsGauge = true
			default:
				return CWLogFilterPlan{}, fmt.Errorf("metric.kind %v has no mapping", raw)
			}
			kindSet = true
		case "service.managed":
			if raw != true {
				return CWLogFilterPlan{}, fmt.Errorf("service.managed=false cannot be honored by CloudWatch Logs")
			}
		default:
			return CWLogFilterPlan{}, fmt.Errorf(
				"attribute %s has no metric filter mapping — refusing rather than silently dropping it "+
					"(the filter pattern is opaque data)", path)
		}
	}
	if p.MetricName == "" {
		return CWLogFilterPlan{}, fmt.Errorf("metric filter requires metric.name")
	}
	if p.FilterPattern == "" {
		return CWLogFilterPlan{}, fmt.Errorf("metric filter requires metric.filter")
	}
	if !kindSet {
		return CWLogFilterPlan{}, fmt.Errorf("metric filter requires metric.kind")
	}
	if p.IsGauge {
		field, _ := impl["value_field"].(string)
		if field == "" {
			return CWLogFilterPlan{}, fmt.Errorf("a gauge metric filter requires implementation.value_field (the field to extract)")
		}
		p.MetricValue = "$" + field
	}
	p.LogGroup, _ = impl["log_group"].(string)
	if !logGroupOK.MatchString(p.LogGroup) {
		return CWLogFilterPlan{}, fmt.Errorf("metric filter requires implementation.log_group (the CloudWatch log group)")
	}
	p.Region, _ = impl["region"].(string)
	if !regionOK.MatchString(p.Region) {
		return CWLogFilterPlan{}, fmt.Errorf("metric filter requires implementation.region")
	}
	if !logFilterNameOK.MatchString(p.FilterName) {
		return CWLogFilterPlan{}, fmt.Errorf("derived filter name %q is invalid", p.FilterName)
	}
	return p, nil
}

func (p CWLogFilterPlan) putBody() string {
	b, _ := json.Marshal(map[string]any{
		"logGroupName":  p.LogGroup,
		"filterName":    p.FilterName,
		"filterPattern": p.FilterPattern,
		"metricTransformations": []any{map[string]any{
			"metricName":      p.MetricName,
			"metricNamespace": logMetricNamespace,
			"metricValue":     p.MetricValue,
		}},
	})
	return string(b)
}
