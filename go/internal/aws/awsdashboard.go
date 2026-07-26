// CloudWatch dashboard request building (D107): the semantic core of the AWS
// capability.monitoring.dashboard driver — the SAME vocabulary GCP and Azure
// dashboards fulfil. A dashboard is a flat SET of metrics, each auto-rendered as one
// metric widget in the DashboardBody. CloudWatch dashboards are GLOBAL; the dashboard
// name is deterministic (PutDashboard is an upsert). Custom widget layout is refused.
// widgetCount = len(metrics); a declared count that contradicts is refused.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var dashMetricOK = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
var dashNameOK = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)

// CWDashPlan is the attribute-derived shape a create assembles.
type CWDashPlan struct {
	DashboardName string
	Metrics       []string
	Region        string // widget region (impl)
}

func cwDashName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(cwDashBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "pv-" + slug + "-" + hex.EncodeToString(sum[:])[:8]
}

var cwDashBad = regexp.MustCompile(`[^a-z0-9_-]+`)

// BuildCWDashboard maps capability.monitoring.dashboard attributes + impl to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildCWDashboard(environment, capability string,
	attrs, impl map[string]any, generation int) (CWDashPlan, error) {
	p := CWDashPlan{DashboardName: cwDashName(environment, capability, generation)}
	countSet, declaredCount := false, 0
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "dashboard.metrics":
			metrics, err := toStringListDashAWS(raw)
			if err != nil {
				return CWDashPlan{}, fmt.Errorf("dashboard.metrics is not a list of strings: %v", err)
			}
			for _, m := range metrics {
				if !dashMetricOK.MatchString(m) || !strings.Contains(m, "/") {
					return CWDashPlan{}, fmt.Errorf("metric %q must be Namespace/MetricName", m)
				}
			}
			p.Metrics = metrics
		case "dashboard.widgetCount":
			f, ok := toFloatDashAWS(raw)
			if !ok {
				return CWDashPlan{}, fmt.Errorf("dashboard.widgetCount is not a number")
			}
			declaredCount = int(f)
			countSet = true
		case "service.managed":
			if raw != true {
				return CWDashPlan{}, fmt.Errorf("service.managed=false cannot be honored by CloudWatch")
			}
		default:
			return CWDashPlan{}, fmt.Errorf(
				"attribute %s has no CloudWatch dashboard mapping — refusing rather than silently dropping it "+
					"(a hand-placed widget layout is free-form content, not capability semantics)", path)
		}
	}
	if len(p.Metrics) == 0 {
		return CWDashPlan{}, fmt.Errorf("a dashboard requires a non-empty dashboard.metrics set")
	}
	if countSet && declaredCount != len(p.Metrics) {
		return CWDashPlan{}, fmt.Errorf(
			"dashboard.widgetCount=%d contradicts the %d metrics (one widget per metric) — refusing a false claim",
			declaredCount, len(p.Metrics))
	}
	p.Region, _ = impl["region"].(string)
	if !regionOK.MatchString(p.Region) {
		return CWDashPlan{}, fmt.Errorf("dashboard requires implementation.region (the widgets' metric region)")
	}
	if !dashNameOK.MatchString(p.DashboardName) {
		return CWDashPlan{}, fmt.Errorf("derived dashboard name %q is invalid", p.DashboardName)
	}
	return p, nil
}

// body assembles the DashboardBody JSON: one metric widget per metric.
func (p CWDashPlan) body() string {
	widgets := make([]any, 0, len(p.Metrics))
	for i, m := range p.Metrics {
		idx := strings.LastIndex(m, "/")
		ns, metric := m[:idx], m[idx+1:]
		widgets = append(widgets, map[string]any{
			"type": "metric", "x": (i % 2) * 12, "y": (i / 2) * 6, "width": 12, "height": 6,
			"properties": map[string]any{
				"metrics": []any{[]any{ns, metric}},
				"view":    "timeSeries",
				"region":  p.Region,
				"title":   m,
			},
		})
	}
	b, _ := json.Marshal(map[string]any{"widgets": widgets})
	return string(b)
}

func toStringListDashAWS(raw any) ([]string, error) {
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

func toFloatDashAWS(raw any) (float64, bool) {
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
