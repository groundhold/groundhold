// CloudWatch alarm request building (D106): the semantic core of the AWS
// capability.monitoring.alert driver — the SAME vocabulary GCP alerting policies and
// Azure metric alerts fulfil. An alarm is ONE metric crossing ONE threshold, one
// direction, optionally notifying an SNS topic. CloudWatch is the AWS Query protocol
// and regional; the alarm name is deterministic (PutMetricAlarm is an upsert). The
// Period/EvaluationPeriods/Statistic are fixed defaults (tuning, not capability
// semantics). A compound alarm is refused (invariant #4).
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

var alarmMetricOK = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
var alarmNameOK = regexp.MustCompile(`^[A-Za-z0-9_+=,.@:/-]{1,255}$`)

// CWAlarmPlan is the attribute-derived shape a create assembles.
type CWAlarmPlan struct {
	AlarmName          string
	Namespace          string
	MetricName         string
	Threshold          float64
	ComparisonOperator string // GreaterThanThreshold | LessThanThreshold
	Notify             bool
	TopicArn           string // SNS ARN (impl); required when Notify
}

func alarmName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(cwBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "pv-" + slug + "-" + hex.EncodeToString(sum[:])[:8]
}

var cwBad = regexp.MustCompile(`[^a-z0-9-]+`)

// BuildCloudWatchAlarm maps capability.monitoring.alert attributes + impl to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildCloudWatchAlarm(account, environment, capability string,
	attrs, impl map[string]any, generation int) (CWAlarmPlan, error) {
	p := CWAlarmPlan{AlarmName: alarmName(environment, capability, generation)}
	metricSet, threshSet, cmpSet := false, false, false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "alert.metric":
			m, _ := raw.(string)
			if !alarmMetricOK.MatchString(m) || !strings.Contains(m, "/") {
				return CWAlarmPlan{}, fmt.Errorf("alert.metric %q must be Namespace/MetricName (e.g. AWS/EC2/CPUUtilization)", m)
			}
			i := strings.LastIndex(m, "/")
			p.Namespace, p.MetricName = m[:i], m[i+1:]
			metricSet = true
		case "alert.threshold":
			f, ok := toFloatAWS(raw)
			if !ok {
				return CWAlarmPlan{}, fmt.Errorf("alert.threshold is not a number")
			}
			p.Threshold = f
			threshSet = true
		case "alert.comparison":
			switch raw {
			case "greater-than":
				p.ComparisonOperator = "GreaterThanThreshold"
			case "less-than":
				p.ComparisonOperator = "LessThanThreshold"
			default:
				return CWAlarmPlan{}, fmt.Errorf("alert.comparison %v has no mapping", raw)
			}
			cmpSet = true
		case "alert.notify":
			p.Notify, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return CWAlarmPlan{}, fmt.Errorf("service.managed=false cannot be honored by CloudWatch")
			}
		default:
			return CWAlarmPlan{}, fmt.Errorf(
				"attribute %s has no CloudWatch alarm mapping — refusing rather than silently dropping it "+
					"(a compound alarm is a logical expression, refused; one alarm = one threshold)", path)
		}
	}
	if !metricSet {
		return CWAlarmPlan{}, fmt.Errorf("alert requires alert.metric (Namespace/MetricName)")
	}
	if !threshSet {
		return CWAlarmPlan{}, fmt.Errorf("alert requires alert.threshold")
	}
	if !cmpSet {
		return CWAlarmPlan{}, fmt.Errorf("alert requires alert.comparison")
	}
	if p.Notify {
		p.TopicArn, _ = impl["notification_channel"].(string)
		if p.TopicArn == "" {
			return CWAlarmPlan{}, fmt.Errorf(
				"alert.notify=true requires implementation.notification_channel (an SNS topic ARN) — " +
					"refusing to create a SILENT alarm that claims to notify")
		}
	}
	if !alarmNameOK.MatchString(p.AlarmName) {
		return CWAlarmPlan{}, fmt.Errorf("derived alarm name %q is invalid", p.AlarmName)
	}
	return p, nil
}

func toFloatAWS(raw any) (float64, bool) {
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
