// CloudWatch alarm request building (D106): the semantic core of the AWS
// capability.monitoring.alert driver — the SAME vocabulary GCP alerting policies and
// Azure metric alerts fulfil. An alarm is ONE metric crossing ONE threshold, one
// direction, optionally notifying an SNS topic. CloudWatch is the AWS Query protocol
// and regional; the alarm name is deterministic (PutMetricAlarm is an upsert).
// A compound alarm is refused (invariant #4).
//
// Period/EvaluationPeriods/Statistic used to be fixed defaults here, called "tuning,
// not capability semantics". That reading was wrong and D695 records why: with
// Average over 300s and one period, "three failures in a quarter hour" cannot be
// stated at all, and with no dimensions an alarm on a dimensioned metric watches a
// series the exporter never emits. They are operands now — CloudWatch's own
// vocabulary, read from `implementation:`, defaulted to exactly what this file sent
// before.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"groundhold/internal/provider"
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

	// D695: how the metric is EVALUATED — operands, because they are CloudWatch's
	// own vocabulary, but not tuning. Without dimensions an alarm on a dimensioned
	// metric watches the dimensionless variant, which most exporters never emit: the
	// alarm exists, the contract reads as covered, and it can never fire.
	Dimensions        []CWDimension // sorted by name; empty means the whole metric
	Statistic         string        // Sum | Maximum | Minimum | Average | SampleCount
	PeriodSeconds     int
	EvaluationPeriods int
	TreatMissingData  string // breaching | notBreaching | ignore | missing ("" = CloudWatch default)
}

// CWDimension is one metric dimension. Order is fixed by sorting on Name so the
// same candidate always renders the same request.
type CWDimension struct {
	Name  string
	Value string
}

// Defaults kept from the pre-D695 driver, so a candidate that declares none of the
// evaluation operands builds exactly the alarm it built before.
const (
	cwDefaultStatistic  = "Average"
	cwDefaultPeriod     = 300
	cwDefaultEvalPeriod = 1
)

// The closed sets CloudWatch accepts. A value outside them is refused here rather
// than by the API mid-apply.
var cwStatistics = map[string]bool{
	"Sum": true, "Maximum": true, "Minimum": true, "Average": true, "SampleCount": true}

var cwMissingData = map[string]bool{
	"breaching": true, "notBreaching": true, "ignore": true, "missing": true}

var cwDimensionNameOK = regexp.MustCompile(`^[\x20-\x7E]{1,255}$`)

// Reserved observation paths for the alarm's evaluation operands (F-LC3). observe
// records the LIVE values here and OperandTargets renders the DECLARED ones the same
// way, so a change to `dimensions` on an alarm that already exists is DRIFT — not the
// silent no-op it would otherwise be, which is the very pretense this entry closes.
const (
	cwDimensionsOperand  = provider.OperandPrefix + "dimensions"
	cwStatisticOperand   = provider.OperandPrefix + "statistic"
	cwPeriodOperand      = provider.OperandPrefix + "period_seconds"
	cwEvalPeriodsOperand = provider.OperandPrefix + "evaluation_periods"
	cwMissingDataOperand = provider.OperandPrefix + "treat_missing_data"
)

// cwDimensionCanon renders dimensions as one comparable string. Sorted by name (the
// plan already is), `=` between name and value, `,` between pairs. Both sides of the
// comparison go through this function, never one through it and one around it.
func cwDimensionCanon(dims []CWDimension) string {
	parts := make([]string, 0, len(dims))
	for _, d := range dims {
		parts = append(parts, d.Name+"="+d.Value)
	}
	return strings.Join(parts, ",")
}

// cwMissingDataCanon: CloudWatch reports "missing" for an alarm that never set
// TreatMissingData, so the DESIRED side must say "missing" too — otherwise every
// alarm built before this operand existed reads as drifted the moment it is observed.
func cwMissingDataCanon(v string) string {
	if v == "" {
		return "missing"
	}
	return v
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
	if err := readAlarmEvaluation(&p, impl); err != nil {
		return CWAlarmPlan{}, err
	}
	return p, nil
}

// readAlarmEvaluation reads the five evaluation operands (D695). Each is optional and
// each defaults to what this driver sent before, so an existing candidate is unchanged;
// each is validated against CloudWatch's closed set here rather than at the API, so a
// typo refuses at compile instead of mid-apply.
func readAlarmEvaluation(p *CWAlarmPlan, impl map[string]any) error {
	p.Statistic, p.PeriodSeconds, p.EvaluationPeriods = cwDefaultStatistic, cwDefaultPeriod, cwDefaultEvalPeriod

	if raw, ok := impl["statistic"]; ok {
		s, _ := raw.(string)
		if !cwStatistics[s] {
			return fmt.Errorf("implementation.statistic %v is not one of Sum, Maximum, Minimum, "+
				"Average, SampleCount (percentiles are ExtendedStatistic and are not built)", raw)
		}
		p.Statistic = s
	}
	// implIntOperand is the D674 reading: absent leaves the default alone, present
	// but unreadable refuses BY NAME rather than falling back to a default that would
	// build a different alarm than the candidate declares.
	if n, set, err := implIntOperand(impl, "period_seconds", "implementation"); err != nil {
		return err
	} else if set {
		// CloudWatch accepts 10, 20 and 30 (high resolution) or any multiple of 60.
		if n <= 0 || (n != 10 && n != 20 && n != 30 && n%60 != 0) {
			return fmt.Errorf("implementation.period_seconds %v must be 10, 20, 30 or a "+
				"multiple of 60 — CloudWatch accepts nothing else", impl["period_seconds"])
		}
		p.PeriodSeconds = n
	}
	if n, set, err := implIntOperand(impl, "evaluation_periods", "implementation"); err != nil {
		return err
	} else if set {
		if n < 1 {
			return fmt.Errorf("implementation.evaluation_periods %v must be a positive whole number",
				impl["evaluation_periods"])
		}
		p.EvaluationPeriods = n
	}
	if raw, ok := impl["treat_missing_data"]; ok {
		s, _ := raw.(string)
		if !cwMissingData[s] {
			return fmt.Errorf("implementation.treat_missing_data %v is not one of breaching, "+
				"notBreaching, ignore, missing", raw)
		}
		p.TreatMissingData = s
	}
	if raw, ok := impl["dimensions"]; ok {
		dims, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("implementation.dimensions must be a map of dimension name to "+
				"value, got %T", raw)
		}
		if len(dims) == 0 {
			// An empty map reads as "I thought about dimensions and chose none", which
			// is what OMITTING the key already says. Refuse the ambiguity rather than
			// build the dimensionless alarm the author was trying to avoid.
			return fmt.Errorf("implementation.dimensions is empty — omit the key to alarm on " +
				"the metric as a whole; an empty map states nothing")
		}
		if len(dims) > 30 {
			return fmt.Errorf("implementation.dimensions has %d entries — CloudWatch alarms "+
				"carry at most 30", len(dims))
		}
		for _, name := range sortedKeys(dims) {
			v, ok := dims[name].(string)
			if !ok {
				return fmt.Errorf("implementation.dimensions[%s] must be a string, got %T",
					name, dims[name])
			}
			if !cwDimensionNameOK.MatchString(name) || !cwDimensionNameOK.MatchString(v) {
				return fmt.Errorf("implementation.dimensions[%s]: name and value must each be "+
					"1..255 printable ASCII characters", name)
			}
			p.Dimensions = append(p.Dimensions, CWDimension{Name: name, Value: v})
		}
	}
	return nil
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

// cloudWatchOperandTargets (F-LC3): the evaluation operands this alarm SHOULD hold,
// rendered exactly as observeCloudWatchAlarm records the live ones. PURE — the
// account and generation do not reach any of these values, so placeholders are safe.
func cloudWatchOperandTargets(attrs, impl map[string]any) ([]provider.OperandTarget, error) {
	plan, err := BuildCloudWatchAlarm("000000000000", "", "cw", attrs, impl, 1)
	if err != nil {
		return nil, err
	}
	// sorted by Path, the same determinism the Lambda targets keep
	return []provider.OperandTarget{
		{Path: cwDimensionsOperand, Desired: cwDimensionCanon(plan.Dimensions)},
		{Path: cwEvalPeriodsOperand, Desired: strconv.Itoa(plan.EvaluationPeriods)},
		{Path: cwPeriodOperand, Desired: strconv.Itoa(plan.PeriodSeconds)},
		{Path: cwStatisticOperand, Desired: plan.Statistic},
		{Path: cwMissingDataOperand, Desired: cwMissingDataCanon(plan.TreatMissingData)},
	}, nil
}
