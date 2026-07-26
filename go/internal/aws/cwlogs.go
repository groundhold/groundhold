// CloudWatch Logs log group request building: the semantic core of the AWS
// capability.monitoring.logs driver. A log group is the durable container CloudWatch
// Logs stores log events in; the capability an organization actually governs is WHERE
// the logs live (residency), HOW LONG they are kept (retention — a compliance AND cost
// control: a group with no retention policy keeps logs forever and bills forever), and
// whether they are encrypted with a CUSTOMER-managed key. STATEFUL: a log group HOLDS
// logs, so destroying it loses history (D47 friction on delete, conservative-honest
// retirement). CloudWatch Logs is the AWS JSON 1.1 protocol, regional; the group is
// content-addressed by (region, logGroupName). The KMS key id is impl detail (a key
// reference, never key material). Ownership is tags applied at birth.
//
// retention.days is a DURATION (not a bare number): the org writes "keep logs at least
// 90 days" as a first-class time quantity the four-valued verifier compares without
// coercion (retention.days gte 90d), and a duration carries the unit so a contract
// never silently means seconds. CloudWatch only accepts a FIXED set of retention day
// counts, so the builder maps the duration to whole days and REFUSES a value outside
// that set rather than silently rounding to a neighbour (which would over- or
// under-deliver on a retention guarantee).
package aws

import (
	"fmt"
	"strings"

	"groundhold/internal/scalars"
)

// cwLogsRetentionDays is the closed set of retention day counts CloudWatch Logs
// accepts (PutRetentionPolicy rejects anything else). A duration that does not map
// to one of these EXACT day counts is refused — never rounded to a neighbour.
var cwLogsRetentionDays = map[int]bool{
	1: true, 3: true, 5: true, 7: true, 14: true, 30: true, 60: true, 90: true,
	120: true, 150: true, 180: true, 365: true, 400: true, 545: true, 731: true,
	1096: true, 1827: true, 2192: true, 2557: true, 2922: true, 3288: true, 3653: true,
}

// cwLogsAllowedList is the same set, sorted, for a helpful refusal message.
const cwLogsAllowedList = "1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653"

// CWLogGroupName is the deterministic log group name (the idempotency/recovery
// handle) when the contract does not name one. Log group names allow
// [A-Za-z0-9_./#-] up to 512 chars; the pv- prefix + slug + hash keeps two installs
// in one account/region from colliding, and g>=2 (D48 replacements) coexist via the
// -gN salt.
func CWLogGroupName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(logFilterBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	tail := "-" + letterHash(environment+"|"+capability+genSuffix(generation), 8)
	const maxLen = 512
	name := "pv-" + slug + tail
	if len(name) > maxLen {
		name = name[:maxLen]
	}
	return name
}

// CWLogsPlan is the attribute-derived shape a create assembles.
type CWLogsPlan struct {
	LogGroupName  string
	Region        string
	RetentionDays int    // one of cwLogsRetentionDays (always set — retention is required)
	CMK           bool   // encryption.customerManagedKeys
	KmsKeyArn     string // impl operand, iff CMK
}

// BuildCWLogs maps capability.monitoring.logs attributes + impl to a plan. Every
// error is a preflight refusal, never a silent drop.
func BuildCWLogs(environment, capability string,
	attrs, impl map[string]any, generation int) (CWLogsPlan, error) {
	p := CWLogsPlan{}
	haveRetention := false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "retention.days":
			days, err := cwLogsDurationToDays(raw)
			if err != nil {
				return CWLogsPlan{}, fmt.Errorf("retention.days: %v", err)
			}
			if !cwLogsRetentionDays[days] {
				return CWLogsPlan{}, fmt.Errorf(
					"retention.days maps to %d day(s), which CloudWatch Logs does not accept — "+
						"it takes only these exact retention day counts: %s "+
						"(refusing to silently round to a neighbouring value)", days, cwLogsAllowedList)
			}
			p.RetentionDays = days
			haveRetention = true
		case "encryption.customerManagedKeys":
			p.CMK = (raw == true)
		case "service.managed":
			if raw != true {
				return CWLogsPlan{}, fmt.Errorf("service.managed=false cannot be honored by CloudWatch Logs")
			}
		default:
			return CWLogsPlan{}, fmt.Errorf(
				"attribute %s has no CloudWatch Logs mapping — refusing rather than silently dropping it", path)
		}
	}
	if !regionOK.MatchString(p.Region) {
		return CWLogsPlan{}, fmt.Errorf("capability.monitoring.logs requires a valid location.region")
	}
	// retention is the point of the capability: a log group with no retention policy
	// keeps logs forever and bills forever, so a create MUST set one.
	if !haveRetention {
		return CWLogsPlan{}, fmt.Errorf(
			"capability.monitoring.logs requires retention.days — a log group with no retention " +
				"policy never expires (unbounded cost and an unstated compliance posture)")
	}
	if p.CMK {
		key, _ := impl["kmsKeyArn"].(string)
		if strings.TrimSpace(key) == "" {
			return CWLogsPlan{}, fmt.Errorf(
				"encryption.customerManagedKeys=true requires implementation.kmsKeyArn " +
					"(the customer key arn is implementation detail, never a capability path)")
		}
		p.KmsKeyArn = key
	}
	// the log group name is an operand: a caller may pin an existing/AWS-dictated name
	// (e.g. a flow-logs or EKS control-plane group) via implementation.log_group;
	// otherwise it is derived deterministically.
	if name, _ := impl["log_group"].(string); strings.TrimSpace(name) != "" {
		p.LogGroupName = name
	} else {
		p.LogGroupName = CWLogGroupName(environment, capability, generation)
	}
	if !logGroupOK.MatchString(p.LogGroupName) || len(p.LogGroupName) > 512 {
		return CWLogsPlan{}, fmt.Errorf("log group name %q is not a valid CloudWatch log group name", p.LogGroupName)
	}
	return p, nil
}

// cwLogsDurationToDays converts a retention.days duration scalar to whole days. It
// parses through the same scalar grammar the verifier uses (so "90d" and "2160h" are
// both accepted, unlike time.ParseDuration which rejects the day unit), and refuses a
// non-positive or fractional-day value rather than truncating it.
func cwLogsDurationToDays(raw any) (int, error) {
	s, err := scalars.Parse(raw)
	if err != nil || s.Kind != scalars.Duration {
		return 0, fmt.Errorf("must be a duration (e.g. \"90d\" or \"2160h\"), got %v", raw)
	}
	ms, ok := s.Value.(float64)
	if !ok || ms <= 0 {
		return 0, fmt.Errorf("must be a positive duration, got %v", raw)
	}
	const msPerDay = 86_400_000.0
	days := ms / msPerDay
	if days != float64(int(days)) {
		return 0, fmt.Errorf("must be a whole number of days, got %v", raw)
	}
	return int(days), nil
}

// createBody is the CreateLogGroup request body (tags stamped at birth = ownership).
func (p CWLogsPlan) createBody(capability, environment string) map[string]any {
	return map[string]any{
		"logGroupName": p.LogGroupName,
		"tags": map[string]string{
			"groundhold-capability":  sanitizeTag(capability),
			"groundhold-environment": sanitizeTag(environment),
		},
	}
}
