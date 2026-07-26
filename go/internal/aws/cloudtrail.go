// AWS CloudTrail request building (audit-trail slice): the PURE forward map of the
// AWS capability.audit.trail driver — the account's audit trail (a durable log of
// every AWS API call) as a governed, compliance-grade capability required before an
// EU platform (Acme) reaches production. What an organization GOVERNS about a trail:
// where it lives (residency), whether it spans all regions (scope), whether its logs
// are cryptographically tamper-evident (integrity — CloudTrail log file validation),
// whether the log objects are SSE-KMS encrypted with a customer key, and whether the
// trail is actually LOGGING (delivery.assured — a configured-but-stopped trail is a
// silent gap in the audit record). The trail NAME, the destination S3 bucket, the KMS
// key, the SNS topic and the CloudWatch Logs group are operator OPERANDS (the
// implementation: block, D26) — each a separate capability the operator owns, never
// stood up here. This file is PURE: it validates the shape and REFUSES before any
// mutation (an unmapped attribute or a missing required operand is a preflight
// refusal, never a silent drop); cloudtrail_net.go drives the plan over the wire.
package aws

import (
	"fmt"
	"regexp"
	"strings"
)

// cloudTrailNameOK bounds a trail name before it is interpolated into a providerId or
// a request body (D73 boundary). CloudTrail names are 3-128 chars, must start with a
// letter, and contain only letters, numbers, periods, underscores and dashes. The
// driver GENERATES a lowercase alnum+hyphen subset; the parser accepts the fuller safe
// set so a hand-adopted trail is not rejected.
var cloudTrailNameOK = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{2,127}$`)

// cloudTrailBad collapses everything outside the generated-name charset to a hyphen.
var cloudTrailBad = regexp.MustCompile(`[^a-z0-9-]+`)

// cloudTrailKmsArnOK bounds the CMK operand: a KMS key ARN (a reference, never key
// material — D53). Accepts a key or an alias ARN.
var cloudTrailKmsArnOK = regexp.MustCompile(`^arn:aws[A-Za-z0-9-]*:kms:[a-z0-9-]+:[0-9]{12}:(key|alias)/.+$`)

// cloudTrailLogsArnOK bounds the CloudWatch Logs log-group ARN operand.
var cloudTrailLogsArnOK = regexp.MustCompile(`^arn:aws[A-Za-z0-9-]*:logs:[a-z0-9-]+:[0-9]{12}:log-group:.+$`)

// cloudTrailRoleArnOK bounds the CloudWatch Logs delivery role ARN operand.
var cloudTrailRoleArnOK = regexp.MustCompile(`^arn:aws[A-Za-z0-9-]*:iam::[0-9]{12}:role/.+$`)

// CloudTrailName is the deterministic trail name — BOTH the idempotency handle
// (CreateTrail dedupes on the name within an account) AND, together with the
// ownership tags, the recovery handle: the providerId is knowable BEFORE the
// CreateTrail response (D29). environment+capability salt the hash so two installs in
// one account never collide; g>=2 (D48 replacements) coexist via the -gN salt.
func CloudTrailName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(cloudTrailBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	tail := "-" + letterHash(environment+"|"+capability+genSuffix(generation), 8)
	const maxLen = 128
	if len("pv-")+len(slug)+len(tail) > maxLen {
		slug = strings.TrimRight(slug[:maxLen-len("pv-")-len(tail)], "-")
	}
	name := "pv-" + slug + tail
	if len(name) > maxLen {
		name = name[:maxLen]
	}
	return name
}

// CloudTrailPlan is the attribute+operand-derived shape a create assembles. The SHAPE
// (multi-region, log validation, CMK, whether the trail logs) is driven by CAPABILITY
// attributes; the placement operands (the destination bucket, the KMS key, the SNS
// topic, the CloudWatch Logs group + delivery role) are OPERATOR input from the
// candidate implementation: block (D26) — separate capabilities, never provisioned here.
type CloudTrailPlan struct {
	Name                       string
	Region                     string
	MultiRegion                bool   // scope.multiRegion -> IsMultiRegionTrail
	LogValidation              bool   // integrity.logValidation -> EnableLogFileValidation
	CMK                        bool   // encryption.customerManagedKeys
	DeliveryAssured            bool   // delivery.assured -> StartLogging after create
	S3BucketName               string // operand, required (the delivery bucket)
	KmsKeyArn                  string // operand, required IFF CMK
	SnsTopicName               string // operand, optional
	CloudWatchLogsLogGroupArn  string // operand, optional
	CloudWatchLogsRoleArn      string // operand, required IFF CloudWatchLogsLogGroupArn
	IncludeGlobalServiceEvents bool   // operand, default true
}

// BuildCloudTrail maps capability.audit.trail attributes + implementation operands to
// a plan, or REFUSES. Every error is a preflight refusal (never a half-build): an
// unmapped attribute, or a missing/invalid required operand, is refused here, before
// the first CloudTrail mutation (invariant #4, D26). delivery.assured defaults to true
// — a configured-but-not-logging trail is a silent audit gap, so the create logs by
// default unless the contract explicitly asks otherwise.
func BuildCloudTrail(environment, capability string,
	attrs, impl map[string]any, generation int) (CloudTrailPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := CloudTrailPlan{
		DeliveryAssured:            true, // a trail that does not log is a dead trail
		IncludeGlobalServiceEvents: true, // capture IAM/STS/global-service events by default
	}

	// --- CAPABILITY attributes drive the SHAPE (refuse any unmapped attribute) ---
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "scope.multiRegion":
			b, ok := raw.(bool)
			if !ok {
				return CloudTrailPlan{}, fmt.Errorf("scope.multiRegion must be a bool")
			}
			p.MultiRegion = b
		case "integrity.logValidation":
			b, ok := raw.(bool)
			if !ok {
				return CloudTrailPlan{}, fmt.Errorf("integrity.logValidation must be a bool")
			}
			p.LogValidation = b
		case "encryption.customerManagedKeys":
			b, ok := raw.(bool)
			if !ok {
				return CloudTrailPlan{}, fmt.Errorf("encryption.customerManagedKeys must be a bool")
			}
			p.CMK = b
		case "delivery.assured":
			b, ok := raw.(bool)
			if !ok {
				return CloudTrailPlan{}, fmt.Errorf("delivery.assured must be a bool")
			}
			p.DeliveryAssured = b
		case "service.managed":
			if raw != true {
				return CloudTrailPlan{}, fmt.Errorf("service.managed=false cannot be honored — groundhold manages the trail it stands up")
			}
		default:
			return CloudTrailPlan{}, fmt.Errorf(
				"attribute %s has no CloudTrail mapping — refusing rather than silently dropping it "+
					"(the audit.trail vocab governs scope.multiRegion, integrity.logValidation, "+
					"encryption.customerManagedKeys, delivery.assured and location.region)", path)
		}
	}

	if !regionOK.MatchString(p.Region) {
		return CloudTrailPlan{}, fmt.Errorf("capability.audit.trail requires a valid location.region")
	}

	// --- OPERATOR operands supply the placement (implementation: block, D26) ---
	// the destination bucket is REQUIRED — a trail with no sink delivers to the void
	// and is not the audit record the contract asked for. It is a REFERENCE to a
	// separate capability.storage.object the operator owns, never stood up here.
	p.S3BucketName = strings.TrimSpace(implString(impl, "s3BucketName"))
	if p.S3BucketName == "" {
		return CloudTrailPlan{}, fmt.Errorf(
			"implementation.s3BucketName is required (the S3 bucket the trail delivers logs to — " +
				"a separate capability.storage.object the operator owns)")
	}

	// the CMK is REQUIRED iff customer-managed encryption is asked for. The ARN is a
	// REFERENCE (names a key), never key material (D53). Given but not asked -> ambiguous.
	p.KmsKeyArn = strings.TrimSpace(implString(impl, "kmsKeyArn"))
	if p.CMK {
		if p.KmsKeyArn == "" {
			return CloudTrailPlan{}, fmt.Errorf(
				"encryption.customerManagedKeys=true requires implementation.kmsKeyArn (a KMS key ARN, " +
					"a separate capability.key.encryption) — refusing to claim CMK encryption with no key")
		}
		if !cloudTrailKmsArnOK.MatchString(p.KmsKeyArn) {
			return CloudTrailPlan{}, fmt.Errorf("implementation.kmsKeyArn %q is not a valid KMS key ARN", p.KmsKeyArn)
		}
	} else if p.KmsKeyArn != "" {
		return CloudTrailPlan{}, fmt.Errorf(
			"implementation.kmsKeyArn was given but encryption.customerManagedKeys is not true — " +
				"a customer key only attaches to CMK encryption; refusing an ambiguous shape")
	}

	// the SNS topic is an optional notification operand (a separate capability.messaging.topic).
	p.SnsTopicName = strings.TrimSpace(implString(impl, "snsTopic"))

	// the CloudWatch Logs group is optional; iff given it needs a delivery role (AWS
	// requires the role CloudTrail assumes to write to the log group) — refuse a group
	// with no role rather than land a half-configured integration.
	p.CloudWatchLogsLogGroupArn = strings.TrimSpace(implString(impl, "cloudWatchLogsGroupArn"))
	p.CloudWatchLogsRoleArn = strings.TrimSpace(implString(impl, "cloudWatchLogsRoleArn"))
	if p.CloudWatchLogsLogGroupArn != "" {
		if !cloudTrailLogsArnOK.MatchString(p.CloudWatchLogsLogGroupArn) {
			return CloudTrailPlan{}, fmt.Errorf("implementation.cloudWatchLogsGroupArn %q is not a valid CloudWatch Logs log-group ARN", p.CloudWatchLogsLogGroupArn)
		}
		if p.CloudWatchLogsRoleArn == "" {
			return CloudTrailPlan{}, fmt.Errorf(
				"implementation.cloudWatchLogsGroupArn requires implementation.cloudWatchLogsRoleArn " +
					"(the IAM role CloudTrail assumes to deliver events to the log group)")
		}
		if !cloudTrailRoleArnOK.MatchString(p.CloudWatchLogsRoleArn) {
			return CloudTrailPlan{}, fmt.Errorf("implementation.cloudWatchLogsRoleArn %q is not a valid IAM role ARN", p.CloudWatchLogsRoleArn)
		}
	} else if p.CloudWatchLogsRoleArn != "" {
		return CloudTrailPlan{}, fmt.Errorf(
			"implementation.cloudWatchLogsRoleArn was given but cloudWatchLogsGroupArn is not — " +
				"the delivery role only attaches to a log-group integration; refusing an ambiguous shape")
	}

	// includeGlobalServiceEvents is an optional operand (default true).
	if v, ok := impl["includeGlobalServiceEvents"].(bool); ok {
		p.IncludeGlobalServiceEvents = v
	}

	// an optional trail-name operand (else the deterministic name), recoverable at
	// observe so a partial create repairs to the SAME trail.
	if given := strings.TrimSpace(implString(impl, "trailName")); given != "" {
		if !cloudTrailNameOK.MatchString(given) {
			return CloudTrailPlan{}, fmt.Errorf("implementation.trailName %q is invalid (letter-led, alnum/._- , 3-128)", given)
		}
		p.Name = given
	} else {
		p.Name = CloudTrailName(environment, capability, generation)
	}
	if !cloudTrailNameOK.MatchString(p.Name) {
		return CloudTrailPlan{}, fmt.Errorf("derived trail name %q is invalid", p.Name)
	}
	return p, nil
}

// createTrailBody is the CreateTrail request body: the trail shape + the ownership
// tags applied at birth (TagsList). Optional operands (KMS key, SNS topic, CloudWatch
// Logs group + role) are added only when present.
func (p CloudTrailPlan) createTrailBody(capability, environment string) map[string]any {
	body := map[string]any{
		"Name":                       p.Name,
		"S3BucketName":               p.S3BucketName,
		"IsMultiRegionTrail":         p.MultiRegion,
		"EnableLogFileValidation":    p.LogValidation,
		"IncludeGlobalServiceEvents": p.IncludeGlobalServiceEvents,
		"TagsList": []any{
			map[string]any{"Key": "groundhold-capability", "Value": sanitizeTag(capability)},
			map[string]any{"Key": "groundhold-environment", "Value": sanitizeTag(environment)},
		},
	}
	if p.CMK {
		body["KmsKeyId"] = p.KmsKeyArn
	}
	if p.SnsTopicName != "" {
		body["SnsTopicName"] = p.SnsTopicName
	}
	if p.CloudWatchLogsLogGroupArn != "" {
		body["CloudWatchLogsLogGroupArn"] = p.CloudWatchLogsLogGroupArn
		body["CloudWatchLogsRoleArn"] = p.CloudWatchLogsRoleArn
	}
	return body
}

// updateTrailBody is the UpdateTrail request body: the mutable shape CloudTrail can
// change in place (multi-region scope, log-file validation, the CMK). The destination
// bucket and global-service-events flag are re-sent so an UpdateTrail never
// inadvertently narrows the trail; the SNS topic and CloudWatch Logs integration are
// re-sent when present.
func (p CloudTrailPlan) updateTrailBody() map[string]any {
	body := map[string]any{
		"Name":                       p.Name,
		"S3BucketName":               p.S3BucketName,
		"IsMultiRegionTrail":         p.MultiRegion,
		"EnableLogFileValidation":    p.LogValidation,
		"IncludeGlobalServiceEvents": p.IncludeGlobalServiceEvents,
	}
	if p.CMK {
		body["KmsKeyId"] = p.KmsKeyArn
	}
	if p.SnsTopicName != "" {
		body["SnsTopicName"] = p.SnsTopicName
	}
	if p.CloudWatchLogsLogGroupArn != "" {
		body["CloudWatchLogsLogGroupArn"] = p.CloudWatchLogsLogGroupArn
		body["CloudWatchLogsRoleArn"] = p.CloudWatchLogsRoleArn
	}
	return body
}

// classifyCloudTrailChange (D46): PURE — can a capability.audit.trail transition be
// honored in place? scope.multiRegion / integrity.logValidation / encryption.customerManagedKeys
// are single UpdateTrail-call mutable; delivery.assured is mutable via StartLogging/
// StopLogging (a single call, cheaper than a replacement, and the create composite
// already performs StartLogging). location.region is immutable — a trail's home region
// is fixed at create, so a region change is a replacement, not a patch. service.managed
// / cost.monthly are unsupported platform/projection properties.
func classifyCloudTrailChange(path string) (string, string) {
	switch path {
	case "scope.multiRegion":
		return "mutable", "in-place via UpdateTrail (IsMultiRegionTrail)"
	case "integrity.logValidation":
		return "mutable", "in-place via UpdateTrail (EnableLogFileValidation)"
	case "encryption.customerManagedKeys":
		return "mutable", "in-place via UpdateTrail (KmsKeyId) — enabling/rotating the CMK"
	case "delivery.assured":
		return "mutable", "in-place via StartLogging/StopLogging"
	case "location.region":
		return "immutable", "a trail's home region is fixed at create — a region change is a replacement, not an in-place patch"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no CloudTrail in-place mapping for " + path
	}
}
