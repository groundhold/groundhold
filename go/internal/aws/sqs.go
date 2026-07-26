// SQS request building (D95): the semantic core of the AWS messaging.queue
// driver — the SAME capability.messaging.queue vocabulary GCP Pub/Sub fulfils
// (the provider-agnostic thesis, D85). SQS is the AWS Query protocol (like RDS/
// SNS) and a queue is REGIONAL, so the queue URL is fully deterministic from
// (region, account, name) — the handle is always knowable, even on a lost
// create response (D29). Unlike a topic, a queue HOLDS the author's data (the
// message backlog), so the vocab is richer: delivery guarantee / ordering (a
// FIFO queue, create-time immutable), retention, encryption, exposure.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"groundhold/internal/scalars"
)

// sqsDLQArnOK bounds a dead-letter target ARN (D73 boundary). A DLQ is itself a
// separate messaging.queue (a queue ARN), so the shape is the standard SQS ARN.
var sqsDLQArnOK = regexp.MustCompile(`^arn:aws:sqs:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]{1,80}(\.fifo)?$`)

// sqsRedrivePolicy is the JSON RedrivePolicy attribute value. A struct (not a
// map) so json.Marshal emits a DETERMINISTIC key order (golden/round-trip tests).
type sqsRedrivePolicy struct {
	DeadLetterTargetArn string `json:"deadLetterTargetArn"`
	MaxReceiveCount     int    `json:"maxReceiveCount"`
}

// intOperand pulls a whole-number operand from the free-form impl block (D26),
// which may arrive as int / int64 / float64 depending on the loader.
func intOperand(raw any) (int, bool) {
	switch v := raw.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		if v != float64(int64(v)) {
			return 0, false
		}
		return int(v), true
	}
	return 0, false
}

// sqsNameOK bounds a queue name before it is interpolated into a URL path
// (D73 boundary). SQS allows [A-Za-z0-9_-] up to 80; a FIFO queue name MUST end
// in ".fifo". The driver GENERATES a lowercase alnum+hyphen subset (+.fifo), but
// the parser accepts the full safe set so a hand-adopted name is not rejected.
var sqsNameOK = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}(\.fifo)?$`)

// sqsBad collapses everything outside the generated queue-name charset.
var sqsBad = regexp.MustCompile(`[^a-z0-9-]+`)

// QueueName is the deterministic queue name (the idempotency mechanism — SQS
// CreateQueue dedupes on the name within the account+region). A FIFO queue name
// MUST end in ".fifo" (create-time immutable, so a delivery.guarantee/ordering
// change is a replacement — D48). Account+environment+capability salt the hash;
// g>=2 (D48 replacements) coexist via the -gN salt. The ".fifo" suffix is
// reserved out of the 80-char budget.
func QueueName(account, environment, capability string, generation int, fifo bool) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(sqsBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	hashInput := account + "|" + environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	tail := "-" + hex.EncodeToString(sum[:])[:8]
	suffix := ""
	if fifo {
		suffix = ".fifo"
	}
	maxLen := 80 - len(suffix)
	if len(slug)+len(tail) > maxLen {
		slug = slug[:maxLen-len(tail)]
		slug = strings.TrimRight(slug, "-")
	}
	name := slug + tail
	if name == "" || !(name[0] >= 'a' && name[0] <= 'z') {
		name = "q" + strings.TrimLeft(name, "-")
	}
	return name + suffix
}

// SQSPlan is the semantic outcome of mapping the vocabulary to SQS: the
// deterministic name/region, whether it is FIFO (name ends .fifo), the
// CreateQueue attribute map (retention, encryption, dedup) and whether a public
// resource policy is required. The shell assembles the ARN/URL (needs the
// account) and the ordered call sequence.
type SQSPlan struct {
	Name       string
	Region     string
	FIFO       bool
	Attributes map[string]string // CreateQueue Attribute.N map (never the Policy — the shell adds it, it needs the ARN)
	Public     bool
}

// BuildSQSCreate maps capability.messaging.queue attributes + the impl block to
// an SQS create plan. Every error is a refusal apply surfaces in preflight,
// before any mutation — never a silently dropped attribute, never a clamp.
func BuildSQSCreate(account, environment, capability string,
	attrs, impl map[string]any, generation int) (SQSPlan, error) {
	if generation < 1 {
		generation = 1
	}
	region := ""
	public := false
	atRest := false
	cmek := false
	exactlyOnce := false
	ordering := false
	deadLetter := false
	retentionSeconds := 0
	hasRetention := false

	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			region, _ = raw.(string)
		case "network.publicExposure":
			public, _ = raw.(bool)
		case "encryption.atRest":
			// Only true is meaningful (vocab). false = SQS's unencrypted default,
			// honorably honored by doing nothing (SQS does NOT encrypt at rest by
			// default) — unlike Pub/Sub which always encrypts.
			atRest, _ = raw.(bool)
		case "encryption.customerManagedKeys":
			cmek, _ = raw.(bool)
		case "delivery.guarantee":
			g, _ := raw.(string)
			switch g {
			case "exactly-once":
				// SQS: exactly-once dedup is a FIFO-queue property (dedup within a
				// 5-minute window). NECESSARY, not SUFFICIENT for exactly-once
				// PROCESSING (needs producer dedup ids + correct ack) — the vocab
				// and the outcome probe say so.
				exactlyOnce = true
			case "at-least-once", "":
				// the SQS baseline — a standard queue.
			default:
				return SQSPlan{}, fmt.Errorf("delivery.guarantee %q is not a valid value", g)
			}
		case "ordering.enabled":
			ordering, _ = raw.(bool)
		case "reliability.deadLetter":
			// posture bool: only true is meaningful (false = no DLQ, SQS's default).
			deadLetter, _ = raw.(bool)
		case "retention.minimum":
			s, err := scalars.Parse(raw)
			if err != nil || s.Kind != scalars.Duration {
				return SQSPlan{}, fmt.Errorf("retention.minimum is not a duration")
			}
			ms, ok := s.Value.(float64)
			if !ok {
				return SQSPlan{}, fmt.Errorf("retention.minimum is not a duration")
			}
			secs := ms / 1000
			if secs != float64(int64(secs)) {
				return SQSPlan{}, fmt.Errorf(
					"retention.minimum must be a whole number of seconds, got %v", secs)
			}
			retentionSeconds = int(secs)
			hasRetention = true
		case "service.managed":
			if raw != true {
				return SQSPlan{}, fmt.Errorf("service.managed=false cannot be honored by SQS")
			}
		default:
			return SQSPlan{}, fmt.Errorf(
				"attribute %s has no SQS mapping — refusing rather than silently dropping it", path)
		}
	}

	if region == "" {
		return SQSPlan{}, fmt.Errorf("sqs requires location.region")
	}
	if !regionOK.MatchString(region) {
		return SQSPlan{}, fmt.Errorf("location.region %q is not a valid AWS region", region)
	}

	// FIFO: exactly-once dedup OR ordering both require a FIFO queue (create-time
	// immutable — the ".fifo" suffix is part of the name, so a later change is a
	// replacement, D48).
	fifo := exactlyOnce || ordering
	attrsOut := map[string]string{}
	if fifo {
		attrsOut["FifoQueue"] = "true"
		if exactlyOnce {
			// absent producer-supplied dedup ids, content-based dedup is what makes
			// a FIFO queue actually dedupe — required to honor exactly-once.
			attrsOut["ContentBasedDeduplication"] = "true"
		}
	}

	// retention envelope: 60s .. 1209600s (14d). Outside -> REFUSE loudly (vocab:
	// never clamp a data-loss floor).
	if hasRetention {
		if retentionSeconds < 60 || retentionSeconds > 1209600 {
			return SQSPlan{}, fmt.Errorf(
				"retention.minimum %ds is outside the SQS envelope (60s..1209600s) — "+
					"refusing rather than clamping", retentionSeconds)
		}
		attrsOut["MessageRetentionPeriod"] = strconv.Itoa(retentionSeconds)
	}

	// Encryption decision (honest, documented):
	//   - CMEK true  -> a customer key is REQUIRED (impl.kms_key_id); the SSE-SQS
	//     managed key is NOT customer-managed, so it does not satisfy the constraint.
	//   - atRest true, no CMEK -> SSE-SQS (SqsManagedSseEnabled), genuine at-rest
	//     encryption with the provider-managed key.
	//   - neither -> no encryption (SQS's unencrypted default).
	switch {
	case cmek:
		key, _ := impl["kms_key_id"].(string)
		if key == "" {
			return SQSPlan{}, fmt.Errorf(
				"encryption.customerManagedKeys requires implementation.kms_key_id " +
					"(a customer KMS key) — the SSE-SQS managed key does not satisfy it")
		}
		attrsOut["KmsMasterKeyId"] = key
	case atRest:
		attrsOut["SqsManagedSseEnabled"] = "true"
	}

	// Dead-letter posture (reliability.deadLetter): the semantic is "failures are
	// captured to a DLQ, not lost"; the DLQ target + retry threshold are impl
	// operands (D26). deadLetter=true PRESUPPOSES both — refuse loudly on a missing
	// operand rather than create a queue that silently drops nothing to a DLQ.
	if deadLetter {
		arn, _ := impl["dead_letter_target_arn"].(string)
		if arn == "" {
			return SQSPlan{}, fmt.Errorf(
				"reliability.deadLetter=true requires implementation.dead_letter_target_arn " +
					"(the ARN of a separate SQS queue to catch unprocessed messages)")
		}
		if !sqsDLQArnOK.MatchString(arn) {
			return SQSPlan{}, fmt.Errorf(
				"implementation.dead_letter_target_arn %q is not a valid SQS queue ARN", arn)
		}
		mrc, ok := intOperand(impl["max_receive_count"])
		if !ok {
			return SQSPlan{}, fmt.Errorf(
				"reliability.deadLetter=true requires implementation.max_receive_count " +
					"(a whole number of attempts before a message is redriven to the DLQ)")
		}
		if mrc < 1 || mrc > 1000 {
			return SQSPlan{}, fmt.Errorf(
				"implementation.max_receive_count %d is outside the SQS envelope (1..1000)", mrc)
		}
		rp, _ := json.Marshal(sqsRedrivePolicy{DeadLetterTargetArn: arn, MaxReceiveCount: mrc})
		attrsOut["RedrivePolicy"] = string(rp)
	}

	return SQSPlan{
		Name:       QueueName(account, environment, capability, generation, fifo),
		Region:     region,
		FIFO:       fifo,
		Attributes: attrsOut,
		Public:     public,
	}, nil
}

// sqsPublicPolicy is the queue resource policy granting anonymous sqs:SendMessage
// — the SQS analogue of SNS's Principal:"*" publish policy (the public-exposure
// second gate). Absent this, SQS's default policy restricts access to the owner.
func sqsPublicPolicy(arn string) string {
	return `{"Version":"2012-10-17","Statement":[{"Sid":"groundholdPublicAccess",` +
		`"Effect":"Allow","Principal":"*","Action":"sqs:SendMessage",` +
		`"Resource":"` + arn + `"}]}`
}

// sortedStrKeys is a deterministic key order for a string map (CreateQueue's
// Attribute.N numbering must be stable for golden/round-trip tests).
func sortedStrKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
