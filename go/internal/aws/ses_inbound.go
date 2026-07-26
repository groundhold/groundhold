// AWS SES INBOUND driver (slice D154): the PURE forward map of the AWS
// capability.email.inbound composite — inbound email RECEIVING as a governed
// capability (the "deal mailbox", module M1). BuildSESInbound turns capability
// attributes + operator operands (implementation: block, D26) into the shape a
// create assembles: a receipt RULE (recipients=[domain], TLS required, spam/virus
// scanning per spam.filtered, and — iff delivery.sink — an S3 action that writes
// the raw MIME to the operator's bucket, optionally announced on an SNS topic)
// inside a receipt RULE SET that a create then ACTIVATES (an inactive rule set
// receives nothing). Everything the pipeline leans on that is a SEPARATE
// capability (the S3 bucket, the SNS topic, the MX record) is an OPERAND, never
// stood up here (the operand boundary, D26). This file is PURE: it validates the
// shape and REFUSES before any mutation — an unmapped attribute or a missing
// required operand is a preflight refusal, never a silent drop. The net shell
// (ses_inbound_net.go) drives the plan through the SES v1 (receiving) Query API.
//
// Ownership honesty: SES receipt rule sets / rules carry NO tags the way S3/SNS
// do (the receiving API has no per-rule tagging), so the DETERMINISTIC rule-set
// name + rule name IS the ownership marker (the budgets pattern, D151) — a rule
// at our derived names is ours; a foreign rule at a foreign name we never touch.
// This is a weaker marker than tags (a hand-created rule that collides with our
// derived name would be treated as ours), stated plainly rather than hidden.
package aws

import (
	"fmt"
	"regexp"
	"strings"
)

// sesInboundNameOK bounds a receipt rule set / rule name before it is
// interpolated into a providerId or a request body (D73 boundary): ASCII
// letters/digits/underscore/dash, starting and ending alnum, <=64 chars.
var sesInboundNameOK = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_-]{0,62}[A-Za-z0-9])?$`)

// sesInboundBad collapses any rune outside the generated-name charset into a hyphen.
var sesInboundBad = regexp.MustCompile(`[^a-z0-9-]+`)

// sesInboundRecipientOK bounds the recipient operand: a bare domain (in.acme.example)
// or a full address (deals@in.acme.example). It rides in the rule's Recipients list.
var sesInboundRecipientOK = regexp.MustCompile(`^([A-Za-z0-9._%+-]+@)?([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$`)

// sesInboundBucketOK bounds the destination S3 bucket NAME (after any arn:...:::
// prefix is stripped) — the S3Action target, a separate storage.object capability.
var sesInboundBucketOK = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// sesInboundPrefixOK bounds the optional S3 object key prefix (where the raw MIME
// lands under the bucket). Permissive but bounded (no control characters).
var sesInboundPrefixOK = regexp.MustCompile(`^[A-Za-z0-9!_.*'()/-]{1,900}$`)

// sesInboundProviderID pins the identity: ses-inbound:<region>:<ruleSet>:<rule>.
// Both names are the ownership marker (there are no tags), so the pid carries the
// exact handles observe/delete/update address — no re-derivation at read time.
func sesInboundProviderID(region, ruleSet, rule string) string {
	return "ses-inbound:" + region + ":" + ruleSet + ":" + rule
}

func splitSESInboundProviderID(providerID string) (region, ruleSet, rule string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "ses-inbound" {
		return "", "", "", fmt.Errorf("providerId %q is not ses-inbound:region:ruleSet:rule", providerID)
	}
	region, ruleSet, rule = parts[1], parts[2], parts[3]
	if !regionOK.MatchString(region) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", region)
	}
	if !sesInboundNameOK.MatchString(ruleSet) {
		return "", "", "", fmt.Errorf("providerId rule-set name %q is invalid", ruleSet)
	}
	if !sesInboundNameOK.MatchString(rule) {
		return "", "", "", fmt.Errorf("providerId rule name %q is invalid", rule)
	}
	return region, ruleSet, rule, nil
}

// sesInboundGeneratedPrefix marks the names this driver GENERATES (vs an operator
// operand). Delete only auto-tears an EMPTY rule set down when it carries this
// prefix — a rule set the operator named by hand is left standing.
const sesInboundGeneratedPrefix = "pv-"

// sesInboundDeterministicName builds a <=64 char SES name from a slug + an 8-letter
// hash tail (letterHash: a-z only, always name-safe), prefixed pv- so it is
// recognizably ours. environment+capability(+recipient) salt the hash so two
// installs never collide, and g>=2 (D48 replacements) coexist via the genSuffix salt.
func sesInboundDeterministicName(slug, salt string) string {
	slug = strings.Trim(sesInboundBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	tail := "-" + letterHash(salt, 8)
	const maxLen = 64
	if len(sesInboundGeneratedPrefix)+len(slug)+len(tail) > maxLen {
		slug = strings.TrimRight(slug[:maxLen-len(sesInboundGeneratedPrefix)-len(tail)], "-")
	}
	name := sesInboundGeneratedPrefix + slug + tail
	if !sesInboundNameOK.MatchString(name) {
		name = sesInboundGeneratedPrefix + "inbound" + tail
	}
	return name
}

func sesInboundRuleSetName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	return sesInboundDeterministicName(slug, environment+"|"+capability+genSuffix(generation)+"|ruleset")
}

func sesInboundRuleName(environment, capability, recipient string, generation int) string {
	return sesInboundDeterministicName(capability+"-"+recipient,
		environment+"|"+capability+"|"+recipient+genSuffix(generation)+"|rule")
}

// normalizeS3Bucket accepts either a bucket NAME or an S3 ARN (arn:aws:s3:::name)
// and returns the bare bucket name SES's S3Action wants. Any path suffix is dropped.
func normalizeS3Bucket(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, ":::"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

// SESInboundPlan is the attribute+operand-derived shape a create assembles. The
// SHAPE (scanning, whether a durable sink is attached) is driven by CAPABILITY
// attributes; the placement operands (recipient, names, bucket, key prefix,
// notification topic) are OPERATOR input from the candidate implementation: block
// (D26) — separate capabilities, never provisioned by this driver.
type SESInboundPlan struct {
	RuleSetName       string // ownership marker (operand, else deterministic)
	RuleName          string // ownership marker (operand, else deterministic)
	RecipientDomain   string // recipients=[this] (operand, required)
	SpamFiltered      bool   // spam.filtered -> receipt rule ScanEnabled
	DeliverySink      bool   // delivery.sink -> an S3 action + an active rule set
	S3BucketName      string // operand, required IFF DeliverySink (a storage.object capability)
	S3ObjectKeyPrefix string // operand, optional (key prefix the raw MIME lands under)
	SNSTopicArn       string // operand, optional (a messaging.topic capability, S3Action notification)
}

// BuildSESInbound maps capability.email.inbound attributes + implementation
// operands to a plan, or REFUSES. Every error is a preflight refusal (never a
// half-build): an unmapped attribute, or a missing/invalid required operand, is
// refused here, before the first SES mutation (invariant #4, D26).
func BuildSESInbound(environment, capability string,
	attrs, impl map[string]any, generation int) (SESInboundPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := SESInboundPlan{}

	// --- CAPABILITY attributes drive the SHAPE (refuse any unmapped attribute) ---
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "spam.filtered":
			b, ok := raw.(bool)
			if !ok {
				return SESInboundPlan{}, fmt.Errorf("spam.filtered must be a bool")
			}
			p.SpamFiltered = b
		case "delivery.sink":
			b, ok := raw.(bool)
			if !ok {
				return SESInboundPlan{}, fmt.Errorf("delivery.sink must be a bool")
			}
			p.DeliverySink = b
		case "service.managed":
			if raw != true {
				return SESInboundPlan{}, fmt.Errorf("service.managed=false cannot be honored — groundhold manages the receiving pipeline it stands up")
			}
		case "location.region":
			// location.region scopes the create (resolved by the dispatch, not here);
			// cost.monthly is a projection — neither is a build input.
		default:
			return SESInboundPlan{}, fmt.Errorf(
				"attribute %s has no SES inbound mapping — refusing rather than silently dropping it "+
					"(the email.inbound vocab governs spam.filtered + delivery.sink)", path)
		}
	}

	// --- OPERATOR operands supply the placement (implementation: block, D26) ---
	p.RecipientDomain = strings.TrimSpace(implString(impl, "recipientDomain"))
	if p.RecipientDomain == "" {
		return SESInboundPlan{}, fmt.Errorf("implementation.recipientDomain is required (the domain/address the rule receives mail for, e.g. in.acme.example)")
	}
	if !sesInboundRecipientOK.MatchString(p.RecipientDomain) {
		return SESInboundPlan{}, fmt.Errorf("implementation.recipientDomain %q is not a valid domain or address", p.RecipientDomain)
	}

	// rule-set + rule names are optional operands; otherwise deterministic (the
	// ownership marker, recoverable via the pid at read time).
	if given := strings.TrimSpace(implString(impl, "ruleSetName")); given != "" {
		if !sesInboundNameOK.MatchString(given) {
			return SESInboundPlan{}, fmt.Errorf("implementation.ruleSetName %q is invalid (alnum/'_'/'-', start+end alnum, <=64)", given)
		}
		p.RuleSetName = given
	} else {
		p.RuleSetName = sesInboundRuleSetName(environment, capability, generation)
	}
	if given := strings.TrimSpace(implString(impl, "ruleName")); given != "" {
		if !sesInboundNameOK.MatchString(given) {
			return SESInboundPlan{}, fmt.Errorf("implementation.ruleName %q is invalid (alnum/'_'/'-', start+end alnum, <=64)", given)
		}
		p.RuleName = given
	} else {
		p.RuleName = sesInboundRuleName(environment, capability, p.RecipientDomain, generation)
	}

	// the S3 sink is REQUIRED iff delivery.sink — refusing to claim durable
	// delivery with no bucket for the raw mail. The bucket is a REFERENCE (names a
	// separate storage.object capability), never a secret (D53). Given but not a
	// sink -> an ambiguous shape, refused.
	p.S3BucketName = normalizeS3Bucket(implString(impl, "s3BucketName"))
	p.S3ObjectKeyPrefix = strings.TrimSpace(implString(impl, "s3ObjectKeyPrefix"))
	p.SNSTopicArn = strings.TrimSpace(implString(impl, "snsTopicArn"))
	if p.DeliverySink {
		if p.S3BucketName == "" {
			return SESInboundPlan{}, fmt.Errorf(
				"delivery.sink=true requires implementation.s3BucketName (the S3 bucket the raw MIME lands in, a " +
					"separate storage.object capability) — refusing to claim durable delivery with no sink for the mail")
		}
		if !sesInboundBucketOK.MatchString(p.S3BucketName) {
			return SESInboundPlan{}, fmt.Errorf("implementation.s3BucketName %q is not a valid S3 bucket name", p.S3BucketName)
		}
		if p.S3ObjectKeyPrefix != "" && !sesInboundPrefixOK.MatchString(p.S3ObjectKeyPrefix) {
			return SESInboundPlan{}, fmt.Errorf("implementation.s3ObjectKeyPrefix %q is invalid", p.S3ObjectKeyPrefix)
		}
		if p.SNSTopicArn != "" && !snsTopicArnOK.MatchString(p.SNSTopicArn) {
			return SESInboundPlan{}, fmt.Errorf("implementation.snsTopicArn %q is not a valid SNS topic ARN", p.SNSTopicArn)
		}
	} else {
		if p.S3BucketName != "" || p.S3ObjectKeyPrefix != "" || p.SNSTopicArn != "" {
			return SESInboundPlan{}, fmt.Errorf(
				"an S3 sink operand (s3BucketName/s3ObjectKeyPrefix/snsTopicArn) was given but delivery.sink is not true — " +
					"a durable sink only attaches to delivery.sink; refusing an ambiguous shape")
		}
	}

	if !sesInboundNameOK.MatchString(p.RuleSetName) || !sesInboundNameOK.MatchString(p.RuleName) {
		return SESInboundPlan{}, fmt.Errorf("derived rule-set/rule name is invalid")
	}
	return p, nil
}

// ruleParams renders the receipt Rule as SES v1 (Query protocol) form params —
// the shared body of CreateReceiptRule and UpdateReceiptRule. TLS is REQUIRED
// (inbound mail must arrive over TLS); the S3 action is attached iff delivery.sink.
func (p SESInboundPlan) ruleParams() map[string]string {
	params := map[string]string{
		"RuleSetName":              p.RuleSetName,
		"Rule.Name":                p.RuleName,
		"Rule.Enabled":             "true",
		"Rule.TlsPolicy":           "Require",
		"Rule.ScanEnabled":         boolStr(p.SpamFiltered),
		"Rule.Recipients.member.1": p.RecipientDomain,
	}
	if p.DeliverySink {
		params["Rule.Actions.member.1.S3Action.BucketName"] = p.S3BucketName
		if p.S3ObjectKeyPrefix != "" {
			params["Rule.Actions.member.1.S3Action.ObjectKeyPrefix"] = p.S3ObjectKeyPrefix
		}
		if p.SNSTopicArn != "" {
			params["Rule.Actions.member.1.S3Action.TopicArn"] = p.SNSTopicArn
		}
	}
	return params
}

// classifySESInboundChange (D46): PURE — can a capability.email.inbound transition
// be honored in place? spam.filtered and delivery.sink are UpdateReceiptRule-
// mutable (both wired to an updater, so no mutable-without-updater gap);
// location.region is unsupported (SES receiving is region-bound — a region change
// is a new pipeline, not a patch); service.managed / others are unsupported.
func classifySESInboundChange(path string) (string, string) {
	switch path {
	case "spam.filtered":
		return "mutable", "in-place via UpdateReceiptRule (toggle ScanEnabled — spam/virus scanning)"
	case "delivery.sink":
		return "mutable", "in-place via UpdateReceiptRule (add/remove the S3 delivery action) + SetActiveReceiptRuleSet"
	case "location.region":
		return "unsupported", "SES receiving is region-bound — a region change is a new receiving pipeline, not an in-place patch"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no SES inbound in-place mapping for " + path
	}
}
