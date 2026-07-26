// AWS SES SENDING driver (slice D148): the PURE forward map of the AWS
// capability.email.sending composite — authenticated outbound email as a governed
// capability. BuildSESSending turns capability attributes + operator operands
// (implementation: block, D26) into the shape a create assembles: the sending
// DOMAIN identity (Easy DKIM), and — iff bounces are tracked — a configuration set
// with a BOUNCE+COMPLAINT event destination that returns delivery failures to the
// record instead of the void. Everything the sender leans on that is a SEPARATE
// capability (the domain the operator owns, the SNS bounce topic) is an OPERAND,
// never stood up here (the operand boundary, D26). This file is PURE: it validates
// the shape and REFUSES before any mutation — an unmapped capability attribute or a
// missing required operand is a preflight refusal, never a silent drop. The net
// shell (ses_sending_net.go) drives the parsed plan through the SESv2 REST-JSON API.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// sesDomainOK bounds a sending domain: labels of alnum/hyphen, at least one dot, an
// alphabetic TLD. Dots are legal (the domain rides in the name segment of the pid).
var sesDomainOK = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$`)

// snsTopicArnOK bounds the bounce-sink operand: an SNS topic ARN (a separate
// capability the operator passes in). It is a REFERENCE (it names a topic), never a
// secret — safe to carry (D53).
var snsTopicArnOK = regexp.MustCompile(`^arn:aws[A-Za-z0-9-]*:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]+$`)

// sesConfigSetNameOK bounds a configuration-set name (SES: alnum + '-'/'_', <=64).
var sesConfigSetNameOK = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// sesConfigBad collapses any other rune into a hyphen for the deterministic name.
var sesConfigBad = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

// sesSendingProviderID pins the identity: ses-sending:<region>:<domain>. The domain
// carries dots — it is the terminal segment, so a plain SplitN recovers it whole.
func sesSendingProviderID(region, domain string) string {
	return "ses-sending:" + region + ":" + domain
}

func splitSESSendingProviderID(providerID string) (region, domain string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "ses-sending" {
		return "", "", fmt.Errorf("providerId %q is not ses-sending:region:domain", providerID)
	}
	region, domain = parts[1], parts[2]
	if !regionOK.MatchString(region) {
		return "", "", fmt.Errorf("providerId region %q is invalid", region)
	}
	if !sesDomainOK.MatchString(domain) {
		return "", "", fmt.Errorf("providerId domain %q is invalid", domain)
	}
	return region, domain, nil
}

// sesConfigSetName is the deterministic configuration-set name when the operator
// gives none. It is a function of capability + DOMAIN ONLY — both are recoverable at
// observe time (the capability is passed, the domain lives in the pid), so observe
// can reconstruct the exact name to read the event destination. (Environment is NOT
// an input: the Observe interface carries no environment, and a domain identity is
// already unique per account/region, so the domain supplies the isolation.)
func sesConfigSetName(capability, domain string) string {
	slug := strings.Trim(sesConfigBad.ReplaceAllString(strings.ToLower(capability+"-"+domain), "-"), "-_")
	sum := sha256.Sum256([]byte(capability + "|" + domain))
	tail := "-" + hex.EncodeToString(sum[:])[:8]
	const maxLen = 64
	if len(slug)+len(tail) > maxLen {
		slug = strings.TrimRight(slug[:maxLen-len(tail)], "-_")
	}
	name := slug + tail
	if name == "" || !sesConfigSetNameOK.MatchString(name) {
		name = "groundhold" + tail
	}
	return name
}

// SESSendingPlan is the attribute+operand-derived shape a create assembles. The
// SHAPE (DKIM posture, whether bounces are tracked) is driven by CAPABILITY
// attributes; the placement operands (the domain, the bounce topic, an optional
// config-set name) are OPERATOR input from the candidate implementation: block
// (D26) — separate capabilities, never provisioned by this driver.
type SESSendingPlan struct {
	Domain               string // sending domain (operand, required)
	DKIM                 bool   // authentication.dkim -> Easy DKIM signing
	BounceTracked        bool   // bounce.tracked -> a BOUNCE+COMPLAINT event destination
	BounceTopicArn       string // operand, required IFF BounceTracked (an SNS topic ARN)
	ConfigurationSetName string // operand (optional) else deterministic from capability+domain
}

// BuildSESSending maps capability.email.sending attributes + implementation operands
// to a plan, or REFUSES. Every error is a preflight refusal (never a half-build): an
// unmapped attribute, or a missing/invalid required operand, is refused here, before
// the first SES mutation (invariant #4, D26).
func BuildSESSending(environment, capability string,
	attrs, impl map[string]any, generation int) (SESSendingPlan, error) {
	p := SESSendingPlan{}

	// --- CAPABILITY attributes drive the SHAPE (refuse any unmapped attribute) ---
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "authentication.dkim":
			b, ok := raw.(bool)
			if !ok {
				return SESSendingPlan{}, fmt.Errorf("authentication.dkim must be a bool")
			}
			p.DKIM = b
		case "bounce.tracked":
			b, ok := raw.(bool)
			if !ok {
				return SESSendingPlan{}, fmt.Errorf("bounce.tracked must be a bool")
			}
			p.BounceTracked = b
		case "sending.productionAccess":
			// MANUAL-GATE (C2): SES sandbox exit is a manual request in the AWS console,
			// never an API create. This is NOT a build input — the create does NOT provision
			// it. It is only a VERIFY TARGET: observe measures the real gate state and verify
			// compares. Accept the type (a malformed value is still refused), then ignore it.
			if _, ok := raw.(bool); !ok {
				return SESSendingPlan{}, fmt.Errorf("sending.productionAccess must be a bool")
			}
		case "service.managed":
			if raw != true {
				return SESSendingPlan{}, fmt.Errorf("service.managed=false cannot be honored — groundhold manages the sending identity it stands up")
			}
		case "location.region":
			// location.region scopes the create (resolved by the dispatch, not here);
			// cost.monthly is a projection — neither is a build input.
		default:
			return SESSendingPlan{}, fmt.Errorf(
				"attribute %s has no SES sending mapping — refusing rather than silently dropping it "+
					"(the email.sending vocab governs authentication.dkim + bounce.tracked)", path)
		}
	}

	// --- OPERATOR operands supply the placement (implementation: block, D26) ---
	p.Domain = strings.TrimSpace(implString(impl, "domain"))
	if p.Domain == "" {
		return SESSendingPlan{}, fmt.Errorf("implementation.domain is required (the sending domain — an identity the operator owns)")
	}
	if !sesDomainOK.MatchString(p.Domain) {
		return SESSendingPlan{}, fmt.Errorf("implementation.domain %q is not a valid domain", p.Domain)
	}

	// the bounce topic is REQUIRED iff bounces are tracked — a failed statutory demand
	// cannot return to the record with no sink. The ARN is a REFERENCE (names a topic),
	// never a secret (D53). Given but not tracked -> an ambiguous shape, refused.
	p.BounceTopicArn = strings.TrimSpace(implString(impl, "bounceTopicArn"))
	if p.BounceTracked {
		if p.BounceTopicArn == "" {
			return SESSendingPlan{}, fmt.Errorf(
				"bounce.tracked=true requires implementation.bounceTopicArn (an SNS topic ARN, a separate " +
					"capability) — refusing to claim bounce tracking with no sink for the failures")
		}
		if !snsTopicArnOK.MatchString(p.BounceTopicArn) {
			return SESSendingPlan{}, fmt.Errorf("implementation.bounceTopicArn %q is not a valid SNS topic ARN", p.BounceTopicArn)
		}
	} else if p.BounceTopicArn != "" {
		return SESSendingPlan{}, fmt.Errorf(
			"implementation.bounceTopicArn was given but bounce.tracked is not true — " +
				"a bounce sink only attaches to bounce tracking; refusing an ambiguous shape")
	}

	// the configuration set name is an optional operand; otherwise a deterministic
	// name (recoverable at observe) so a partial create repairs to the SAME set.
	if given := strings.TrimSpace(implString(impl, "configurationSetName")); given != "" {
		if !sesConfigSetNameOK.MatchString(given) {
			return SESSendingPlan{}, fmt.Errorf("implementation.configurationSetName %q is invalid (alnum, '-'/'_', <=64)", given)
		}
		p.ConfigurationSetName = given
	} else {
		p.ConfigurationSetName = sesConfigSetName(capability, p.Domain)
	}
	return p, nil
}
