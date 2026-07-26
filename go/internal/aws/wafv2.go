// WAFv2 request building (D116): the semantic core of the AWS capability.security.waf
// driver — the SAME vocabulary Azure Front Door WAF and GCP Cloud Armor fulfil. A
// CLOUDFRONT-scope WebACL is a global L7 edge firewall. The rule DEFINITIONS are
// OPAQUE (invariant #4): this builder only toggles PROVIDER-MANAGED rule groups and
// the enforcement mode; bespoke rules ride under implementation as opaque config.
// CLOUDFRONT-scope WAFv2 is always created against the us-east-1 endpoint.
package aws

import (
	"fmt"
	"regexp"
	"strings"
)

// wafNameOK bounds a WebACL name (1-128: letters, digits, hyphen, underscore).
var wafNameOK = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// WAFACLName is the deterministic WebACL name (the idempotency/recovery handle).
func WAFACLName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, slug)
	slug = strings.Trim(slug, "-")
	return "pv-" + slug + "-" + letterHash(environment+"|"+capability+genSuffix(generation), 8)
}

// WAFPlan is the attribute-derived shape a create assembles.
type WAFPlan struct {
	Name           string
	Prevention     bool // policy.mode: true = block (None), false = detection (Count)
	ManagedRuleset bool
	BotProtection  bool
}

// BuildWAF maps capability.security.waf attributes to a plan. Every error is a
// preflight refusal, never a silent drop.
func BuildWAF(environment, capability string,
	attrs, impl map[string]any, generation int) (WAFPlan, error) {
	p := WAFPlan{Name: WAFACLName(environment, capability, generation)}
	modeSet := false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "policy.mode":
			modeSet = true
			switch raw {
			case "prevention":
				p.Prevention = true
			case "detection":
				p.Prevention = false
			default:
				return WAFPlan{}, fmt.Errorf("policy.mode %v has no WAFv2 mapping", raw)
			}
		case "managed.ruleset":
			p.ManagedRuleset, _ = raw.(bool)
		case "bot.protection":
			p.BotProtection, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return WAFPlan{}, fmt.Errorf("service.managed=false cannot be honored by WAFv2")
			}
		default:
			return WAFPlan{}, fmt.Errorf(
				"attribute %s has no WAFv2 mapping — refusing rather than silently dropping it "+
					"(custom rules, rate limits, IP lists are opaque implementation config)", path)
		}
	}
	if !modeSet {
		return WAFPlan{}, fmt.Errorf("waf policy requires policy.mode (prevention | detection)")
	}
	if !wafNameOK.MatchString(p.Name) {
		return WAFPlan{}, fmt.Errorf("derived WebACL name %q is invalid", p.Name)
	}
	return p, nil
}

// overrideAction returns the managed-rule-group override for the mode: None blocks
// (prevention), Count only logs (detection).
func (p WAFPlan) overrideAction() map[string]any {
	if p.Prevention {
		return map[string]any{"None": map[string]any{}}
	}
	return map[string]any{"Count": map[string]any{}}
}

func managedRule(name, vendor, ruleName string, priority int, override map[string]any) map[string]any {
	return map[string]any{
		"Name":     name,
		"Priority": priority,
		"Statement": map[string]any{
			"ManagedRuleGroupStatement": map[string]any{"VendorName": vendor, "Name": ruleName},
		},
		"OverrideAction": override,
		"VisibilityConfig": map[string]any{
			"SampledRequestsEnabled":   true,
			"CloudWatchMetricsEnabled": true,
			"MetricName":               name,
		},
	}
}

// createBody is the CreateWebACL request body. DefaultAction is Allow (block only
// what the rules match). Ownership is tags.
func (p WAFPlan) createBody(capability, environment string) map[string]any {
	rules := []any{}
	if p.ManagedRuleset {
		rules = append(rules, managedRule("owasp", "AWS", "AWSManagedRulesCommonRuleSet", 1, p.overrideAction()))
	}
	if p.BotProtection {
		rules = append(rules, managedRule("bot", "AWS", "AWSManagedRulesBotControlRuleSet", 2, p.overrideAction()))
	}
	return map[string]any{
		"Name":          p.Name,
		"Scope":         "CLOUDFRONT",
		"DefaultAction": map[string]any{"Allow": map[string]any{}},
		"Rules":         rules,
		"VisibilityConfig": map[string]any{
			"SampledRequestsEnabled":   true,
			"CloudWatchMetricsEnabled": true,
			"MetricName":               p.Name,
		},
		"Tags": []any{
			map[string]any{"Key": "groundhold-capability", "Value": sanitizeTag(capability)},
			map[string]any{"Key": "groundhold-environment", "Value": sanitizeTag(environment)},
		},
	}
}
