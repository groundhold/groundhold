// GCP Cloud Armor request building (D116): the semantic core of the GCP
// capability.security.waf driver — the SAME vocabulary AWS WAFv2 and Azure Front
// Door WAF fulfil. A global Compute securityPolicy is an L7 edge firewall. Invariant
// #4: only the enforcement mode and the managed rule SETS are exposed; custom rule
// expressions are opaque config carried under implementation. securityPolicies carry
// NO labels, so ownership is a DESCRIPTION MARKER (the VPC/tagless discipline).
package gcp

import (
	"fmt"
	"strings"
)

// ArmorPolicyName is the deterministic securityPolicy name (the idempotency handle).
func ArmorPolicyName(project, environment, capability string, generation int) string {
	return resourceName(project, environment, capability, generation, 63)
}

// ArmorPlan is the attribute-derived shape a create assembles.
type ArmorPlan struct {
	Name           string
	Prevention     bool // policy.mode: preview=false (enforce) vs true (detect)
	ManagedRuleset bool
	BotProtection  bool
}

// BuildArmor maps capability.security.waf attributes to a Cloud Armor plan. Every
// error is a preflight refusal, never a silent drop.
func BuildArmor(project, environment, capability string,
	attrs, impl map[string]any, generation int) (ArmorPlan, error) {
	p := ArmorPlan{Name: ArmorPolicyName(project, environment, capability, generation)}
	modeSet := false
	for _, path := range sortedKeysG(attrs) {
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
				return ArmorPlan{}, fmt.Errorf("policy.mode %v has no Cloud Armor mapping", raw)
			}
		case "managed.ruleset":
			p.ManagedRuleset, _ = raw.(bool)
		case "bot.protection":
			p.BotProtection, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return ArmorPlan{}, fmt.Errorf("service.managed=false cannot be honored by Cloud Armor")
			}
		default:
			return ArmorPlan{}, fmt.Errorf(
				"attribute %s has no Cloud Armor mapping — refusing rather than silently dropping it "+
					"(custom rules, rate limits, IP lists are opaque implementation config)", path)
		}
	}
	if !modeSet {
		return ArmorPlan{}, fmt.Errorf("waf policy requires policy.mode (prevention | detection)")
	}
	if !gcpName.MatchString(p.Name) {
		return ArmorPlan{}, fmt.Errorf("derived policy name %q is invalid", p.Name)
	}
	if !projectOK.MatchString(project) {
		return ArmorPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	return p, nil
}

// createBody is the securityPolicies.insert request body. Ownership is the
// description marker (no labels exist on this resource).
func (p ArmorPlan) createBody(capability, environment string) map[string]any {
	rules := []any{
		// the required default rule (lowest priority) — allow all not matched.
		map[string]any{
			"priority": 2147483647,
			"match": map[string]any{
				"versionedExpr": "SRC_IPS_V1",
				"config":        map[string]any{"srcIpRanges": []any{"*"}},
			},
			"action":      "allow",
			"description": "default rule",
		},
	}
	if p.ManagedRuleset {
		rules = append([]any{map[string]any{
			"priority": 1000,
			"match": map[string]any{
				"expr": map[string]any{"expression": "evaluatePreconfiguredWaf('sqli-v33-stable')"},
			},
			"action":  "deny(403)",
			"preview": !p.Prevention, // detection => preview (log only)
		}}, rules...)
	}
	body := map[string]any{
		"name":        p.Name,
		"type":        "CLOUD_ARMOR",
		"description": strings.ReplaceAll(vpcOwnerMarker(capability, environment), "\n", ""),
		"rules":       rules,
	}
	if p.BotProtection {
		body["adaptiveProtectionConfig"] = map[string]any{
			"layer7DdosDefenseConfig": map[string]any{"enable": true},
		}
	}
	return body
}
