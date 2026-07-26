// Azure Front Door WAF request building (D116): the semantic core of the Azure
// capability.security.waf driver — the SAME vocabulary AWS WAFv2 and GCP Cloud Armor
// fulfil. A Microsoft.Network/FrontDoorWebApplicationFirewallPolicies is a global L7
// edge firewall. Invariant #4: only the enforcement MODE and the managed rule SETS
// are exposed; custom rule definitions are opaque config carried under implementation.
package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
)

const frontDoorWAFAPIVersion = "2022-05-01"

// fdWAFNameOK bounds a Front Door WAF policy name (1-128: letters/digits, must start
// with a letter — the ARM constraint for these policies).
var fdWAFNameOK = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]{0,127}$`)

// FrontDoorWAFPlan is the attribute-derived shape a create assembles.
type FrontDoorWAFPlan struct {
	Name           string
	Prevention     bool
	ManagedRuleset bool
	BotProtection  bool
}

func frontDoorWAFName(environment, capability string, generation int) string {
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "pvwaf" + hex.EncodeToString(sum[:])[:16] // alnum only, starts with a letter
}

// BuildFrontDoorWAF maps capability.security.waf attributes to a plan. Every error
// is a refusal apply surfaces in preflight.
func BuildFrontDoorWAF(environment, capability string,
	attrs, impl map[string]any, generation int) (FrontDoorWAFPlan, error) {
	p := FrontDoorWAFPlan{Name: frontDoorWAFName(environment, capability, generation)}
	modeSet := false

	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
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
				return FrontDoorWAFPlan{}, fmt.Errorf("policy.mode %v has no Front Door WAF mapping", raw)
			}
		case "managed.ruleset":
			p.ManagedRuleset, _ = raw.(bool)
		case "bot.protection":
			p.BotProtection, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return FrontDoorWAFPlan{}, fmt.Errorf("service.managed=false cannot be honored by Front Door WAF")
			}
		default:
			return FrontDoorWAFPlan{}, fmt.Errorf(
				"attribute %s has no Front Door WAF mapping — refusing rather than silently dropping it "+
					"(custom rules, rate limits, IP lists are opaque implementation config)", path)
		}
	}
	if !modeSet {
		return FrontDoorWAFPlan{}, fmt.Errorf("waf policy requires policy.mode (prevention | detection)")
	}
	if !fdWAFNameOK.MatchString(p.Name) {
		return FrontDoorWAFPlan{}, fmt.Errorf("derived policy name %q is invalid", p.Name)
	}
	return p, nil
}

// createBody is the FrontDoorWebApplicationFirewallPolicies PUT body. Ownership is tags.
func (p FrontDoorWAFPlan) createBody(tags map[string]any) map[string]any {
	mode := "Prevention"
	if !p.Prevention {
		mode = "Detection"
	}
	ruleSets := []any{}
	if p.ManagedRuleset {
		ruleSets = append(ruleSets, map[string]any{
			"ruleSetType": "Microsoft_DefaultRuleSet", "ruleSetVersion": "2.1", "ruleSetAction": "Block",
		})
	}
	if p.BotProtection {
		ruleSets = append(ruleSets, map[string]any{
			"ruleSetType": "Microsoft_BotManagerRuleSet", "ruleSetVersion": "1.0",
		})
	}
	return map[string]any{
		"location": "Global",
		"sku":      map[string]any{"name": "Premium_AzureFrontDoor"},
		"tags":     tags,
		"properties": map[string]any{
			"policySettings": map[string]any{"enabledState": "Enabled", "mode": mode},
			"managedRules":   map[string]any{"managedRuleSets": ruleSets},
		},
	}
}
