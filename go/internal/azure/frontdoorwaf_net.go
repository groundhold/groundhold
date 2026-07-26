// Azure Front Door WAF network shell (D116): the ARM half of the Azure
// capability.security.waf driver. A single FrontDoorWebApplicationFirewallPolicies
// PUT polled to provisioningState=Succeeded; the name is deterministic, so the
// providerId is knowable before the response (D29). Ownership is tags. D29/D87.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func frontDoorWAFProviderID(sub, rg, name string) string {
	return "fdwaf:" + sub + ":" + rg + ":" + name
}

func splitFrontDoorWAFProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "fdwaf" {
		return "", "", "", fmt.Errorf("providerId %q is not fdwaf:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || !fdWAFNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) frontDoorWAFPath(name string) string {
	return "Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/" + name
}

func (d *Driver) createFrontDoorWAF(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildFrontDoorWAF(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure front door waf requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := frontDoorWAFProviderID(d.Subscription, rg, plan.Name)
	url, _ := d.armURL(rg, d.frontDoorWAFPath(plan.Name), frontDoorWAFAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	if r := d.putAndPoll(url, body, pid, "front door waf policy"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type frontDoorWAFDoc struct {
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
		PolicySettings    struct {
			Mode string `json:"mode"`
		} `json:"policySettings"`
		ManagedRules struct {
			ManagedRuleSets []struct {
				RuleSetType string `json:"ruleSetType"`
			} `json:"managedRuleSets"`
		} `json:"managedRules"`
	} `json:"properties"`
}

func (d *Driver) observeFrontDoorWAF(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitFrontDoorWAFProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	url, _ := d.armURL(rg, d.frontDoorWAFPath(name), frontDoorWAFAPIVersion)
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("wafPolicies.get: %v", e)
	}
	if st == http.StatusNotFound {
		return nil, []string{"waf policy not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("wafPolicies.get: HTTP %d", st)
	}
	var doc frontDoorWAFDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "wafPolicies.get", Cause: "body", Status: st}
	}
	mode := "detection"
	if doc.Properties.PolicySettings.Mode == "Prevention" {
		mode = "prevention"
	}
	managed, bot := false, false
	for _, rs := range doc.Properties.ManagedRules.ManagedRuleSets {
		switch rs.RuleSetType {
		case "Microsoft_DefaultRuleSet":
			managed = true
		case "Microsoft_BotManagerRuleSet":
			bot = true
		}
	}
	return []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "policy.mode", Value: mode, Derivation: "measured"},
		{Path: "managed.ruleset", Value: managed, Derivation: "measured"},
		{Path: "bot.protection", Value: bot, Derivation: "measured"},
	}, nil, nil
}

func (d *Driver) deleteFrontDoorWAF(capability, environment, providerID string) provider.CreateResult {
	_, rg, name, err := splitFrontDoorWAFProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	url, _ := d.armURL(rg, d.frontDoorWAFPath(name), frontDoorWAFAPIVersion)
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc frontDoorWAFDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "waf policy tags do not match — refusing to delete a resource that is not ours"}
	}
	dst, dresp, de := d.doARM("DELETE", url, nil)
	if de != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", de)}
	}
	if dst == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if dst >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", dst)}
	}
	if dst < 200 || dst >= 300 {
		if r := provider.MutationResult(dst, azErrCode(dresp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", dst, mutDetailAz(dresp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
