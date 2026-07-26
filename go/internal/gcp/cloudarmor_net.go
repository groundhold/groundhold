// GCP Cloud Armor network shell (D116): the compute-plane half of the
// capability.security.waf driver. A global securityPolicy insert/delete is a
// Compute global-operation LRO (the VPC machinery, reused). The policy name is
// deterministic, so the providerId is knowable before the create response (D29).
// Ownership is the DESCRIPTION MARKER (securityPolicies carry no labels). D29/D87.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func armorProviderID(project, name string) string {
	return "armor:" + project + ":" + name
}

func splitArmorProviderID(providerID string) (project, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "armor" {
		return "", "", fmt.Errorf("providerId %q is not armor:project:name", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !gcpName.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId policy %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

func (d *Driver) armorURL(project, name string) string {
	return fmt.Sprintf("%s/projects/%s/global/securityPolicies/%s", d.computeBase(), project, name)
}

func (d *Driver) createArmor(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildArmor(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := armorProviderID(d.Project, plan.Name)
	url := fmt.Sprintf("%s/projects/%s/global/securityPolicies", d.computeBase(), d.Project)
	status, res := d.computeInsert(url, plan.createBody(capability, environment), "global")
	if status == http.StatusConflict {
		// content-addressed: an existing policy with our name+marker is ours.
		desc, found, rerr := d.computeGet(d.armorURL(d.Project, plan.Name))
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing policy gave no answer — reconcile: " + rerr.Error()}
		}
		if !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, but the conflicting policy was gone on the follow-up read — reconcile"}
		}
		if !markerOurs(desc, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a security policy with this name exists and is not ours (marker does not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	}
	if res.Status == "succeeded" || res.ProviderID == "" {
		res.ProviderID = pid
	}
	return res
}

func (d *Driver) observeArmor(capability, providerID string) ([]provider.Observation, []string, error) {
	project, name, err := splitArmorProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	status, body, err := d.call("GET", d.armorURL(project, name), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("securityPolicies.get: %v", err)
	}
	if status == http.StatusNotFound {
		return nil, []string{"security policy not found — nothing to observe"}, nil
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("securityPolicies.get: HTTP %d", status)
	}
	var doc struct {
		Rules []struct {
			Action  string `json:"action"`
			Preview bool   `json:"preview"`
			Match   struct {
				Expr struct {
					Expression string `json:"expression"`
				} `json:"expr"`
			} `json:"match"`
		} `json:"rules"`
		AdaptiveProtectionConfig struct {
			Layer7DdosDefenseConfig struct {
				Enable bool `json:"enable"`
			} `json:"layer7DdosDefenseConfig"`
		} `json:"adaptiveProtectionConfig"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil, nil, readBody("securityPolicies.get", status)
	}
	managed, prevention := false, true
	for _, r := range doc.Rules {
		if r.Match.Expr.Expression != "" { // a preconfigured-WAF managed rule
			managed = true
			if r.Preview {
				prevention = false
			}
		}
	}
	mode := "prevention"
	if !prevention {
		mode = "detection"
	}
	return []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "policy.mode", Value: mode, Derivation: "measured"},
		{Path: "managed.ruleset", Value: managed, Derivation: "measured"},
		{Path: "bot.protection", Value: doc.AdaptiveProtectionConfig.Layer7DdosDefenseConfig.Enable, Derivation: "measured"},
	}, nil, nil
}

func (d *Driver) deleteArmor(capability, environment, providerID string) provider.CreateResult {
	project, name, err := splitArmorProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	status, body, err := d.call("GET", d.armorURL(project, name), nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + err.Error()}
	}
	if status == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if status != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", status)}
	}
	var doc struct {
		Description string `json:"description"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + readBody("securityPolicies.get", status).Error()}
	}
	if !markerOurs(doc.Description, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "security policy marker does not match — refusing to delete a resource that is not ours"}
	}
	st, resp, e := d.call("DELETE", d.armorURL(project, name), nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, gcpErrCode(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(resp))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(resp, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "delete response carried no operation — reconcile"}
	}
	res := d.pollComputeOperation("global", op.Name)
	if res.Status == "succeeded" || res.ProviderID == "" {
		res.ProviderID = providerID
	}
	return res
}
