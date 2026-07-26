// Azure RBAC role-assignment network shell (D104): the ARM half of the
// capability.authorization.grant driver. A single PUT of a roleAssignment at
// subscription scope, named by a DETERMINISTIC GUID so create is idempotent and the
// binding is content-addressed (no ownership tags — groundhold deletes only the exact
// assignment its operands name). A lost PUT is unknown (D29).
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func azureRoleProviderID(sub, guid string) string { return "azauth:" + sub + ":" + guid }

func splitAzureRoleProviderID(providerID string) (sub, guid string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "azauth" {
		return "", "", fmt.Errorf("providerId %q is not azauth:sub:assignmentGuid", providerID)
	}
	if !subOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId subscription %q is invalid", parts[1])
	}
	if !azGUIDOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId assignment guid %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

func (d *Driver) roleAssignmentURL(sub, guid string) string {
	return fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments/%s?api-version=%s",
		d.BaseURL, sub, guid, roleAssignmentAPIVersion)
}

func roleDefinitionID(sub, roleGuid string) string {
	return "/subscriptions/" + sub + "/providers/Microsoft.Authorization/roleDefinitions/" + roleGuid
}

func (d *Driver) createAzureRole(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAzureRole(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	scope := "/subscriptions/" + d.Subscription
	guid := azAssignmentGUID(scope, plan.PrincipalID, plan.RoleGuid)
	pid := azureRoleProviderID(d.Subscription, guid)
	body, _ := json.Marshal(map[string]any{
		"properties": map[string]any{
			"roleDefinitionId": roleDefinitionID(d.Subscription, plan.RoleGuid),
			"principalId":      plan.PrincipalID,
			"principalType":    "ServicePrincipal",
		},
	})
	st, resp, e := d.doARM("PUT", d.roleAssignmentURL(d.Subscription, guid), body)
	if e != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", e)}
	}
	switch {
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st == http.StatusConflict || strings.Contains(string(resp), "RoleAssignmentExists"):
		// deterministic name + same operands => the existing assignment IS ours
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, azErrCode(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetailAz(resp))}
	}
}

type azureRoleDoc struct {
	Properties struct {
		RoleDefinitionID string `json:"roleDefinitionId"`
		PrincipalID      string `json:"principalId"`
	} `json:"properties"`
}

func (d *Driver) observeAzureRole(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, guid, err := splitAzureRoleProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	st, resp, e := d.doARM("GET", d.roleAssignmentURL(sub, guid), nil)
	if e != nil {
		return nil, nil, fmt.Errorf("roleAssignments.get: %v", e)
	}
	if st == http.StatusNotFound {
		return nil, []string{"role assignment not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("roleAssignments.get: HTTP %d", st)
	}
	var doc azureRoleDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "roleAssignments.get", Cause: "body", Status: st}
	}
	roleGuid := doc.Properties.RoleDefinitionID[strings.LastIndex(doc.Properties.RoleDefinitionID, "/")+1:]
	obs := []provider.Observation{
		{Path: "grant.role", Value: azRoleNameForGuid(roleGuid), Derivation: "measured"},
		{Path: "grant.principal", Value: doc.Properties.PrincipalID, Derivation: "measured"},
		{Path: "access.scope", Value: "account", Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	if priv, known := classifyAzureRoleGuid(roleGuid); known {
		obs = append(obs, provider.Observation{Path: "access.privileged", Value: priv, Derivation: "measured"})
	} else {
		diags = append(diags, "access.privileged not observed: role "+roleGuid+" is not in groundhold's known built-in role set (a custom role's privilege is not guessed)")
	}
	return obs, diags, nil
}

func (d *Driver) deleteAzureRole(capability, environment, providerID string) provider.CreateResult {
	sub, guid, err := splitAzureRoleProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	st, resp, e := d.doARM("DELETE", d.roleAssignmentURL(sub, guid), nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, azErrCode(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetailAz(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
