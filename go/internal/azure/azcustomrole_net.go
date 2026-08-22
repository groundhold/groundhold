// Azure custom roleDefinition network shell (D105): the ARM half of the
// capability.authorization.role driver. A single PUT of a custom roleDefinition at
// subscription scope, named by a DETERMINISTIC GUID (idempotent, content-addressed,
// no ownership tags). observe reads the flat action set back out of
// permissions[0].actions and derives access.mutating/access.privileged. A lost PUT is
// unknown (D29).
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func azureCustomRoleProviderID(sub, guid string) string { return "azcrole:" + sub + ":" + guid }

func splitAzureCustomRoleProviderID(providerID string) (sub, guid string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "azcrole" {
		return "", "", fmt.Errorf("providerId %q is not azcrole:sub:guid", providerID)
	}
	if !subOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId subscription %q is invalid", parts[1])
	}
	if !subOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId roleDefinition guid %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

func (d *Driver) customRoleURL(sub, guid string) string {
	return fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s?api-version=%s",
		d.BaseURL, sub, guid, customRoleAPIVersion)
}

func (d *Driver) createAzureCustomRole(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAzureCustomRole(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	scope := "/subscriptions/" + d.Subscription
	guid := azRoleDefGUID(scope, plan.RoleName)
	pid := azureCustomRoleProviderID(d.Subscription, guid)
	body, _ := json.Marshal(map[string]any{
		"properties": map[string]any{
			"roleName":    plan.RoleName,
			"description": "groundhold-managed custom role",
			"type":        "CustomRole",
			"permissions": []any{map[string]any{
				"actions":        plan.Permissions,
				"notActions":     []any{},
				"dataActions":    []any{},
				"notDataActions": []any{},
			}},
			"assignableScopes": []any{scope},
		},
	})
	st, resp, e := d.doARM("PUT", d.customRoleURL(d.Subscription, guid), body)
	if e != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", e)}
	}
	switch {
	case st == http.StatusOK || st == http.StatusCreated:
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

type azureCustomRoleDoc struct {
	Properties struct {
		Permissions []struct {
			Actions    []string `json:"actions"`
			NotActions []string `json:"notActions"`
			// D1197: an Azure role carries its DATA-plane grants in a separate list.
			// These were not parsed at all, so a role whose only writes live here —
			// the ordinary shape of every built-in data role, "Storage Blob Data
			// Contributor" among them — presented an empty or read-only action set
			// and measured access.mutating=FALSE while it could write blobs.
			DataActions    []string `json:"dataActions"`
			NotDataActions []string `json:"notDataActions"`
		} `json:"permissions"`
	} `json:"properties"`
}

func (d *Driver) observeAzureCustomRole(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, guid, err := splitAzureCustomRoleProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	st, resp, e := d.doARM("GET", d.customRoleURL(sub, guid), nil)
	if e != nil {
		return nil, nil, fmt.Errorf("roleDefinitions.get: %v", e)
	}
	if st == http.StatusNotFound {
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"custom role not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("roleDefinitions.get: HTTP %d", st)
	}
	var doc azureCustomRoleDoc
	if json.Unmarshal(resp, &doc) != nil || len(doc.Properties.Permissions) == 0 {
		return nil, nil, fmt.Errorf("roleDefinitions.get: empty permissions — %w", armBody("roleDefinitions.get", st))
	}
	actions, narrowed := azRoleActions(doc)
	var diags []string
	if narrowed {
		diags = append(diags, "role.permissions lists the granted actions only: the role "+
			"also carries notActions or notDataActions, which NARROW what those actions "+
			"reach. They are not subtracted here — ignoring a narrowing over-reports "+
			"privilege, which is the safe side of a security attribute, but the reported "+
			"set is a ceiling rather than an exact grant")
	}
	return []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "role.permissions", Value: actions, Derivation: "measured"},
		{Path: "access.mutating", Value: azRoleMutating(actions), Derivation: "measured"},
		{Path: "access.privileged", Value: azRolePrivileged(actions), Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}, diags, nil
}

func (d *Driver) deleteAzureCustomRole(capability, environment, providerID string) provider.CreateResult {
	sub, guid, err := splitAzureCustomRoleProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	// D458 — ownership. A roleDefinition carries no tags, but its NAME is a GUID this
	// runtime derives from (scope, roleName): recomputing it is an exact answer, not a
	// heuristic. Deleting a stranger's custom role revokes every permission it grants
	// from every principal assigned to it, at once, with nothing to undo it.
	if want := azRoleDefGUID("/subscriptions/"+sub,
		azCustomRoleName(capability, environment)); guid != want {
		return provider.CreateResult{Status: "failed",
			Reason: "role definition id is not the one this contract would have minted — " +
				"refusing to delete a role that is not ours"}
	}
	st, resp, e := d.doARM("DELETE", d.customRoleURL(sub, guid), nil)
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
