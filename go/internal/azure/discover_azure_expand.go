// Expanded Azure discovery sweeps (D52 brownfield): the driver PROVISIONS +
// OBSERVES far more than its first List sweep enumerated, leaving `groundhold
// discover --provider azure` blind to most of a production estate. These sweeps
// close the gap for the production-stack services — compute (Container Apps +
// jobs), network (VNet), identity (custom roles, role assignments, managed
// identities), secrets (Key Vault) — by ADDING the subscription-scope LIST and
// REUSING each service's existing observe reverse map. No new semantics are
// introduced here.
//
// D53: Key Vault discovery surfaces the vault's EXISTENCE + metadata only. The
// secret VALUE is a data-plane object groundhold never reads (observeKeyVault has
// no data-plane read); discovery inherits that guarantee unchanged.
//
// Four-valued discipline: a List that errors is a diagnostic for THAT sweep, never
// a fabricated absence; per-item observe failures append a diagnostic and skip,
// never hide a sibling. Region handling: ARM resource types split into REGIONAL
// (filtered to the requested region) and subscription-GLOBAL (roles + role
// assignments have no location — every one is surfaced regardless of region).
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

// azListItem is the shared subscription-scope list projection: every ARM resource
// carries id/name/location.
type azListItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
}

// discoverRegional is the shared regional sweep: list one resource type at
// subscription scope, keep the in-region ones, reverse-map each through the
// service's OWN observe (reuse, never re-derive). The providerId is built from the
// same (sub, rg, name) the service's observe expects.
func (d *Driver) discoverRegional(providerPath, apiVersion, region, resourceType, label string,
	pid func(sub, rg, name string) string,
	observe func(capability, providerID string) ([]provider.Observation, []string, error),
) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/%s?api-version=%s",
		d.BaseURL, d.Subscription, providerPath, apiVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%s.list: %v", label, err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("%s.list: HTTP %d", label, st)
	}
	var page struct {
		Value []azListItem `json:"value"`
	}
	if json.Unmarshal(resp, &page) != nil {
		return nil, nil, fmt.Errorf("%s: %w", label, armBody("list", st))
	}
	want := azRegion(region)
	var out []provider.Discovered
	var diags []string
	for _, it := range page.Value {
		if azRegion(it.Location) != want {
			continue // lives in another region — not this sweep
		}
		rg := resourceGroupOf(it.ID)
		if rg == "" {
			diags = append(diags, it.Name+": resource group unparseable from id")
			continue
		}
		p := pid(d.Subscription, rg, it.Name)
		obs, odiags, oerr := observe("", p)
		if oerr != nil {
			diags = append(diags, it.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, it.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   p,
			ResourceType: resourceType,
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverContainerApps enumerates Container Apps in the region as
// capability.workload.container (Microsoft.App/containerApps). The leaf app is the
// ledger identity; the managed environment is constitutive substrate, not swept.
func (d *Driver) discoverContainerApps(region string) ([]provider.Discovered, []string, error) {
	return d.discoverRegional("Microsoft.App/containerApps", appAPIVersion, region,
		"capability.workload.container", "containerApps", acaProviderID, d.observeContainerApp)
}

// discoverContainerAppsJobs enumerates Container Apps Jobs in the region as
// capability.container.job (Microsoft.App/jobs).
func (d *Driver) discoverContainerAppsJobs(region string) ([]provider.Discovered, []string, error) {
	return d.discoverRegional("Microsoft.App/jobs", containerAppsJobsAPIVersion, region,
		"capability.container.job", "jobs", containerAppsJobProviderID, d.observeContainerAppsJob)
}

// discoverVNet enumerates virtual networks in the region as
// capability.network.private (Microsoft.Network/virtualNetworks). The subnet + NSG
// composite is read back through the same observe egress-restricted derivation.
func (d *Driver) discoverVNet(region string) ([]provider.Discovered, []string, error) {
	return d.discoverRegional("Microsoft.Network/virtualNetworks", networkAPIVersion, region,
		"capability.network.private", "virtualNetworks", vnetProviderID, d.observeVNet)
}

// discoverKeyVault enumerates Key Vaults in the region as capability.secret
// (Microsoft.KeyVault/vaults). D53: existence + metadata ONLY — observeKeyVault
// never reads a secret value, and discovery adds no data-plane read.
func (d *Driver) discoverKeyVault(region string) ([]provider.Discovered, []string, error) {
	return d.discoverRegional("Microsoft.KeyVault/vaults", keyVaultAPIVersion, region,
		"capability.secret", "vaults", keyVaultProviderID, d.observeKeyVault)
}

// discoverManagedIdentity enumerates user-assigned managed identities in the region
// as capability.identity.serviceaccount
// (Microsoft.ManagedIdentity/userAssignedIdentities).
func (d *Driver) discoverManagedIdentity(region string) ([]provider.Discovered, []string, error) {
	return d.discoverRegional("Microsoft.ManagedIdentity/userAssignedIdentities", managedIdentityAPIVersion,
		region, "capability.identity.serviceaccount", "userAssignedIdentities",
		uamiProviderID, d.observeManagedIdentity)
}

// discoverCustomRoles enumerates CUSTOM role definitions as
// capability.authorization.role (Microsoft.Authorization/roleDefinitions). Roles are
// subscription-GLOBAL (no location) — every custom role is surfaced regardless of the
// requested region; built-in roles are skipped (they are not authored capabilities).
// The reverse map is observeAzureCustomRole, keyed by the roleDefinition GUID (the
// list item's name).
func (d *Driver) discoverCustomRoles(_ string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions?api-version=%s",
		d.BaseURL, d.Subscription, customRoleAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("roleDefinitions.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("roleDefinitions.list: HTTP %d", st)
	}
	var page struct {
		Value []struct {
			Name       string `json:"name"`
			Properties struct {
				Type string `json:"type"`
			} `json:"properties"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &page) != nil {
		return nil, nil, &armReadError{Op: "roleDefinitions.list", Cause: "body", Status: st}
	}
	var out []provider.Discovered
	var diags []string
	for _, r := range page.Value {
		if r.Properties.Type != "CustomRole" {
			continue // built-in roles are not groundhold-authored capabilities
		}
		pid := azureCustomRoleProviderID(d.Subscription, r.Name)
		obs, odiags, oerr := d.observeAzureCustomRole("", pid)
		if oerr != nil {
			diags = append(diags, r.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, r.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.authorization.role",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverRoleAssignments enumerates RBAC role assignments as
// capability.authorization.grant (Microsoft.Authorization/roleAssignments).
// Assignments are subscription-GLOBAL (no location) — every one at subscription
// scope is surfaced regardless of the requested region. There are no ownership tags
// (a grant is content-addressed); a real subscription can hold many, so this sweep
// surfaces the whole RBAC estate for selective adoption (parity with how the other
// sweeps surface every resource of their type). The reverse map is observeAzureRole,
// keyed by the assignment GUID (the list item's name).
func (d *Driver) discoverRoleAssignments(_ string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=%s",
		d.BaseURL, d.Subscription, roleAssignmentAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("roleAssignments.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("roleAssignments.list: HTTP %d", st)
	}
	var page struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &page) != nil {
		return nil, nil, &armReadError{Op: "roleAssignments.list", Cause: "body", Status: st}
	}
	var out []provider.Discovered
	var diags []string
	for _, a := range page.Value {
		if !azGUIDOK.MatchString(a.Name) {
			diags = append(diags, a.Name+": assignment name is not a valid GUID — skipped")
			continue
		}
		pid := azureRoleProviderID(d.Subscription, a.Name)
		obs, odiags, oerr := d.observeAzureRole("", pid)
		if oerr != nil {
			diags = append(diags, a.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, a.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.authorization.grant",
			Observations: obs,
		})
	}
	return out, diags, nil
}
