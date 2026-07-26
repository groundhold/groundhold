package azure

import (
	"encoding/json"
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

// backupVaultDoc is the subset of the ARM backupVaults resource observe reads.
type backupVaultDoc struct {
	Location string            `json:"location"`
	Tags     map[string]string `json:"tags"`
	Props    struct {
		Security struct {
			Immutability struct {
				State string `json:"state"` // Disabled | Unlocked | Locked
			} `json:"immutabilitySettings"`
			SoftDelete struct {
				State           string `json:"state"`
				RetentionInDays int    `json:"retentionDurationInDays"`
			} `json:"softDeleteSettings"`
			Encryption struct {
				State string `json:"state"` // Enabled when CMK
			} `json:"encryptionSettings"`
		} `json:"securitySettings"`
	} `json:"properties"`
}

// createBackupVault builds and PUTs the vault, polling provisioningState to
// Succeeded (a top-level ARM resource, like vnet/flex — unlike the synchronous
// backup POLICY child).
func (d *Driver) createBackupVault(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildBackupVault(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := backupVaultProviderID(d.Subscription, plan.ResourceGroup, plan.Name)
	url, err := d.backupVaultURL(plan.ResourceGroup, plan.Name)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if r := d.putAndPoll(url, d.backupVaultCreateBody(plan, capability, environment), pid, "backup vault"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// observeBackupVault reverse-maps a live vault. lockMode is fully distinguishable
// on Azure (the state field is authoritative), so — unlike AWS, which collapses to
// compliance — governance and compliance are both reported honestly.
func (d *Driver) observeBackupVault(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, vault, err := splitBackupVaultProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not ours", sub)
	}
	url, err := d.backupVaultURL(rg, vault)
	if err != nil {
		return nil, nil, err
	}
	st, resp, err := d.doARM("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("backupVaults GET: HTTP %d", st)
	}
	var doc backupVaultDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, fmt.Errorf("backupVaults GET: unparseable vault document")
	}
	var obs []provider.Observation
	var diags []string
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: doc.Location, Derivation: "measured"})
	}
	obs = append(obs, provider.Observation{Path: "service.managed", Value: true, Derivation: "measured"})
	if doc.Props.Security.SoftDelete.RetentionInDays > 0 {
		obs = append(obs, provider.Observation{Path: "retention.minimum",
			Value: fmt.Sprintf("%dh", doc.Props.Security.SoftDelete.RetentionInDays*24), Derivation: "measured"})
	}
	switch doc.Props.Security.Immutability.State {
	case "Locked":
		obs = append(obs, provider.Observation{Path: "retention.lockMode", Value: "compliance", Derivation: "measured"})
	case "Unlocked":
		obs = append(obs, provider.Observation{Path: "retention.lockMode", Value: "governance", Derivation: "measured"})
	}
	if doc.Props.Security.Encryption.State == "Enabled" {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: true, Derivation: "measured"})
	}
	return obs, diags, nil
}

// deleteBackupVault (D47): a compliance-Locked or still-populated vault refuses
// deletion — recovery points are data and must age out or be deleted first, never
// forced. Ownership (tags) is re-checked before any mutation.
func (d *Driver) deleteBackupVault(capability, environment, providerID string) provider.CreateResult {
	sub, rg, vault, err := splitBackupVaultProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not ours", sub)}
	}
	url, err := d.backupVaultURL(rg, vault)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	st, resp, err := d.doARM("GET", url, nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, err)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc backupVaultDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read unparseable — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "backup vault tags do not match — refusing to delete a resource that is not ours"}
	}
	if doc.Props.Security.Immutability.State == "Locked" {
		return provider.CreateResult{Status: "failed",
			Reason: "vault is immutability-Locked (compliance/WORM) — recovery points are data; " +
				"the lock must elapse, they are never force-deleted"}
	}
	r := d.deleteAndConfirm(url, providerID, "backup vault")
	if r != nil && r.Status == "failed" {
		// a still-populated vault refuses delete with a 4xx — surface the honest
		// stateful reason (D47), not the raw provider error.
		r.Reason = "vault still holds backup instances — recovery points are data; " +
			"they must age out or be deleted first (never forced): " + r.Reason
	}
	return *r
}

// discoverBackupVault enumerates DataProtection backup vaults in the region as
// adoptable capability.backup.vault resources (brownfield sweep — find all; the
// adoption decision is separate).
func (d *Driver) discoverBackupVault(region string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.DataProtection/backupVaults?api-version=%s",
		d.BaseURL, d.Subscription, dataProtectionAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("backupVaults.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("backupVaults.list: HTTP %d", st)
	}
	var vaults struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &vaults) != nil {
		return nil, nil, &armReadError{Op: "backupVaults.list", Cause: "body", Status: st}
	}
	want := azRegion(region)
	var out []provider.Discovered
	var diags []string
	for _, v := range vaults.Value {
		if azRegion(v.Location) != want {
			continue
		}
		rg := resourceGroupOf(v.ID)
		if rg == "" || !backupVaultNameOK.MatchString(v.Name) {
			diags = append(diags, v.Name+": not representable as a providerId")
			continue
		}
		pid := backupVaultProviderID(d.Subscription, rg, v.Name)
		obs, odiags, oerr := d.observeBackupVault("", pid)
		if oerr != nil {
			diags = append(diags, v.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, v.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.backup.vault",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// reconcileBackupVault concludes a lost create/delete by reading the live vault's
// provisioningState + ownership (D57).
func (d *Driver) reconcileBackupVault(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, vault, err := splitBackupVaultProviderID(pid)
	if err != nil {
		return badPidReconcile("backupvault", err)
	}
	return d.reconcileStdARM(pid, sub, rg, "Microsoft.DataProtection/backupVaults/"+vault,
		dataProtectionAPIVersion, "backup vault "+vault, capability, environment)
}
