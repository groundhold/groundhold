package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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
				State string `json:"state"`
				// D908: Azure returns this as a JSON number WITH a fraction (14.0), which
				// cannot decode into an int — the whole vault document then failed to
				// parse, so the pre-delete read returned "unparseable" and every retire
				// died as unknown (the vault was never deleted). float64 accepts 14.0.
				RetentionInDays float64 `json:"retentionDurationInDays"`
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
	if st == http.StatusNotFound {
		// F-LC3 (D522): a readable absence, not a failure to read. Folded into the
		// generic error it blocked the binding on unknown instead of re-creating.
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"backup vault not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("backupVaults GET: HTTP %d", st)
	}
	var doc backupVaultDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, fmt.Errorf("backupVaults GET: unparseable vault document")
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3).
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
	}
	var diags []string
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: doc.Location, Derivation: "measured"})
	}
	obs = append(obs, provider.Observation{Path: "service.managed", Value: true, Derivation: "measured"})
	if doc.Props.Security.SoftDelete.RetentionInDays > 0 {
		obs = append(obs, provider.Observation{Path: "retention.minimum",
			Value: fmt.Sprintf("%dh", int(doc.Props.Security.SoftDelete.RetentionInDays)*24), Derivation: "measured"})
	}
	switch doc.Props.Security.Immutability.State {
	case "Locked":
		obs = append(obs, provider.Observation{Path: "retention.lockMode", Value: "compliance", Derivation: "measured"})
	case "Unlocked":
		obs = append(obs, provider.Observation{Path: "retention.lockMode", Value: "governance", Derivation: "measured"})
	case "Disabled", "":
		// No immutability configured: a MEASURED off-value, not an absence (S3 D1041,
		// which reads an absent lock config as an authoritative `retention.locked:
		// false`). Omitting it would let a `compliance` candidate be adopted over a vault
		// with no immutability — a permanent false WORM assurance; `none` makes that read
		// VIOLATED. retention.minimum stays absent-when-off (the other half of the
		// precedent) — soft-delete already emitted it above when present.
		obs = append(obs, provider.Observation{Path: "retention.lockMode", Value: "none", Derivation: "measured"})
	default:
		// An immutability state this driver does not recognize (an Azure API change).
		// Do NOT assume `none` — that could false-VIOLATE a genuinely locked new state,
		// the wrong direction for a security attribute. Leave lockMode unobserved so a
		// hard constraint on it blocks at the audit floor rather than misreading.
		diags = append(diags, fmt.Sprintf("retention.lockMode not observed: unrecognized "+
			"immutability state %q — not classified rather than assumed unlocked",
			doc.Props.Security.Immutability.State))
	}
	obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: doc.Props.Security.Encryption.State == "Enabled", Derivation: "measured"})
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
		// D741: this rewrote EVERY failed delete to "vault still holds backup
		// instances" — a specific data-safety claim, asserted whatever the cause. A
		// missing `backupVaults/delete` permission, a throttle, a wrong subscription
		// and a policy denial all came back telling the operator to wait for recovery
		// points to age out. That is a cause we never established, and the action it
		// implies is wrong for every case but one.
		//
		// So ask. The vault's own backupInstances list is one call on a path that has
		// already failed, and it turns an invented reason into a measured one — or into
		// an honest "we could not tell".
		n, readable := d.countBackupInstances(url)
		switch {
		case readable && n > 0:
			r.Reason = fmt.Sprintf("vault still holds %d backup instance(s) — recovery "+
				"points are data; they must age out or be deleted first (never forced): %s",
				n, r.Reason)
		case readable:
			r.Reason = "the vault holds no backup instances, so this refusal is NOT about " +
				"stored data — the provider's own reason follows: " + r.Reason
		default:
			r.Reason = "the cause was not established (the vault's backup instances could " +
				"not be read) — the provider's own reason follows: " + r.Reason
		}
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
			Observations: provider.WithoutAbsence(obs),
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

// countBackupInstances reads how many backup instances a vault holds (D741). The second
// return is whether the answer was READ at all — an unreadable list must never become
// "empty", which is how a refusal starts asserting a cause nobody measured.
func (d *Driver) countBackupInstances(vaultURL string) (int, bool) {
	// The vault URL already carries ?api-version=...; the instances collection hangs
	// off the same resource path.
	base, query, _ := strings.Cut(vaultURL, "?")
	u := base + "/backupInstances"
	if query != "" {
		u += "?" + query
	}
	st, body, err := d.armGet(u)
	if err != nil || st != http.StatusOK {
		return 0, false
	}
	var doc struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return 0, false
	}
	return len(doc.Value), true
}
