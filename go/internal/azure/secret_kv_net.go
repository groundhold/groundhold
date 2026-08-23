// Azure Key Vault network shell (D97): the ARM half of the capability.secret
// driver. The binding is the VAULT (Microsoft.KeyVault/vaults) — a single async
// PUT polled to provisioningState=Succeeded, tagged for ownership. The secret's
// VALUE is never written (data plane, out of band); the reserved secret name is
// surfaced in the create result, not created. Residency is honest: a vault lives
// in its ARM location. Delete removes the vault (the whole home) after an
// ownership tag pre-check; a vault that is not ours is refused, never deleted.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func keyVaultProviderID(sub, rg, vault string) string {
	return "akv:" + sub + ":" + rg + ":" + vault
}

func splitKeyVaultProviderID(providerID string) (sub, rg, vault string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "akv" {
		return "", "", "", fmt.Errorf("providerId %q is not akv:sub:rg:vault", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || !vaultNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) vaultPath(vault string) string {
	return "Microsoft.KeyVault/vaults/" + vault
}

func (d *Driver) createKeyVault(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildKeyVault(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure key vault requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := keyVaultProviderID(d.Subscription, rg, plan.Vault)

	vURL, _ := d.armURL(rg, d.vaultPath(plan.Vault), keyVaultAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	if r := d.putAndPoll(vURL, body, pid, "key vault"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded",
		Reason: "vault provisioned as the secret's home; the value is supplied out of band " +
			"(groundhold never writes it). Reserved secret name: " + plan.ReservedName}
}

type keyVaultDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState   string `json:"provisioningState"`
		PublicNetworkAccess string `json:"publicNetworkAccess"`
	} `json:"properties"`
}

func (d *Driver) observeKeyVault(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, vault, err := splitKeyVaultProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	vURL, _ := d.armURL(rg, d.vaultPath(vault), keyVaultAPIVersion)
	st, resp, e := d.doARM("GET", vURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("vaults.get: %v", e)
	}
	if st == http.StatusNotFound {
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"key vault not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("vaults.get: HTTP %d", st)
	}
	var doc keyVaultDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "vaults.get", Cause: "body", Status: st}
	}
	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "encryption.atRest", Value: true, Derivation: "platform-invariant"},
	}
	var diags []string
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region",
			Value: strings.ToLower(doc.Location), Derivation: "measured"})
	}
	switch doc.Properties.PublicNetworkAccess {
	case "Enabled":
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: true, Derivation: "measured"})
	case "Disabled":
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: false, Derivation: "measured"})
	default:
		diags = append(diags, "network.publicExposure not observed: publicNetworkAccess absent from the vault properties")
	}
	// The secret VALUE is data-plane and out of scope — never observed (groundhold
	// has no data-plane read here, and would not report a value if it did).
	return obs, diags, nil
}

func (d *Driver) deleteKeyVault(capability, environment, providerID string) provider.CreateResult {
	_, rg, vault, err := splitKeyVaultProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	vURL, _ := d.armURL(rg, d.vaultPath(vault), keyVaultAPIVersion)
	// ownership pre-read (the vault carries our tags).
	st, resp, e := d.doARM("GET", vURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + armTransport("vaults.get", e).Error()}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc keyVaultDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + armBody("vaults.get", st).Error()}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "key vault tags do not match — refusing to delete a resource that is not ours"}
	}
	dst, dresp, de := d.doARM("DELETE", vURL, nil)
	if de != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", de)}
	}
	if dst == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if dst >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", dst)}
	}
	if dst < 200 || dst >= 300 {
		if r := provider.MutationResult(dst, azErrCode(dresp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed",
			Reason: fmt.Sprintf("delete HTTP %d: %s", dst, mutDetailAz(dresp))}
	}
	// soft-delete is on: the vault is recoverable until its retention expires. That
	// is Azure's data-protection default (mirrors deletionProtection), not a lie
	// about the delete — the vault is gone from active use; purge is a separate,
	// deliberate act we do not take.
	// D1241: the same weaker-than-the-word success as the AWS twin, and its sibling in
	// this very package already says it. This driver CREATES the vault with
	// `enableSoftDelete: true` (secret_kv.go), so a delete leaves the vault recoverable
	// until its retention window expires — while `key_azure_net.go`, the vault for
	// capability.key.encryption, discloses precisely that on its own delete. One vault
	// delete in the package told the operator; the other did not.
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded",
		Reason: "vault (and its secret) deleted; this driver enables soft-delete at create, " +
			"so Azure keeps it RECOVERABLE until the retention window expires — purge is a " +
			"separate, deliberate act not taken here"}
}
