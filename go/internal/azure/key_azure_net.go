// Azure Key Vault key network shell (D102): the ARM half of the
// capability.key.encryption driver. Create is the constitutive-composite sequence
// vault (async, polled) then key. Ownership is the vault's tags. Delete removes the
// VAULT (which removes the key with it); Azure soft-delete keeps it recoverable for
// the retention window — the result says so rather than claim hard removal. The key
// MATERIAL is never read. D29/D87 honesty throughout.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"groundhold/internal/provider"
)

// azKeyRegionOK bounds an Azure region before it is interpolated into a providerId.
var azKeyRegionOK = regexp.MustCompile(`^[a-z][a-z0-9]{2,39}$`)

func azureKeyProviderID(sub, rg, region, vault, key string) string {
	return "akvkey:" + sub + ":" + rg + ":" + region + ":" + vault + ":" + key
}

func splitAzureKeyProviderID(providerID string) (sub, rg, region, vault, key string, err error) {
	parts := strings.SplitN(providerID, ":", 6)
	if len(parts) != 6 || parts[0] != "akvkey" {
		return "", "", "", "", "", fmt.Errorf("providerId %q is not akvkey:sub:rg:region:vault:key", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || !azKeyRegionOK.MatchString(parts[3]) ||
		!vaultNameOK.MatchString(parts[4]) || !azNameOK.MatchString(parts[5]) {
		return "", "", "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], parts[4], parts[5], nil
}

func (d *Driver) keyPath(vault, key string) string {
	return "Microsoft.KeyVault/vaults/" + vault + "/keys/" + key
}

func (d *Driver) createAzureKey(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAzureKey(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed", Reason: "azure key vault requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := azureKeyProviderID(d.Subscription, rg, plan.Region, plan.Vault, plan.Key)

	// ---- 1. vault (constitutive, async) ----
	vURL, _ := d.armURL(rg, d.vaultPath(plan.Vault), keyVaultAPIVersion)
	vbody, _ := json.Marshal(plan.vaultCreateBody(d.tags(capability, environment)))
	if r := d.putAndPoll(vURL, vbody, pid, "key vault"); r != nil {
		return *r
	}
	// ---- 2. key ----
	kURL, _ := d.armURL(rg, d.keyPath(plan.Vault, plan.Key), keyVaultAPIVersion)
	kbody, _ := json.Marshal(plan.keyCreateBody())
	if r := d.putSetting(kURL, kbody, pid, "key"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type azureKeyDoc struct {
	Properties struct {
		Kty            string `json:"kty"`
		RotationPolicy struct {
			LifetimeActions []struct {
				Trigger struct {
					TimeAfterCreate string `json:"timeAfterCreate"`
				} `json:"trigger"`
			} `json:"lifetimeActions"`
		} `json:"rotationPolicy"`
	} `json:"properties"`
}

func (d *Driver) observeAzureKey(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, region, vault, key, err := splitAzureKeyProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	kURL, _ := d.armURL(rg, d.keyPath(vault, key), keyVaultAPIVersion)
	st, resp, e := d.doARM("GET", kURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("keys.get: %v", e)
	}
	if st == http.StatusNotFound {
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"key not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("keys.get: HTTP %d", st)
	}
	var doc azureKeyDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "keys.get", Cause: "body", Status: st}
	}
	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	// D1069-class: protection.level for EVERY key type, not only RSA. Azure marks
	// HSM-backed keys with a `-HSM` suffix on the key type (RSA-HSM, EC-HSM, oct-HSM);
	// any other type is software-protected. Matching only RSA/RSA-HSM emitted NOTHING for
	// an EC or oct key, so a `protection.level: hsm` candidate was adopted/verified as
	// satisfied over a software EC key (a false HSM assurance). The suffix rule is the
	// measured fact for all types.
	if kty := doc.Properties.Kty; kty != "" {
		level := "software"
		if strings.HasSuffix(kty, "-HSM") {
			level = "hsm"
		}
		obs = append(obs, provider.Observation{Path: "protection.level", Value: level, Derivation: "measured"})
	}
	// D1040/D1067: rotation.enabled is emitted for BOTH states — a key with no active
	// rotation policy is a MEASURED false (rotation OFF), not an absence. Emitting only
	// the ON case let a rotation contract be adopted/verified as satisfied over a key
	// that never rotates (the cross-cloud twin of the AWS/GCP KMS fix). rotation.period
	// is emitted only when the policy actually rotates the key.
	rotDays := 0
	if la := doc.Properties.RotationPolicy.LifetimeActions; len(la) > 0 {
		rotDays = isoDaysToInt(la[0].Trigger.TimeAfterCreate)
	}
	obs = append(obs, provider.Observation{Path: "rotation.enabled",
		Value: rotDays > 0, Derivation: "measured"})
	if rotDays > 0 {
		obs = append(obs, provider.Observation{Path: "rotation.period",
			Value: fmt.Sprintf("%dd", rotDays), Derivation: "measured"})
	}
	return obs, nil, nil
}

// isoDaysToInt parses a "P<N>D" ISO-8601 duration into whole days (0 on anything else).
func isoDaysToInt(iso string) int {
	if len(iso) < 3 || iso[0] != 'P' || iso[len(iso)-1] != 'D' {
		return 0
	}
	n, err := strconv.Atoi(iso[1 : len(iso)-1])
	if err != nil {
		return 0
	}
	return n
}

func (d *Driver) deleteAzureKey(capability, environment, providerID string) provider.CreateResult {
	_, rg, _, vault, _, err := splitAzureKeyProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// ownership pre-read on the vault (the substrate carries our tags); deleting
	// the vault removes the key with it.
	vURL, _ := d.armURL(rg, d.vaultPath(vault), keyVaultAPIVersion)
	st, resp, e := d.doARM("GET", vURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var vdoc struct {
		Tags map[string]string `json:"tags"`
	}
	if json.Unmarshal(resp, &vdoc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if vdoc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		vdoc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "key vault tags do not match — refusing to delete a resource that is not ours"}
	}
	dst, dresp, de := d.doARM("DELETE", vURL, nil)
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
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded",
		Reason: "vault (and its key) deleted; Azure soft-delete keeps it recoverable until the retention " +
			"window expires — purge is a separate, deliberate act not taken here"}
}
