// Azure Container Registry network shell (D110): the ARM half of the
// capability.registry.image driver. A single PUT polled to provisioningState=Succeeded,
// ownership by tags. observe reverse-maps region / public reach / CMK. immutable.tags is
// not observed (Azure has no registry-level flag — it is refused at build).
//
// security.scanOnPush (fala 2) is measured from Microsoft Defender for Containers
// (Microsoft.Security/pricings/Containers, pricingTier=Standard) — a SUBSCRIPTION posture,
// not a registry field (the honest divergence from ECR's per-repo imageScanningConfiguration
// and even from GCP's project-level Container Scanning API, because Azure's mechanism has its
// OWN driver: capability.security.threatdetection). We REUSE the defender driver's pricings
// read (getDefenderPricing / defenderPlanContainers, same package) rather than duplicating
// it or reaching into defender.go. An unreadable pricing is a diagnostic, never a false
// reading (D29).
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func azureACRProviderID(sub, rg, name string) string { return "acr:" + sub + ":" + rg + ":" + name }

func splitAzureACRProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "acr" {
		return "", "", "", fmt.Errorf("providerId %q is not acr:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid sub/rg", providerID)
	}
	if !acrNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId registry name %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) createACR(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildACR(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed", Reason: "azure registry requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := azureACRProviderID(d.Subscription, rg, plan.Name)
	rURL, _ := d.armURL(rg, "Microsoft.ContainerRegistry/registries/"+plan.Name, acrAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	if r := d.putAndPoll(rURL, body, pid, "azure container registry"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type azureACRDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		PublicNetworkAccess string `json:"publicNetworkAccess"`
		Encryption          struct {
			Status string `json:"status"`
		} `json:"encryption"`
	} `json:"properties"`
}

func (d *Driver) observeACR(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitAzureACRProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	rURL, _ := d.armURL(rg, "Microsoft.ContainerRegistry/registries/"+name, acrAPIVersion)
	st, resp, e := d.doARM("GET", rURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("registries.get: %v", e)
	}
	if st == http.StatusNotFound {
		return nil, []string{"registry not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("registries.get: HTTP %d", st)
	}
	var doc azureACRDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "registries.get", Cause: "body", Status: st}
	}
	region := doc.Location
	if region == "" {
		region = "unknown"
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "encryption.customerManagedKeys", Value: doc.Properties.Encryption.Status == "enabled", Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	// publicNetworkAccess is a PREMIUM-only control on ACR: Basic/Standard
	// registries have no Private Link and ARM omits the field for them, so an
	// absent value is NOT "not public" — it is unknown. Never collapse absent to a
	// measured false (the false-safe direction that would falsely PASS a
	// no-public-exposure constraint on an always-public registry).
	switch doc.Properties.PublicNetworkAccess {
	case "Enabled":
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: true, Derivation: "measured"})
	case "Disabled":
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: false, Derivation: "measured"})
	default:
		diags = append(diags, "network.publicExposure not observed: publicNetworkAccess absent "+
			"(a Premium-only field ARM omits for Basic/Standard registries, which are always public)")
	}
	// security.scanOnPush is measured from Microsoft Defender for Containers
	// (Microsoft.Security/pricings/Containers, pricingTier=Standard), NOT from the registry
	// (Azure has no per-registry scanning field — the honest divergence from ECR, whose
	// scanOnPush is read off imageScanningConfiguration per repository). This is the SAME
	// subscription plan capability.security.threatdetection's protection.kubernetes governs;
	// we reuse the defender driver's pricings read. An unreadable pricing is a diagnostic,
	// never a false reading (D29). found=false (404, plan absent) is honestly scanOnPush=false.
	pricing, found, rerr := d.getDefenderPricing(sub, defenderPlanContainers)
	if rerr == nil {
		on := found && strings.EqualFold(pricing.Properties.PricingTier, "Standard")
		obs = append(obs, provider.Observation{Path: "security.scanOnPush", Value: on, Derivation: "measured"})
		diags = append(diags, "security.scanOnPush measured from Microsoft Defender for Containers "+
			"(Microsoft.Security/pricings/Containers), a subscription posture governed by "+
			"capability.security.threatdetection — not a per-registry setting; it is shared by every "+
			"registry in the subscription")
	} else {
		diags = append(diags, "security.scanOnPush not observed: the Microsoft Defender for "+
			"Containers pricing state (Microsoft.Security/pricings) gave no answer: "+rerr.Error())
	}
	return obs, diags, nil
}

func (d *Driver) deleteACR(capability, environment, providerID string) provider.CreateResult {
	_, rg, name, err := splitAzureACRProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rURL, _ := d.armURL(rg, "Microsoft.ContainerRegistry/registries/"+name, acrAPIVersion)
	st, resp, e := d.doARM("GET", rURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc azureACRDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed", Reason: "registry tags do not match — refusing to delete a resource that is not ours"}
	}
	dst, dresp, de := d.doARM("DELETE", rURL, nil)
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
