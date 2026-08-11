// Azure AI Search network shell (D113): the ARM half of the capability.search.index
// driver. A single searchServices PUT polled to provisioningState=succeeded; the
// service name is deterministic, so the providerId is knowable before the response
// (D29). Ownership is tags. observe reverse-maps region / public reach / zone
// redundancy (from the SKU + replicas) / CMK enforcement. D29/D87 honesty throughout.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func aiSearchProviderID(sub, rg, name string) string {
	return "aisearch:" + sub + ":" + rg + ":" + name
}

func splitAISearchProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "aisearch" {
		return "", "", "", fmt.Errorf("providerId %q is not aisearch:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || !searchNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) aiSearchPath(name string) string {
	return "Microsoft.Search/searchServices/" + name
}

func (d *Driver) createAISearch(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAISearch(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure ai search requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := aiSearchProviderID(d.Subscription, rg, plan.Name)
	url, _ := d.armURL(rg, d.aiSearchPath(plan.Name), searchAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	if r := d.putAndPoll(url, body, pid, "ai search service"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type aiSearchDoc struct {
	Location   string                `json:"location"`
	Tags       map[string]string     `json:"tags"`
	Sku        struct{ Name string } `json:"sku"`
	Properties struct {
		ProvisioningState   string `json:"provisioningState"`
		PublicNetworkAccess string `json:"publicNetworkAccess"`
		ReplicaCount        int    `json:"replicaCount"`
		EncryptionWithCmk   struct {
			Enforcement string `json:"enforcement"`
		} `json:"encryptionWithCmk"`
	} `json:"properties"`
}

func (d *Driver) observeAISearch(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitAISearchProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	url, _ := d.armURL(rg, d.aiSearchPath(name), searchAPIVersion)
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("searchServices.get: %v", e)
	}
	if st == http.StatusNotFound {
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"search service not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("searchServices.get: HTTP %d", st)
	}
	var doc aiSearchDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "searchServices.get", Cause: "body", Status: st}
	}
	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "encryption.atRest", Value: true, Derivation: "platform-invariant"},
		{Path: "encryption.inTransit", Value: true, Derivation: "platform-invariant"},
		{Path: "network.publicExposure", Value: doc.Properties.PublicNetworkAccess != "disabled", Derivation: "measured"},
	}
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: strings.ToLower(doc.Location), Derivation: "measured"})
	}
	// availability.class: >=3 replicas on a Standard service distribute across availability
	// zones — but ONLY in a region that HAS them (D956). A region without availability zones
	// cannot be zone-redundant at any replica count, so the regional claim is GATED on the
	// region's AZ count (Microsoft.Resources locations — the same D948 helper flexpostgres D947
	// and redis D948 apply at create; field 2026-08-08: northcentralus exposes 0 AZs, westeurope
	// 3). AI Search exposes no zone field of its own, so the replica count is the strongest
	// direct signal and the region's AZ count is the necessary precondition. Skip-loudly (D75):
	// an inconclusive AZ read keeps the replica signal rather than downgrade on a read failure.
	var diags []string
	if doc.Sku.Name == "standard" && doc.Properties.ReplicaCount >= 3 {
		region := strings.ReplaceAll(strings.ToLower(doc.Location), " ", "")
		if zones, known := d.regionLogicalZones(region); known && len(zones) < 2 {
			obs = append(obs, provider.Observation{Path: "availability.class", Value: "zonal", Derivation: "measured"})
			diags = append(diags, "availability.class: region "+region+" exposes fewer than two "+
				"availability zones, so >=3 replicas are not zone-redundant (zonal, not regional)")
		} else {
			obs = append(obs, provider.Observation{Path: "availability.class", Value: "regional", Derivation: "measured"})
		}
	} else {
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "zonal", Derivation: "measured"})
	}
	obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: doc.Properties.EncryptionWithCmk.Enforcement == "Enabled", Derivation: "measured"})
	return obs, diags, nil
}

func (d *Driver) deleteAISearch(capability, environment, providerID string) provider.CreateResult {
	_, rg, name, err := splitAISearchProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	url, _ := d.armURL(rg, d.aiSearchPath(name), searchAPIVersion)
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
	var doc aiSearchDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "search service tags do not match — refusing to delete a resource that is not ours"}
	}
	// D984: route the delete through deleteAndConfirm (D971) — a Search service DELETE
	// returns 202 Accepted (async); concluding succeeded here tombstoned a service
	// (with its indexes) still live. The helper polls to a confirmed 404, unknown on
	// timeout.
	return *d.deleteAndConfirm(url, providerID, "cognitive search")
}
