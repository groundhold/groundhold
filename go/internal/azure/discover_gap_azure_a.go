// Gap-closing Azure discovery sweeps, batch A (D52 brownfield): the driver
// PROVISIONS + OBSERVES these services today, but `groundhold discover --provider
// azure` never enumerated them. These sweeps ADD the subscription-scope LIST and
// REUSE each service's OWN observe reverse map (two-step: List gives providerIds,
// observe gives attributes). No new semantics — every ResourceType/observe pair is
// exactly the one the create/observe path already speaks.
//
// Region handling mirrors the existing split (discover_azure_expand.go): REGIONAL
// resources (registries, search, apim, event-hub/kafka namespaces, storage
// accounts) are filtered to the requested region by their `location`; GLOBAL
// resources (Azure CDN profiles/endpoints and DNS zones all carry location
// "Global"/none) are surfaced regardless of region — filtering them would fabricate
// absence, exactly as the role sweeps avoid.
//
// D53: azurefiles surfaces the storage account's EXISTENCE + metadata only, and DNS
// never reads a record set — both inherit the guarantee from their observe, which
// does no secret/data-plane read.
//
// Four-valued discipline: a List that errors is a diagnostic for THAT sweep (never a
// fabricated empty list); a per-resource observe failure appends a diagnostic and
// skips, never hiding a sibling.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

// ---- simple regional sweeps (sub/rg/name leaf) reuse the shared helper ----

// discoverACR enumerates container registries in the region as
// capability.registry.image (Microsoft.ContainerRegistry/registries), reverse-mapped
// through observeACR.
func (d *Driver) discoverACR(region string) ([]provider.Discovered, []string, error) {
	return d.discoverRegional("Microsoft.ContainerRegistry/registries", acrAPIVersion, region,
		"capability.registry.image", "acr registries", azureACRProviderID, d.observeACR)
}

// discoverAISearch enumerates AI Search services in the region as
// capability.search.index (Microsoft.Search/searchServices), reverse-mapped through
// observeAISearch.
func (d *Driver) discoverAISearch(region string) ([]provider.Discovered, []string, error) {
	return d.discoverRegional("Microsoft.Search/searchServices", searchAPIVersion, region,
		"capability.search.index", "aisearch searchServices", aiSearchProviderID, d.observeAISearch)
}

// discoverAPIM enumerates API Management services in the region as
// capability.apigateway.http (Microsoft.ApiManagement/service), reverse-mapped
// through observeAPIM.
func (d *Driver) discoverAPIM(region string) ([]provider.Discovered, []string, error) {
	return d.discoverRegional("Microsoft.ApiManagement/service", apimAPIVersion, region,
		"capability.apigateway.http", "apim service", apimProviderID, d.observeAPIM)
}

// discoverAzKafka enumerates Event Hubs (Kafka-endpoint) namespaces in the region as
// capability.messaging.kafka (Microsoft.EventHub/namespaces), reverse-mapped through
// observeAzKafka. Azure's managed Kafka IS an Event Hubs namespace — there is no
// distinct ARM type; the namespace is the binding (D115).
func (d *Driver) discoverAzKafka(region string) ([]provider.Discovered, []string, error) {
	return d.discoverRegional("Microsoft.EventHub/namespaces", azKafkaAPIVersion, region,
		"capability.messaging.kafka", "azkafka namespaces", azKafkaProviderID, d.observeAzKafka)
}

// ---- azurefiles: storage-account composite (account -> share leaf) ----

// discoverAzureFiles enumerates Azure Files shares in the region as
// capability.storage.filesystem: list storage accounts (Microsoft.Storage), keep the
// in-region ones, then the file shares under each, reverse-mapped through
// observeAzFiles (which reads the ACCOUNT — D53: metadata only, no share data-plane
// read). The share is the ledger leaf; the account is constitutive substrate.
func (d *Driver) discoverAzureFiles(region string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=%s",
		d.BaseURL, d.Subscription, storageAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("azfiles storageAccounts.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("azfiles storageAccounts.list: HTTP %d", st)
	}
	var accts struct {
		Value []azListItem `json:"value"`
	}
	if json.Unmarshal(resp, &accts) != nil {
		return nil, nil, &armReadError{Op: "azfiles storageAccounts.list", Cause: "body", Status: st}
	}
	want := azRegion(region)
	var out []provider.Discovered
	var diags []string
	for _, a := range accts.Value {
		if azRegion(a.Location) != want {
			continue // lives in another region — not this sweep
		}
		rg := resourceGroupOf(a.ID)
		if rg == "" {
			diags = append(diags, a.Name+": resource group unparseable from id")
			continue
		}
		out = append(out, d.azFilesShareLeaves(rg, a.Name, &diags)...)
	}
	return out, diags, nil
}

// azFilesShareLeaves lists the file shares under one storage account and projects each
// through observeAzFiles. A list error appends a diagnostic and yields nothing (never
// a fabricated absence for a sibling account).
func (d *Driver) azFilesShareLeaves(rg, account string, diags *[]string) []provider.Discovered {
	sURL, err := d.armURL(rg, "Microsoft.Storage/storageAccounts/"+account+"/fileServices/default/shares", storageAPIVersion)
	if err != nil {
		*diags = append(*diags, account+": "+err.Error())
		return nil
	}
	st, resp, e := d.doARM("GET", sURL, nil)
	if e != nil || st != http.StatusOK {
		*diags = append(*diags, account+"/shares: "+azReadWhy(st, resp, e))
		return nil
	}
	var shares struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	_ = json.Unmarshal(resp, &shares)
	var out []provider.Discovered
	for _, sh := range shares.Value {
		pid := azFilesProviderID(d.Subscription, rg, account, sh.Name)
		obs, odiags, oerr := d.observeAzFiles("", pid)
		if oerr != nil {
			*diags = append(*diags, account+"/"+sh.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			*diags = append(*diags, account+"/"+sh.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.storage.filesystem",
			Observations: obs,
		})
	}
	return out
}

// ---- azurecdn: profile -> endpoint composite (GLOBAL) ----

// discoverAzureCDN enumerates Azure CDN endpoints as capability.cdn.distribution:
// list profiles (Microsoft.Cdn/profiles), then the endpoints under each, reverse-
// mapped through observeAzureCDN. CDN is a global service (profiles carry location
// "Global" and observeAzureCDN emits no region), so — like the role sweeps — every
// endpoint is surfaced regardless of the requested region.
func (d *Driver) discoverAzureCDN(_ string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Cdn/profiles?api-version=%s",
		d.BaseURL, d.Subscription, azureCDNAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("azcdn profiles.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("azcdn profiles.list: HTTP %d", st)
	}
	var profiles struct {
		Value []azListItem `json:"value"`
	}
	if json.Unmarshal(resp, &profiles) != nil {
		return nil, nil, &armReadError{Op: "azcdn profiles.list", Cause: "body", Status: st}
	}
	var out []provider.Discovered
	var diags []string
	for _, prof := range profiles.Value {
		rg := resourceGroupOf(prof.ID)
		if rg == "" {
			diags = append(diags, prof.Name+": resource group unparseable from id")
			continue
		}
		out = append(out, d.azcdnEndpointLeaves(rg, prof.Name, &diags)...)
	}
	return out, diags, nil
}

// azcdnEndpointLeaves lists the endpoints under one CDN profile and projects each
// through observeAzureCDN. A list error appends a diagnostic and yields nothing.
func (d *Driver) azcdnEndpointLeaves(rg, profile string, diags *[]string) []provider.Discovered {
	eURL, err := d.armURL(rg, d.cdnProfilePath(profile)+"/endpoints", azureCDNAPIVersion)
	if err != nil {
		*diags = append(*diags, profile+": "+err.Error())
		return nil
	}
	st, resp, e := d.doARM("GET", eURL, nil)
	if e != nil || st != http.StatusOK {
		*diags = append(*diags, profile+"/endpoints: "+azReadWhy(st, resp, e))
		return nil
	}
	var eps struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	_ = json.Unmarshal(resp, &eps)
	var out []provider.Discovered
	for _, ep := range eps.Value {
		pid := azureCDNProviderID(d.Subscription, rg, profile, ep.Name)
		obs, odiags, oerr := d.observeAzureCDN("", pid)
		if oerr != nil {
			*diags = append(*diags, profile+"/"+ep.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			*diags = append(*diags, profile+"/"+ep.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.cdn.distribution",
			Observations: obs,
		})
	}
	return out
}

// ---- dnszone: two ARM resource types (GLOBAL) ----

// discoverDNSZone enumerates DNS zones as capability.dns.zone across BOTH ARM types
// the exposure bit forks into (D101): public Microsoft.Network/dnsZones and private
// Microsoft.Network/privateDnsZones, each with its own API version. Zones are global
// (location "global"), so every zone is surfaced regardless of the requested region.
// The zone RESOURCE NAME is the domain; records are never read (observeAzureDNS does
// no record-set read).
func (d *Driver) discoverDNSZone(_ string) ([]provider.Discovered, []string, error) {
	var out []provider.Discovered
	var diags []string
	pub, pd, perr := d.dnszoneZonesOfKind("Microsoft.Network/dnsZones", publicDNSAPIVersion, "pub")
	if perr != nil {
		return nil, nil, perr
	}
	out = append(out, pub...)
	diags = append(diags, pd...)
	priv, prd, prerr := d.dnszoneZonesOfKind("Microsoft.Network/privateDnsZones", privateDNSAPIVersion, "priv")
	if prerr != nil {
		return nil, nil, prerr
	}
	out = append(out, priv...)
	diags = append(diags, prd...)
	return out, diags, nil
}

// dnszoneZonesOfKind lists one DNS resource type at subscription scope and projects
// each zone through observeAzureDNS with the matching pub|priv kind. A list error is
// a hard error for the sweep (never a fabricated empty list).
func (d *Driver) dnszoneZonesOfKind(providerPath, apiVersion, kind string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/%s?api-version=%s",
		d.BaseURL, d.Subscription, providerPath, apiVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%s.list: %v", providerPath, err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("%s.list: HTTP %d", providerPath, st)
	}
	var page struct {
		Value []azListItem `json:"value"`
	}
	if json.Unmarshal(resp, &page) != nil {
		return nil, nil, fmt.Errorf("%s: %w", providerPath, armBody("list", st))
	}
	var out []provider.Discovered
	var diags []string
	for _, z := range page.Value {
		rg := resourceGroupOf(z.ID)
		if rg == "" {
			diags = append(diags, z.Name+": resource group unparseable from id")
			continue
		}
		pid := azureDNSProviderID(d.Subscription, rg, kind, z.Name)
		obs, odiags, oerr := d.observeAzureDNS("", pid)
		if oerr != nil {
			diags = append(diags, z.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, z.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.dns.zone",
			Observations: obs,
		})
	}
	return out, diags, nil
}
