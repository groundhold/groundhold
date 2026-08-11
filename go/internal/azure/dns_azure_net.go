// Azure DNS network shell (D101): the ARM half of the capability.dns.zone driver.
// The providerId carries the RESOURCE-TYPE fork (pub|priv) the exposure bit chose,
// so observe/delete address the right type (dnsZones vs privateDnsZones) with the
// right API version. A single PUT polled to provisioningState=Succeeded, ownership
// by tags. The RECORDS are never read or written. A zone that still holds records
// refuses deletion (Azure returns a conflict), never forced.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func azureDNSProviderID(sub, rg, kind, domain string) string {
	return "adns:" + sub + ":" + rg + ":" + kind + ":" + domain
}

func splitAzureDNSProviderID(providerID string) (sub, rg, kind, domain string, err error) {
	parts := strings.SplitN(providerID, ":", 5)
	if len(parts) != 5 || parts[0] != "adns" {
		return "", "", "", "", fmt.Errorf("providerId %q is not adns:sub:rg:kind:domain", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) {
		return "", "", "", "", fmt.Errorf("providerId %q has an invalid sub/rg", providerID)
	}
	if parts[3] != "pub" && parts[3] != "priv" {
		return "", "", "", "", fmt.Errorf("providerId kind %q is not pub|priv", parts[3])
	}
	if !azDNSDomainOK.MatchString(parts[4]) {
		return "", "", "", "", fmt.Errorf("providerId domain %q is invalid", parts[4])
	}
	return parts[1], parts[2], parts[3], parts[4], nil
}

// dnsTypePath returns the ARM provider path + API version for a (kind, domain).
func dnsTypePath(kind, domain string) (path, apiVersion string) {
	if kind == "pub" {
		return "Microsoft.Network/dnsZones/" + domain, publicDNSAPIVersion
	}
	return "Microsoft.Network/privateDnsZones/" + domain, privateDNSAPIVersion
}

func kindFor(public bool) string {
	if public {
		return "pub"
	}
	return "priv"
}

func (d *Driver) createAzureDNS(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAzureDNS(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure dns requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := azureDNSProviderID(d.Subscription, rg, kindFor(plan.Public), plan.Domain)
	zURL, _ := d.armURL(rg, plan.providerPath(), plan.apiVersion())
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	if r := d.putAndPoll(zURL, body, pid, "azure dns zone"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type azureDNSDoc struct {
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
	} `json:"properties"`
}

func (d *Driver) observeAzureDNS(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, kind, domain, err := splitAzureDNSProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	path, apiVersion := dnsTypePath(kind, domain)
	zURL, _ := d.armURL(rg, path, apiVersion)
	st, resp, e := d.doARM("GET", zURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("dnsZones.get: %v", e)
	}
	if st == http.StatusNotFound {
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"dns zone not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("dnsZones.get: HTTP %d", st)
	}
	var doc azureDNSDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "dnsZones.get", Cause: "body", Status: st}
	}
	// the resource TYPE that answered IS the public/private fact (measured).
	return []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "zone.domain", Value: domain, Derivation: "measured"},
		{Path: "network.publicExposure", Value: kind == "pub", Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "dnssec.enabled", Value: false, Derivation: "config-intent"},
	}, nil, nil
}

func (d *Driver) deleteAzureDNS(capability, environment, providerID string) provider.CreateResult {
	_, rg, kind, domain, err := splitAzureDNSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	path, apiVersion := dnsTypePath(kind, domain)
	zURL, _ := d.armURL(rg, path, apiVersion)
	st, resp, e := d.doARM("GET", zURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc azureDNSDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "dns zone tags do not match — refusing to delete a resource that is not ours"}
	}
	dst, dresp, de := d.doARM("DELETE", zURL, nil)
	if de != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", de)}
	}
	if dst == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if dst == http.StatusConflict {
		return provider.CreateResult{Status: "failed",
			Reason: "the zone still holds records and cannot be deleted — remove the record set first (never forced): " + mutDetailAz(dresp)}
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
