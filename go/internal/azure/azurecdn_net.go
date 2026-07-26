// Azure CDN network shell (D118): the ARM half of the capability.cdn.distribution
// driver. Constitutive composite under one binding: profile (async, poll) ->
// endpoint. The providerId carries profile + endpoint; ownership is profile tags;
// delete removes the profile (and its endpoints). D29/D87 honesty throughout.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func azureCDNProviderID(sub, rg, profile, endpoint string) string {
	return "azcdn:" + sub + ":" + rg + ":" + profile + ":" + endpoint
}

func splitAzureCDNProviderID(providerID string) (sub, rg, profile, endpoint string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 5 || parts[0] != "azcdn" {
		return "", "", "", "", fmt.Errorf("providerId %q is not azcdn:sub:rg:profile:endpoint", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) ||
		!azNameOK.MatchString(parts[3]) || !azNameOK.MatchString(parts[4]) {
		return "", "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], parts[4], nil
}

func (d *Driver) cdnProfilePath(profile string) string {
	return "Microsoft.Cdn/profiles/" + profile
}

func (d *Driver) createAzureCDN(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAzureCDN(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure cdn requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := azureCDNProviderID(d.Subscription, rg, plan.Profile, plan.Endpoint)

	// ---- 1. profile (the constitutive substrate; async) ----
	profURL, _ := d.armURL(rg, d.cdnProfilePath(plan.Profile), azureCDNAPIVersion)
	profBody, _ := json.Marshal(plan.profileBody(d.tags(capability, environment)))
	if r := d.putAndPoll(profURL, profBody, pid, "cdn profile"); r != nil {
		return *r
	}

	// ---- 2. the endpoint (the leaf) ----
	epURL, _ := d.armURL(rg, d.cdnProfilePath(plan.Profile)+"/endpoints/"+plan.Endpoint, azureCDNAPIVersion)
	epBody, _ := json.Marshal(plan.endpointBody())
	if r := d.putSetting(epURL, epBody, pid, "cdn endpoint"); r != nil {
		return *r
	}

	// ---- 3. custom domains (D332): each alias is a customDomains sub-resource, then
	// its TLS is bound via a SEPARATE enableCustomHttps operation (Azure's model — not
	// an inline field like CloudFront's ViewerCertificate). ----
	epPath := d.cdnProfilePath(plan.Profile) + "/endpoints/" + plan.Endpoint
	for _, host := range plan.Aliases {
		cdName := customDomainResourceName(host)
		cdURL, _ := d.armURL(rg, epPath+"/customDomains/"+cdName, azureCDNAPIVersion)
		cdBody, _ := json.Marshal(plan.customDomainBody(host))
		if r := d.putSetting(cdURL, cdBody, pid, "cdn custom domain"); r != nil {
			return *r
		}
		// enableCustomHttps is an async action (202 Accepted); provisioning a managed
		// cert also waits on domain validation. 2xx = initiated; the binding completes
		// out of band, so we do not block on it here (surfaced honestly, not faked).
		httpsURL, _ := d.armURL(rg, epPath+"/customDomains/"+cdName+"/enableCustomHttps", azureCDNAPIVersion)
		httpsBody, _ := json.Marshal(plan.customHTTPSBody())
		st, resp, e := d.doARM("POST", httpsURL, httpsBody)
		if r := terminalOr(st, resp, e, pid, "cdn enableCustomHttps"); r != nil {
			return *r
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type azureCDNProfileDoc struct {
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
	} `json:"properties"`
}

type azureCDNEndpointDoc struct {
	Properties struct {
		IsHttpAllowed  bool `json:"isHttpAllowed"`
		IsHttpsAllowed bool `json:"isHttpsAllowed"`
		Origins        []struct {
			Properties struct {
				HostName string `json:"hostName"`
			} `json:"properties"`
		} `json:"origins"`
	} `json:"properties"`
}

func (d *Driver) observeAzureCDN(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, profile, endpoint, err := splitAzureCDNProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	epURL, _ := d.armURL(rg, d.cdnProfilePath(profile)+"/endpoints/"+endpoint, azureCDNAPIVersion)
	st, resp, e := d.doARM("GET", epURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("endpoints.get: %v", e)
	}
	if st == http.StatusNotFound {
		return nil, []string{"cdn endpoint not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("endpoints.get: HTTP %d", st)
	}
	var doc azureCDNEndpointDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "endpoints.get", Cause: "body", Status: st}
	}
	viewer := "https-only"
	if doc.Properties.IsHttpAllowed && doc.Properties.IsHttpsAllowed {
		viewer = "allow-all"
	}
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "viewer.protocol", Value: viewer, Derivation: "measured"},
	}
	if len(doc.Properties.Origins) > 0 && doc.Properties.Origins[0].Properties.HostName != "" {
		obs = append(obs, provider.Observation{Path: "origin.domain",
			Value: doc.Properties.Origins[0].Properties.HostName, Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteAzureCDN(capability, environment, providerID string) provider.CreateResult {
	_, rg, profile, _, err := splitAzureCDNProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	profURL, _ := d.armURL(rg, d.cdnProfilePath(profile), azureCDNAPIVersion)
	st, resp, e := d.doARM("GET", profURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc azureCDNProfileDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "cdn profile tags do not match — refusing to delete a resource that is not ours"}
	}
	dst, dresp, de := d.doARM("DELETE", profURL, nil)
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
