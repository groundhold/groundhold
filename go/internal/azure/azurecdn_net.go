// Azure Front Door Standard network shell (D118, reimplemented D999): the ARM half of
// the capability.cdn.distribution driver. Constitutive composite under one binding:
// profile (async LRO) -> origin group -> origin -> afd endpoint -> [secret] -> custom
// domains -> route. The providerId carries profile + endpoint; ownership is profile
// tags; delete removes the profile (which cascades every child). D29/D87 honesty
// throughout.
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
	profPath := d.cdnProfilePath(plan.Profile)

	// ---- 1. profile (the constitutive substrate; async LRO) ----
	profURL, _ := d.armURL(rg, profPath, azureCDNAPIVersion)
	profBody, _ := json.Marshal(plan.profileBody(d.tags(capability, environment)))
	if r := d.putAndPoll(profURL, profBody, pid, "afd profile"); r != nil {
		return *r
	}

	// ---- 2. origin group + origin (the backend the edge fetches from) ----
	ogURL, _ := d.armURL(rg, profPath+"/originGroups/"+plan.OriginGroup, azureCDNAPIVersion)
	ogBody, _ := json.Marshal(plan.originGroupBody())
	if r := d.putAndPoll(ogURL, ogBody, pid, "afd origin group"); r != nil {
		return *r
	}
	orURL, _ := d.armURL(rg, profPath+"/originGroups/"+plan.OriginGroup+"/origins/"+azCDNOriginName, azureCDNAPIVersion)
	orBody, _ := json.Marshal(plan.originBody())
	if r := d.putAndPoll(orURL, orBody, pid, "afd origin"); r != nil {
		return *r
	}

	// ---- 3. the afd endpoint (the edge hostname) ----
	epURL, _ := d.armURL(rg, profPath+"/afdEndpoints/"+plan.Endpoint, azureCDNAPIVersion)
	epBody, _ := json.Marshal(plan.afdEndpointBody())
	if r := d.putAndPoll(epURL, epBody, pid, "afd endpoint"); r != nil {
		return *r
	}

	// ---- 4. custom domains (D332/D999): a BYO cert first lands as a profile secret,
	// then each alias is a customDomains sub-resource whose tlsSettings names the cert
	// (managed or the secret). A managed cert provisions out of band after domain
	// validation — 2xx here means the resource is accepted, not that TLS is live. ----
	if plan.CertKeyVault != nil {
		secURL, _ := d.armURL(rg, profPath+"/secrets/"+plan.secretName(), azureCDNAPIVersion)
		secBody, _ := json.Marshal(plan.secretBody())
		if r := d.putAndPoll(secURL, secBody, pid, "afd secret"); r != nil {
			return *r
		}
	}
	for _, host := range plan.Aliases {
		cdName := customDomainResourceName(host)
		cdURL, _ := d.armURL(rg, profPath+"/customDomains/"+cdName, azureCDNAPIVersion)
		cdBody, _ := json.Marshal(plan.customDomainBody(d.Subscription, rg, host))
		if r := d.putAndPoll(cdURL, cdBody, pid, "afd custom domain"); r != nil {
			return *r
		}
	}

	// ---- 5. the route (ties endpoint -> origin group, carries viewer + cache posture,
	// associates any custom domains). Last, because it references the resources above. ----
	rtURL, _ := d.armURL(rg, profPath+"/afdEndpoints/"+plan.Endpoint+"/routes/"+plan.Route, azureCDNAPIVersion)
	rtBody, _ := json.Marshal(plan.routeBody(d.Subscription, rg))
	if r := d.putAndPoll(rtURL, rtBody, pid, "afd route"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// The origin group, origin, and route are profile-scoped children with FIXED names —
// the profile (uniquely named per capability) namespaces them, so fixed names never
// collide AND observe can address them from the providerId (profile+endpoint) alone,
// with no environment/generation to recompute.
const (
	azCDNOriginName  = "origin1"
	azCDNOriginGroup = "default-origin-group"
	azCDNRoute       = "default-route"
)

type azureCDNProfileDoc struct {
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
	} `json:"properties"`
}

type azureAFDRouteDoc struct {
	Properties struct {
		SupportedProtocols []string `json:"supportedProtocols"`
		HTTPSRedirect      string   `json:"httpsRedirect"`
	} `json:"properties"`
}

type azureAFDOriginDoc struct {
	Properties struct {
		HostName string `json:"hostName"`
	} `json:"properties"`
}

// afdViewerProtocol reverse-maps a route's supportedProtocols + httpsRedirect to the
// vocabulary's viewer.protocol. Https-only accepts only HTTPS; with HTTP accepted, the
// httpsRedirect flag distinguishes a 301 redirect from serving both.
func afdViewerProtocol(supported []string, httpsRedirect string) string {
	http := false
	for _, p := range supported {
		if strings.EqualFold(p, "Http") {
			http = true
		}
	}
	if !http {
		return "https-only"
	}
	if strings.EqualFold(httpsRedirect, "Enabled") {
		return "redirect-to-https"
	}
	return "allow-all"
}

func (d *Driver) observeAzureCDN(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, profile, endpoint, err := splitAzureCDNProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	profPath := d.cdnProfilePath(profile)
	// The afd endpoint is the existence anchor: a 404 here is the authoritative "gone".
	epURL, _ := d.armURL(rg, profPath+"/afdEndpoints/"+endpoint, azureCDNAPIVersion)
	st, _, e := d.doARM("GET", epURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("afdEndpoints.get: %v", e)
	}
	if st == http.StatusNotFound {
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"afd endpoint not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("afdEndpoints.get: HTTP %d", st)
	}
	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	// viewer.protocol lives on the route (supportedProtocols + httpsRedirect). The
	// origin group, origin, and route are profile-scoped children with FIXED names, so
	// they are fully derivable from the providerId (no env/generation needed here).
	rtURL, _ := d.armURL(rg, profPath+"/afdEndpoints/"+endpoint+"/routes/"+azCDNRoute, azureCDNAPIVersion)
	if rst, rresp, rerr := d.doARM("GET", rtURL, nil); rerr == nil && rst == http.StatusOK {
		var rt azureAFDRouteDoc
		if json.Unmarshal(rresp, &rt) == nil && len(rt.Properties.SupportedProtocols) > 0 {
			obs = append(obs, provider.Observation{Path: "viewer.protocol",
				Value: afdViewerProtocol(rt.Properties.SupportedProtocols, rt.Properties.HTTPSRedirect), Derivation: "measured"})
		} else {
			diags = append(diags, "route present but supportedProtocols unread — viewer.protocol omitted rather than fabricated")
		}
	} else {
		diags = append(diags, "route not read — viewer.protocol omitted rather than fabricated")
	}
	// origin.domain lives on the origin under the origin group.
	orURL, _ := d.armURL(rg, profPath+"/originGroups/"+azCDNOriginGroup+"/origins/"+azCDNOriginName, azureCDNAPIVersion)
	if ost, oresp, oerr := d.doARM("GET", orURL, nil); oerr == nil && ost == http.StatusOK {
		var or azureAFDOriginDoc
		if json.Unmarshal(oresp, &or) == nil && or.Properties.HostName != "" {
			obs = append(obs, provider.Observation{Path: "origin.domain", Value: or.Properties.HostName, Derivation: "measured"})
		}
	}
	return obs, diags, nil
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
	// D984: route the delete through deleteAndConfirm (D971) — a CDN profile DELETE
	// returns 202 Accepted (async); concluding succeeded here tombstoned a billable
	// profile still live. The helper polls to a confirmed 404, unknown on timeout.
	return *d.deleteAndConfirm(profURL, providerID, "cdn profile")
}
