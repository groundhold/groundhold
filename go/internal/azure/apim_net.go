// Azure API Management network shell (D119): the ARM half of the Azure
// capability.apigateway.http driver. A single Microsoft.ApiManagement/service PUT
// polled to provisioningState=Succeeded; the service name is deterministic, so the
// providerId is knowable before the response (D29). Ownership is tags. D29/D87.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func apimProviderID(sub, rg, name string) string {
	return "apim:" + sub + ":" + rg + ":" + name
}

func splitAPIMProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "apim" {
		return "", "", "", fmt.Errorf("providerId %q is not apim:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || !apimNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) apimPath(name string) string {
	return "Microsoft.ApiManagement/service/" + name
}

func (d *Driver) createAPIM(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAPIM(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure apim requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := apimProviderID(d.Subscription, rg, plan.Name)
	url, _ := d.armURL(rg, d.apimPath(plan.Name), apimAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	if r := d.putAndPoll(url, body, pid, "api management service"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type apimDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
	} `json:"properties"`
}

func (d *Driver) observeAPIM(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitAPIMProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	url, _ := d.armURL(rg, d.apimPath(name), apimAPIVersion)
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("service.get: %v", e)
	}
	if st == http.StatusNotFound {
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"apim service not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("service.get: HTTP %d", st)
	}
	var doc apimDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "service.get", Cause: "body", Status: st}
	}
	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// an APIM service is an HTTP gateway.
		{Path: "protocol", Value: "http", Derivation: "config-intent"},
	}
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: strings.ToLower(doc.Location), Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteAPIM(capability, environment, providerID string) provider.CreateResult {
	_, rg, name, err := splitAPIMProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	url, _ := d.armURL(rg, d.apimPath(name), apimAPIVersion)
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
	var doc apimDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "apim service tags do not match — refusing to delete a resource that is not ours"}
	}
	// D984: route the delete through deleteAndConfirm (D971) — APIM DELETE returns
	// 202 Accepted (a long-running delete); concluding succeeded here tombstoned a
	// service still live. The helper polls to a confirmed 404, unknown on timeout.
	return *d.deleteAndConfirm(url, providerID, "api management")
}
