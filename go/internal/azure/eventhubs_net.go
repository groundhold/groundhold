// Azure Event Hubs network shell (D114): the ARM half of the capability.streaming.pipe
// driver. Constitutive composite under one binding: namespace (async, poll) ->
// event hub (entity). The providerId carries namespace + hub; ownership is namespace
// tags; delete removes the namespace (and its hubs). D29/D87 honesty throughout.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func eventHubsProviderID(sub, rg, ns, hub string) string {
	return "eventhubs:" + sub + ":" + rg + ":" + ns + ":" + hub
}

func splitEventHubsProviderID(providerID string) (sub, rg, ns, hub string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 5 || parts[0] != "eventhubs" {
		return "", "", "", "", fmt.Errorf("providerId %q is not eventhubs:sub:rg:ns:hub", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) ||
		!azNameOK.MatchString(parts[3]) || !azNameOK.MatchString(parts[4]) {
		return "", "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], parts[4], nil
}

func (d *Driver) ehNamespacePath(ns string) string {
	return "Microsoft.EventHub/namespaces/" + ns
}

func (d *Driver) createEventHubs(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildEventHubs(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure event hubs requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := eventHubsProviderID(d.Subscription, rg, plan.Namespace, plan.Hub)

	// ---- 1. namespace (the constitutive substrate; async) ----
	nsURL, _ := d.armURL(rg, d.ehNamespacePath(plan.Namespace), eventHubsAPIVersion)
	nsBody, _ := json.Marshal(plan.namespaceBody(d.tags(capability, environment)))
	if r := d.putAndPoll(nsURL, nsBody, pid, "event hubs namespace"); r != nil {
		return *r
	}

	// ---- 2. the event hub (entity) ----
	hubURL, _ := d.armURL(rg, d.ehNamespacePath(plan.Namespace)+"/eventhubs/"+plan.Hub, eventHubsAPIVersion)
	hubBody, _ := json.Marshal(plan.hubBody())
	if r := d.putSetting(hubURL, hubBody, pid, "event hub"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type ehNamespaceDoc struct {
	Location   string                `json:"location"`
	Tags       map[string]string     `json:"tags"`
	Sku        struct{ Name string } `json:"sku"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
		ZoneRedundant     bool   `json:"zoneRedundant"`
		Encryption        struct {
			KeySource string `json:"keySource"`
		} `json:"encryption"`
	} `json:"properties"`
}

type ehHubDoc struct {
	Properties struct {
		MessageRetentionInDays int `json:"messageRetentionInDays"`
	} `json:"properties"`
}

func (d *Driver) observeEventHubs(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, ns, hub := "", "", "", ""
	var err error
	sub, rg, ns, hub, err = splitEventHubsProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	nsURL, _ := d.armURL(rg, d.ehNamespacePath(ns), eventHubsAPIVersion)
	st, resp, e := d.doARM("GET", nsURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("namespaces.get: %v", e)
	}
	if st == http.StatusNotFound {
		return nil, []string{"namespace not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("namespaces.get: HTTP %d", st)
	}
	var doc ehNamespaceDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "namespaces.get", Cause: "body", Status: st}
	}
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: strings.ToLower(doc.Location), Derivation: "measured"})
	}
	if doc.Properties.ZoneRedundant {
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "regional", Derivation: "measured"})
	} else {
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "zonal", Derivation: "measured"})
	}
	if doc.Properties.Encryption.KeySource == "Microsoft.KeyVault" {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: true, Derivation: "measured"})
	}
	// retention lives on the hub entity.
	hubURL, _ := d.armURL(rg, d.ehNamespacePath(ns)+"/eventhubs/"+hub, eventHubsAPIVersion)
	if hst, hresp, he := d.doARM("GET", hubURL, nil); he == nil && hst == http.StatusOK {
		var hd ehHubDoc
		if json.Unmarshal(hresp, &hd) == nil && hd.Properties.MessageRetentionInDays > 0 {
			obs = append(obs, provider.Observation{Path: "retention.window",
				Value: fmt.Sprintf("%dh", hd.Properties.MessageRetentionInDays*24), Derivation: "measured"})
		}
	}
	return obs, nil, nil
}

func (d *Driver) deleteEventHubs(capability, environment, providerID string) provider.CreateResult {
	_, rg, ns, _, err := splitEventHubsProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	nsURL, _ := d.armURL(rg, d.ehNamespacePath(ns), eventHubsAPIVersion)
	st, resp, e := d.doARM("GET", nsURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc ehNamespaceDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "namespace tags do not match — refusing to delete a resource that is not ours"}
	}
	dst, dresp, de := d.doARM("DELETE", nsURL, nil)
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
