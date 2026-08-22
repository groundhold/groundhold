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
		PartitionCount         int `json:"partitionCount"`
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
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"namespace not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("namespaces.get: HTTP %d", st)
	}
	var doc ehNamespaceDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "namespaces.get", Cause: "body", Status: st}
	}
	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
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
	obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: doc.Properties.Encryption.KeySource == "Microsoft.KeyVault", Derivation: "measured"})
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
	// D984: route the delete through deleteAndConfirm (D971) — an Event Hubs namespace
	// DELETE returns 202 Accepted (async); concluding succeeded here tombstoned a
	// data-bearing namespace still live. The helper polls to a confirmed 404, unknown
	// on timeout.
	return *d.deleteAndConfirm(nsURL, providerID, "event hubs namespace")
}

// classifyEventHubsChange decides whether a drift on an Event Hubs composite is reconciled in
// place or replaced. Before D1212 eventhubs had NO ClassifyChange, so every drift fell to the
// driver default of "immutable" = replacement. That verdict was being applied to
// retention.window — and replacing the namespace drops every event buffered in it and breaks
// every producer/consumer, to change a number Azure changes online. D1212: messageRetentionInDays
// is writable on the hub (a PUT), so retention.window is `mutable`; everything else stays
// "immutable" (honest replacement). The Azure counterpart of the Kinesis retention fix (D1211).
func classifyEventHubsChange(path string) (string, string) {
	switch path {
	case "retention.window":
		return "mutable", "retention.window is changed in place: messageRetentionInDays on the " +
			"hub (a PUT that preserves the partition count), so the retention policy changes without " +
			"replacing the namespace (which drops its buffered events)"
	default:
		return "immutable", fmt.Sprintf(
			"Event Hubs has no in-place update path for %q — reconciling a drift is a replacement", path)
	}
}

// updateEventHubs changes retention.window in place (D1212): a PUT of the hub with the new
// messageRetentionInDays, PRESERVING the partition count it read (partitionCount is writable in
// the schema but increase-only in practice — echoing the current value keeps the PUT from
// disturbing it). Ownership is the NAMESPACE's tags (the hub carries none), re-checked before any
// write. Four-valued via putSetting: an ambiguous PUT keeps the deterministic providerID.
func (d *Driver) updateEventHubs(capability, environment, providerID string,
	attrs map[string]any, changes []string) provider.CreateResult {
	sub, rg, ns, hub, err := splitEventHubsProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	nsURL, _ := d.armURL(rg, d.ehNamespacePath(ns), eventHubsAPIVersion)
	st, resp, e := d.doARM("GET", nsURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{Status: "failed", Reason: "namespace no longer exists — cannot update"}
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-update read HTTP %d — reconcile", st)}
	}
	var nsDoc ehNamespaceDoc
	if json.Unmarshal(resp, &nsDoc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if nsDoc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		nsDoc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "namespace tags do not match — refusing to patch a resource that is not ours"}
	}

	hubURL, _ := d.armURL(rg, d.ehNamespacePath(ns)+"/eventhubs/"+hub, eventHubsAPIVersion)
	for _, path := range changes {
		switch path {
		case "retention.window":
			days, derr := daysFromHours(attrs["retention.window"])
			if derr != nil {
				return provider.CreateResult{Status: "failed", Reason: "retention.window: " + derr.Error()}
			}
			// Read the hub to preserve its partition count (create-fixed; a PUT that omitted
			// it could reset it). A hub that 404s is a clean failure, not a silent create.
			hst, hresp, he := d.doARM("GET", hubURL, nil)
			if he != nil {
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: "hub pre-update read gave no answer — reconcile: " + azReadWhy(hst, hresp, he)}
			}
			if hst == http.StatusNotFound {
				return provider.CreateResult{Status: "failed", Reason: "event hub no longer exists — cannot update"}
			}
			if hst != http.StatusOK {
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: fmt.Sprintf("hub pre-update read HTTP %d — reconcile", hst)}
			}
			var hd ehHubDoc
			if json.Unmarshal(hresp, &hd) != nil {
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: "hub pre-update read answered HTTP 200 with an unparseable body — reconcile"}
			}
			props := map[string]any{"messageRetentionInDays": days}
			if hd.Properties.PartitionCount > 0 {
				props["partitionCount"] = hd.Properties.PartitionCount
			}
			body, _ := json.Marshal(map[string]any{"properties": props})
			if r := d.putSetting(hubURL, body, providerID, "event hub messageRetentionInDays"); r != nil {
				return *r
			}
		default:
			return provider.CreateResult{Status: "failed",
				Reason: "no azure eventhubs in-place mapping for " + path}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
