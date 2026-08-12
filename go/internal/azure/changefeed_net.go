// Azure Event Grid changefeed network shell: the ARM half of the Azure
// observability.changefeed driver. A single PUT of an event subscription at
// subscription scope (/subscriptions/{id}/providers/Microsoft.EventGrid/
// eventSubscriptions/{name}); the PUT is async (LRO), polled to
// properties.provisioningState == Succeeded. Ownership is the deterministic name
// (no tags on this proxy resource — the azcustomrole discipline). observe reverse-
// maps the StorageQueue destination back to feed.target + service.managed.
package azure

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func changeFeedProviderID(sub, name string) string { return "eventgrid:" + sub + ":" + name }

func splitChangeFeedProviderID(providerID string) (sub, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "eventgrid" {
		return "", "", fmt.Errorf("providerId %q is not eventgrid:sub:name", providerID)
	}
	if !subOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId subscription %q is invalid", parts[1])
	}
	if !azNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId event-subscription name %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

// changeFeedURL is the subscription-scoped event-subscription URL. The scope is the
// subscription itself (no resource group), so it is built directly rather than via
// armURL. sub is bounded by subOK and name by azNameOK before interpolation (D73).
func (d *Driver) changeFeedURL(sub, name string) (string, error) {
	if !subOK.MatchString(sub) {
		return "", fmt.Errorf("azure subscription %q is not a valid GUID", sub)
	}
	if !azNameOK.MatchString(name) {
		return "", fmt.Errorf("event-subscription name %q is invalid", name)
	}
	return fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.EventGrid/eventSubscriptions/%s?api-version=%s",
		d.BaseURL, sub, name, changeFeedAPIVersion), nil
}

func (d *Driver) createChangeFeed(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildChangeFeed(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := changeFeedProviderID(d.Subscription, plan.Name)
	url, err := d.changeFeedURL(d.Subscription, plan.Name)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	body, _ := json.Marshal(map[string]any{
		"properties": map[string]any{
			"destination": map[string]any{
				"endpointType": "StorageQueue",
				"properties": map[string]any{
					"resourceId": plan.StorageAccountID,
					"queueName":  plan.QueueName,
				},
			},
		},
	})
	st, resp, e := d.doARM("PUT", url, body)
	if e != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", e)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		return provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetailAz(resp))}
	}
	// PUT is an LRO; poll provisioningState to a terminal outcome.
	deadline := d.Now().Add(d.PollTimeout)
	for {
		state, readable := d.changeFeedState(d.Subscription, plan.Name)
		if readable {
			switch state {
			case "Succeeded":
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			case "Failed", "Canceled":
				return provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "event subscription entered state " + state}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "event subscription still provisioning at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

type changeFeedDoc struct {
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
		Destination       struct {
			EndpointType string `json:"endpointType"`
			Properties   struct {
				ResourceID string `json:"resourceId"`
				QueueName  string `json:"queueName"`
			} `json:"properties"`
		} `json:"destination"`
	} `json:"properties"`
}

// getChangeFeed reads the resource. D295: a read that produced nothing names its
// CAUSE (status + the provider's own code) instead of collapsing four
// different failures into one word; a 404 stays an authoritative absence.
func (d *Driver) getChangeFeed(sub, name string) (changeFeedDoc, bool, error) {
	var doc changeFeedDoc
	url, uerr := d.changeFeedURL(sub, name)
	if uerr != nil {
		return doc, false, &armReadError{Op: "eventSubscriptions.get", Cause: "scope", Detail: uerr.Error()}
	}
	found, err := d.armGetURLInto("eventSubscriptions.get", url, &doc)
	return doc, found, err
}

func (d *Driver) changeFeedState(sub, name string) (string, bool) {
	doc, found, rerr := d.getChangeFeed(sub, name)
	if rerr != nil || !found {
		// a poll helper answers (state, ok) — the CAUSE travels through the
		// observe/reconcile paths that need it; here "not ready yet" is the
		// honest reduction (D295 keeps the four-valued meaning intact).
		return "", false
	}
	return doc.Properties.ProvisioningState, true
}

func (d *Driver) observeChangeFeed(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, name, err := splitChangeFeedProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	doc, found, rerr := d.getChangeFeed(sub, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"event subscription not found — bound resource is gone (will re-create)"}, nil
	}
	// service.managed is intrinsic to Event Grid; a change feed that exists IS a
	// managed feed. It rides even if the destination is an unexpected endpoint type.
	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	dst := doc.Properties.Destination
	if dst.EndpointType == "StorageQueue" &&
		dst.Properties.ResourceID != "" && dst.Properties.QueueName != "" {
		obs = append(obs, provider.Observation{Path: "feed.target",
			Value:      composeFeedTarget(dst.Properties.ResourceID, dst.Properties.QueueName),
			Derivation: "measured"})
	} else {
		// A non-StorageQueue destination is not this driver's feed.target semantic;
		// name what was NOT observed and why (D44), never invent a target string.
		diags = append(diags, fmt.Sprintf(
			"feed.target not observed: destination endpointType %q is not StorageQueue", dst.EndpointType))
	}
	return obs, diags, nil
}

func (d *Driver) deleteChangeFeed(capability, environment, providerID string) provider.CreateResult {
	sub, name, err := splitChangeFeedProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: "providerId subscription is not the driver's — refusing to delete across subscriptions"}
	}
	// ownership: an EventGrid event subscription carries no tags — the deterministic
	// name is the evidence (D458).
	if !azNameLooksOurs(name, "pv-cf", environment, capability) {
		return provider.CreateResult{Status: "failed",
			Reason: "event subscription name does not carry our ownership marker — " +
				"refusing to delete a resource that is not ours"}
	}
	url, err := d.changeFeedURL(sub, name)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// D1012: an EventGrid event-subscription DELETE is a LONG-RUNNING operation —
	// EventSubscriptions_Delete is x-ms-long-running-operation in the 2025-02-15 spec,
	// with 202 among its responses. Concluding succeeded on the 202 would tombstone a
	// change-feed export channel that has only entered "deleting" and may still be
	// delivering events to its destination; if the async deletion then fails it is
	// orphaned from a ledger that says it is gone. Route through deleteAndConfirm (D971),
	// which polls a 202 to a confirmed 404 (unknown on timeout) exactly as the create
	// path polls provisioningState. A 200/204 is a synchronous delete — already gone.
	return *d.deleteAndConfirm(url, providerID, "event subscription")
}
