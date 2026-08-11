// Azure Service Bus network shell (D99): the ARM half of the Azure messaging
// drivers. Constitutive composite under one binding: namespace (async) -> entity
// (queue or topic). The providerId carries namespace + entity; ownership is
// namespace tags; delete removes the namespace (and its entities). D29/D87 honesty
// throughout.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func sbProviderID(kind, sub, rg, ns, entity string) string {
	return kind + ":" + sub + ":" + rg + ":" + ns + ":" + entity
}

func splitSBProviderID(providerID string) (kind, sub, rg, ns, entity string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 5 || (parts[0] != "sbq" && parts[0] != "sbt") {
		return "", "", "", "", "", fmt.Errorf("providerId %q is not sb{q,t}:sub:rg:ns:entity", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) ||
		!azNameOK.MatchString(parts[3]) || !azNameOK.MatchString(parts[4]) {
		return "", "", "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[0], parts[1], parts[2], parts[3], parts[4], nil
}

func (d *Driver) sbNamespacePath(ns string) string {
	return "Microsoft.ServiceBus/namespaces/" + ns
}

// createSBNamespace PUTs the constitutive namespace and polls it to provisioned.
func (d *Driver) createSBNamespace(rg, ns, region string, public bool, capability, environment, pid string) *provider.CreateResult {
	url, _ := d.armURL(rg, d.sbNamespacePath(ns), serviceBusAPIVersion)
	pna := "Disabled"
	if public {
		pna = "Enabled"
	}
	body, _ := json.Marshal(map[string]any{
		"location":   region,
		"sku":        map[string]any{"name": "Standard", "tier": "Standard"},
		"tags":       d.tags(capability, environment),
		"properties": map[string]any{"publicNetworkAccess": pna},
	})
	return d.putAndPoll(url, body, pid, "service bus namespace")
}

func ttlISO(days int64) string { return fmt.Sprintf("P%dD", days) }

func (d *Driver) createServiceBusQueue(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildServiceBusQueue(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, sub, res := d.sbScope(impl)
	if res != nil {
		return *res
	}
	pid := sbProviderID("sbq", sub, rg, plan.Namespace, plan.Entity)
	if r := d.createSBNamespace(rg, plan.Namespace, plan.Region, plan.Public, capability, environment, pid); r != nil {
		return *r
	}
	qURL, _ := d.armURL(rg, d.sbNamespacePath(plan.Namespace)+"/queues/"+plan.Entity, serviceBusAPIVersion)
	body, _ := json.Marshal(map[string]any{"properties": sbQueueProps(plan)})
	if r := d.putSetting(qURL, body, pid, "service bus queue"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// sbQueueProps is the queue entity's properties body, shared by create and update so
// the two paths never drift. Dead-lettering (reliability.deadLetter): Azure's queue
// has a BUILT-IN dead-letter sub-queue, so there is no target to name — we set the
// retry threshold (maxDeliveryCount) and turn on deadLetteringOnMessageExpiration.
func sbQueueProps(plan ServiceBusPlan) map[string]any {
	props := map[string]any{
		"requiresDuplicateDetection": plan.Dedup,
		"requiresSession":            plan.Session,
	}
	if plan.TTLDays > 0 {
		props["defaultMessageTimeToLive"] = ttlISO(plan.TTLDays)
	}
	if plan.DeadLetter {
		props["maxDeliveryCount"] = plan.MaxDelivery
		props["deadLetteringOnMessageExpiration"] = true
	}
	return props
}

func (d *Driver) createServiceBusTopic(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildServiceBusTopic(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, sub, res := d.sbScope(impl)
	if res != nil {
		return *res
	}
	pid := sbProviderID("sbt", sub, rg, plan.Namespace, plan.Entity)
	if r := d.createSBNamespace(rg, plan.Namespace, plan.Region, plan.Public, capability, environment, pid); r != nil {
		return *r
	}
	tURL, _ := d.armURL(rg, d.sbNamespacePath(plan.Namespace)+"/topics/"+plan.Entity, serviceBusAPIVersion)
	body, _ := json.Marshal(map[string]any{"properties": map[string]any{}})
	if r := d.putSetting(tURL, body, pid, "service bus topic"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

func (d *Driver) sbScope(impl map[string]any) (rg, sub string, res *provider.CreateResult) {
	rg, _ = impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return "", "", &provider.CreateResult{Status: "failed", Reason: "azure service bus requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return "", "", &provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	return rg, d.Subscription, nil
}

type sbNamespaceDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState   string `json:"provisioningState"`
		PublicNetworkAccess string `json:"publicNetworkAccess"`
	} `json:"properties"`
}

type sbEntityDoc struct {
	Properties struct {
		DefaultMessageTimeToLive         string `json:"defaultMessageTimeToLive"`
		RequiresDuplicateDetection       bool   `json:"requiresDuplicateDetection"`
		RequiresSession                  bool   `json:"requiresSession"`
		MaxDeliveryCount                 int    `json:"maxDeliveryCount"`
		DeadLetteringOnMessageExpiration bool   `json:"deadLetteringOnMessageExpiration"`
	} `json:"properties"`
}

func (d *Driver) sbObserve(capability, providerID string) ([]provider.Observation, []string, error) {
	kind, sub, rg, ns, entity, err := splitSBProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	nsURL, _ := d.armURL(rg, d.sbNamespacePath(ns), serviceBusAPIVersion)
	st, resp, e := d.doARM("GET", nsURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("namespaces.get: %v", e)
	}
	if st == http.StatusNotFound {
		// F-LC3 (D523): the namespace holds the queue, so its absence is the bound
		// resource's absence. A diagnostic alone leaves the binding a no-op forever.
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"service bus namespace not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("namespaces.get: HTTP %d", st)
	}
	var nsDoc sbNamespaceDoc
	if json.Unmarshal(resp, &nsDoc) != nil {
		return nil, nil, &armReadError{Op: "namespaces.get", Cause: "body", Status: st}
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3).
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "encryption.atRest", Value: true, Derivation: "platform-invariant"},
	}
	if nsDoc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: strings.ToLower(nsDoc.Location), Derivation: "measured"})
	}
	var diags []string
	// publicNetworkAccess / Private Link is a PREMIUM-tier control on Service Bus;
	// Basic/Standard namespaces are always public and ARM can omit the field, so an
	// absent value is unknown, never a measured false (which would falsely PASS a
	// no-public-exposure constraint on an always-public namespace).
	switch nsDoc.Properties.PublicNetworkAccess {
	case "Enabled":
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: true, Derivation: "measured"})
	case "Disabled":
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: false, Derivation: "measured"})
	default:
		diags = append(diags, "network.publicExposure not observed: publicNetworkAccess absent "+
			"(a Premium-tier field ARM omits for Basic/Standard namespaces, which are always public)")
	}
	// queue-only: read the entity for delivery/ordering/retention.
	if kind == "sbq" {
		entURL, _ := d.armURL(rg, d.sbNamespacePath(ns)+"/queues/"+entity, serviceBusAPIVersion)
		if est, eresp, ee := d.doARM("GET", entURL, nil); ee == nil && est == http.StatusOK {
			var ed sbEntityDoc
			if json.Unmarshal(eresp, &ed) == nil {
				g := "at-least-once"
				if ed.Properties.RequiresDuplicateDetection {
					g = "exactly-once"
				}
				obs = append(obs,
					provider.Observation{Path: "delivery.guarantee", Value: g, Derivation: "measured"},
					provider.Observation{Path: "ordering.enabled", Value: ed.Properties.RequiresSession, Derivation: "measured"},
					// reliability.deadLetter posture: Azure's built-in DLQ is ALWAYS
					// present, so its existence is not the signal — the governed toggle
					// deadLetteringOnMessageExpiration is what groundhold set for this posture.
					provider.Observation{Path: "reliability.deadLetter",
						Value: ed.Properties.DeadLetteringOnMessageExpiration, Derivation: "measured"},
				)
			}
		}
	}
	return obs, diags, nil
}

// updateServiceBus honors an in-place change-set on a Service Bus QUEUE entity
// (reliability.deadLetter / retention.minimum) via a queues PUT (create-or-update).
// The change-set is gated — every path must be one classifyServiceBusQueueChange calls
// mutable — the desired plan is re-derived (refuse-before-mutate) from the hash-pinned
// candidate, and the rebuilt providerId must match the bound one (a forged binding must
// not redirect the mutation to another namespace/entity). Topics carry no mutable
// vocabulary, so an sbt providerId is refused. Four-valued on the wire.
func (d *Driver) updateServiceBus(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	kind, sub, rg, ns, entity, err := splitSBProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if kind != "sbq" {
		return provider.CreateResult{Status: "failed",
			Reason: "in-place update is only wired for Service Bus queues (topics carry no mutable vocabulary)"}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's — refusing to redirect the mutation", sub)}
	}
	for _, path := range changes {
		if k, reason := classifyServiceBusQueueChange(path); k != "mutable" {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("service bus queue cannot honor an in-place change to %q: %s", path, reason)}
		}
	}
	plan, err := BuildServiceBusQueue(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// A forged binding must not redirect the mutation: the rebuilt entity name must
	// match the bound one (namespace + entity are the create-time discriminators).
	if plan.Namespace != ns || plan.Entity != entity {
		return provider.CreateResult{Status: "failed",
			Reason: "rebuilt queue identity does not match the bound providerId — refusing to redirect the mutation"}
	}
	// D460 — ownership, before the PUT. The identity check above only proves the bound
	// providerId is self-consistent with the candidate; it says nothing about who owns
	// the namespace standing at that deterministic path. sbDelete has read the tags
	// since it was written. This did not, so an update wrote our queue properties into
	// a stranger's namespace — and an ARM PUT to an occupied path overwrites (D254).
	if r := d.refuseForeignSBNamespace(rg, ns, capability, environment, providerID,
		"update"); r != nil {
		return *r
	}
	qURL, _ := d.armURL(rg, d.sbNamespacePath(ns)+"/queues/"+entity, serviceBusAPIVersion)
	body, _ := json.Marshal(map[string]any{"properties": sbQueueProps(plan)})
	if r := d.putSetting(qURL, body, providerID, "service bus queue"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// refuseForeignSBNamespace is the ownership boundary both mutating verbs share. A queue
// has no tags of its own — the NAMESPACE carries them — so update and delete must ask
// the same question of the same resource. Sharing the code is the point: the two verbs
// disagreed about ownership for as long as each carried its own copy, and only one of
// the copies existed (D460).
//
// A namespace that is absent answers nil: the caller decides what "gone" means for its
// verb (idempotent success for delete, a failing PUT for update).
func (d *Driver) refuseForeignSBNamespace(rg, ns, capability, environment, providerID,
	verb string) *provider.CreateResult {
	nsURL, _ := d.armURL(rg, d.sbNamespacePath(ns), serviceBusAPIVersion)
	st, resp, e := d.doARM("GET", nsURL, nil)
	if e != nil {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-" + verb + " read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		if verb == "delete" {
			return &provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
		}
		return &provider.CreateResult{Status: "failed",
			Reason: "service bus namespace no longer exists — reconcile"}
	}
	if st != http.StatusOK {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-%s read HTTP %d — reconcile", verb, st)}
	}
	var nsDoc sbNamespaceDoc
	if json.Unmarshal(resp, &nsDoc) != nil {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-" + verb + " read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if nsDoc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		nsDoc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return &provider.CreateResult{Status: "failed",
			Reason: "service bus namespace tags do not match — refusing to " + verb +
				" a resource that is not ours"}
	}
	return nil
}

func (d *Driver) sbDelete(capability, environment, providerID string) provider.CreateResult {
	_, _, rg, ns, _, err := splitSBProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	nsURL, _ := d.armURL(rg, d.sbNamespacePath(ns), serviceBusAPIVersion)
	if r := d.refuseForeignSBNamespace(rg, ns, capability, environment, providerID,
		"delete"); r != nil {
		return *r
	}
	if r := d.deleteAndConfirm(nsURL, providerID, "service bus namespace"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
