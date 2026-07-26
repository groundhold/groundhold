// Azure Event Hubs Kafka network shell (D115): the ARM half of the Azure
// capability.messaging.kafka driver. A single Event Hubs namespace PUT (kafkaEnabled)
// polled to provisioningState=Succeeded; the namespace name is deterministic, so the
// providerId is knowable before the response (D29). Ownership is tags. D29/D87 honesty.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func azKafkaProviderID(sub, rg, ns string) string {
	return "azkafka:" + sub + ":" + rg + ":" + ns
}

func splitAzKafkaProviderID(providerID string) (sub, rg, ns string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "azkafka" {
		return "", "", "", fmt.Errorf("providerId %q is not azkafka:sub:rg:namespace", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || !azNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) azKafkaPath(ns string) string {
	return "Microsoft.EventHub/namespaces/" + ns
}

func (d *Driver) createAzKafka(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAzKafka(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure event hubs kafka requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := azKafkaProviderID(d.Subscription, rg, plan.Namespace)
	url, _ := d.armURL(rg, d.azKafkaPath(plan.Namespace), azKafkaAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	if r := d.putAndPoll(url, body, pid, "event hubs kafka namespace"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type azKafkaDoc struct {
	Location   string                `json:"location"`
	Tags       map[string]string     `json:"tags"`
	Sku        struct{ Name string } `json:"sku"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
		KafkaEnabled      bool   `json:"kafkaEnabled"`
		ZoneRedundant     bool   `json:"zoneRedundant"`
		Encryption        struct {
			KeySource string `json:"keySource"`
		} `json:"encryption"`
	} `json:"properties"`
}

func (d *Driver) observeAzKafka(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, ns, err := splitAzKafkaProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	url, _ := d.armURL(rg, d.azKafkaPath(ns), azKafkaAPIVersion)
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("namespaces.get: %v", e)
	}
	if st == http.StatusNotFound {
		return nil, []string{"namespace not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("namespaces.get: HTTP %d", st)
	}
	var doc azKafkaDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "namespaces.get", Cause: "body", Status: st}
	}
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "encryption.inTransit", Value: true, Derivation: "config-intent"},
		{Path: "engine.protocol", Value: "kafka/3", Derivation: "config-intent"},
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
	return obs, nil, nil
}

func (d *Driver) deleteAzKafka(capability, environment, providerID string) provider.CreateResult {
	_, rg, ns, err := splitAzKafkaProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	url, _ := d.armURL(rg, d.azKafkaPath(ns), azKafkaAPIVersion)
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
	var doc azKafkaDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "namespace tags do not match — refusing to delete a resource that is not ours"}
	}
	dst, dresp, de := d.doARM("DELETE", url, nil)
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
