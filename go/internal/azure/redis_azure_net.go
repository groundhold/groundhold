// Azure Cache for Redis network shell (D100): the ARM half of the
// capability.cache.keyvalue driver. A single async PUT (Microsoft.Cache/Redis)
// polled to provisioningState=Succeeded, tagged for ownership. Unlike Memorystore
// and ElastiCache, the cache CAN be publicly exposed, so observe reports
// network.publicExposure as a MEASURED toggle read back from publicNetworkAccess.
// D29/D87 honesty: a lost/garbled create is unknown WITH the deterministic pid.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func redisAzureProviderID(sub, rg, name string) string {
	return "aredis:" + sub + ":" + rg + ":" + name
}

func splitRedisAzureProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "aredis" {
		return "", "", "", fmt.Errorf("providerId %q is not aredis:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || !azNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) redisPath(name string) string {
	return "Microsoft.Cache/Redis/" + name
}

func (d *Driver) createRedisAzure(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildRedisAzure(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure cache for redis requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := redisAzureProviderID(d.Subscription, rg, plan.Name)
	rURL, _ := d.armURL(rg, d.redisPath(plan.Name), redisAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	if r := d.putAndPoll(rURL, body, pid, "azure cache for redis"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type redisAzureDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState   string `json:"provisioningState"`
		RedisVersion        string `json:"redisVersion"`
		PublicNetworkAccess string `json:"publicNetworkAccess"`
		EnableNonSslPort    *bool  `json:"enableNonSslPort"`
		Sku                 struct {
			Name string `json:"name"`
		} `json:"sku"`
	} `json:"properties"`
}

func (d *Driver) observeRedisAzure(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitRedisAzureProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	rURL, _ := d.armURL(rg, d.redisPath(name), redisAPIVersion)
	st, resp, e := d.doARM("GET", rURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("redis.get: %v", e)
	}
	if st == http.StatusNotFound {
		return nil, []string{"cache instance not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("redis.get: HTTP %d", st)
	}
	var doc redisAzureDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "redis.get", Cause: "body", Status: st}
	}
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "encryption.atRest", Value: true, Derivation: "config-intent"},
	}
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region",
			Value: strings.ToLower(doc.Location), Derivation: "measured"})
	}
	if v := redisAzureProtocolFor(doc.Properties.RedisVersion); v != "" {
		obs = append(obs, provider.Observation{Path: "engine.protocol", Value: v, Derivation: "measured"})
	}
	var diags []string
	switch doc.Properties.PublicNetworkAccess {
	case "Enabled":
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: true, Derivation: "measured"})
	case "Disabled":
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: false, Derivation: "measured"})
	default:
		diags = append(diags, "network.publicExposure not observed: publicNetworkAccess absent")
	}
	if doc.Properties.EnableNonSslPort != nil {
		obs = append(obs, provider.Observation{Path: "encryption.inTransit",
			Value: !*doc.Properties.EnableNonSslPort, Derivation: "measured"})
	}
	switch doc.Properties.Sku.Name {
	case "Basic":
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "zonal", Derivation: "measured"})
	case "Standard", "Premium":
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "regional", Derivation: "measured"})
	}
	return obs, diags, nil
}

// redisAzureProtocolFor reverse-maps the Azure redisVersion to engine.protocol.
func redisAzureProtocolFor(v string) string {
	switch {
	case strings.HasPrefix(v, "6"):
		return "redis/6"
	case strings.HasPrefix(v, "4"):
		return "redis/4"
	default:
		return ""
	}
}

func (d *Driver) deleteRedisAzure(capability, environment, providerID string) provider.CreateResult {
	_, rg, name, err := splitRedisAzureProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rURL, _ := d.armURL(rg, d.redisPath(name), redisAPIVersion)
	st, resp, e := d.doARM("GET", rURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc redisAzureDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "cache tags do not match — refusing to delete a resource that is not ours"}
	}
	dst, dresp, de := d.doARM("DELETE", rURL, nil)
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
