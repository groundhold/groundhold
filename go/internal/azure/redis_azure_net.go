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

	// D948: a zone-redundant (regional) cache pins to the region's availability zones. Fill
	// the zones from the subscription's AZ mapping and refuse up front if the region cannot
	// span at least two — rather than a Premium cache that does not survive a zone loss.
	// Skip-loudly (D75): an inconclusive AZ read falls back to the common [1,2,3] set rather
	// than blocking the create.
	if plan.ZoneRedundant {
		zones, known := d.regionLogicalZones(plan.Region)
		if known && len(zones) < 2 {
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf(
				"availability.class=regional (zone-redundant) needs a region with at least two "+
					"availability zones, but %s exposes %d to this subscription — refusing rather than "+
					"a Premium cache that cannot survive a zone loss; use availability.class=zonal or a "+
					"multi-AZ region", plan.Region, len(zones))}
		}
		if known {
			plan.Zones = zones
		} else {
			plan.Zones = []string{"1", "2", "3"}
		}
	}

	rURL, _ := d.armURL(rg, d.redisPath(plan.Name), redisAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	if r := d.putAndPoll(rURL, body, pid, "azure cache for redis"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type redisAzureDoc struct {
	Location string            `json:"location"`
	Tags     map[string]string `json:"tags"`
	// D946: zone redundancy lives in the top-level `zones` array, NOT in the SKU tier.
	// The observe used to derive availability.class from the tier (Standard→regional),
	// but Standard is a single-zone primary/replica (hardware failover only); zone
	// survival exists ONLY when this array is set (Premium/Enterprise).
	Zones      []string `json:"zones"`
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
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"cache instance not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("redis.get: HTTP %d", st)
	}
	var doc redisAzureDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "redis.get", Cause: "body", Status: st}
	}
	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "encryption.atRest", Value: true, Derivation: "platform-invariant"},
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
	// D946: availability.class from the ACTUAL zone-redundancy state, not the tier. A
	// cache with a populated top-level `zones` array survives an availability-zone loss
	// (regional); any cache without it — Basic OR Standard — is single-zone (zonal).
	// Reporting Standard as regional off the tier let a hard `availability.class ==
	// regional` constraint read satisfied against a cache that loses data on a zone
	// outage (the caplens.AvailabilityClass regional signal is zone redundancy, not a
	// two-node replica).
	if len(doc.Zones) > 0 {
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "regional", Derivation: "measured"})
	} else {
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "zonal", Derivation: "measured"})
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
	// D984: route the delete through deleteAndConfirm (D971) — Redis DELETE returns
	// 202 Accepted (async); concluding succeeded here tombstoned a cache still live.
	// The helper polls to a confirmed 404, unknown on timeout.
	return *d.deleteAndConfirm(rURL, providerID, "redis")
}

// regionLogicalZones reads the subscription's availability-zone mapping for a region —
// the logical zones a zone-redundant resource can pin to (D948). known=false on an
// inconclusive read (transport/HTTP/parse) so the caller falls back rather than blocking.
func (d *Driver) regionLogicalZones(region string) (zones []string, known bool) {
	url := d.BaseURL + "/subscriptions/" + d.Subscription + "/locations?api-version=2022-12-01"
	err := d.listAllARMPages("subscription.locations", url, func(body []byte) error {
		var doc struct {
			Value []struct {
				Name                     string `json:"name"`
				AvailabilityZoneMappings []struct {
					LogicalZone string `json:"logicalZone"`
				} `json:"availabilityZoneMappings"`
			} `json:"value"`
		}
		if json.Unmarshal(body, &doc) != nil {
			return fmt.Errorf("subscription locations page did not parse")
		}
		for _, l := range doc.Value {
			if strings.EqualFold(l.Name, region) {
				known = true
				for _, m := range l.AvailabilityZoneMappings {
					if m.LogicalZone != "" {
						zones = append(zones, m.LogicalZone)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, false
	}
	return zones, known
}
