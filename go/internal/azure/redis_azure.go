// Azure Cache for Redis request building (D100): the Azure half of the
// capability.cache.keyvalue driver — the SAME vocabulary GCP Memorystore and AWS
// ElastiCache fulfil. Two honest asymmetries versus the other clouds: (1) Azure
// Cache for Redis CAN have a public endpoint (publicNetworkAccess), so
// network.publicExposure is a REAL toggle here, not a refusal — the vocabulary
// stays honest across genuinely different provider capabilities. (2) the standard
// managed resource supports up to Redis 6 (Redis 7 is Enterprise) and offers no
// customer-managed key over the cache, so redis/7 and encryption.customerManagedKeys
// are honest one-cloud gaps (refused, not silently downgraded), the same stance as
// CMK on an Azure Key Vault secret (D97).
package azure

import (
	"fmt"
	"sort"
	"strconv"
)

const redisAPIVersion = "2023-08-01"

// RedisPlan is the attribute-derived shape a create assembles into an ARM body.
type RedisPlan struct {
	Name         string
	Region       string
	SkuName      string // Basic | Standard
	Capacity     int    // sizing (impl), default 1
	RedisVersion string // "6" | "4"
	Public       bool
	InTransit    bool
}

func redisAzureVersion(protocol string) (string, error) {
	engine, ver, ok := splitProtocol(protocol)
	if !ok || engine != "redis" {
		if engine == "memcached" {
			return "", fmt.Errorf("engine.protocol memcached has no managed Azure twin — refusing (honest one-cloud gap)")
		}
		return "", fmt.Errorf("engine.protocol %q is not a redis/N protocol", protocol)
	}
	switch ver {
	case "6":
		return "6", nil
	case "4":
		return "4", nil
	case "7":
		return "", fmt.Errorf(
			"redis/7 is not honored by Azure Cache for Redis (standard tiers support up to " +
				"Redis 6; Redis 7 is the Enterprise tier) — refusing rather than silently downgrading")
	default:
		return "", fmt.Errorf("redis version %q has no Azure Cache for Redis mapping", ver)
	}
}

func splitProtocol(p string) (engine, majorVer string, ok bool) {
	for i := 0; i < len(p); i++ {
		if p[i] == '/' {
			engine = p[:i]
			rest := p[i+1:]
			major := rest
			for j := 0; j < len(rest); j++ {
				if rest[j] == '.' {
					major = rest[:j]
					break
				}
			}
			return engine, major, true
		}
	}
	return p, "", false
}

// BuildRedisAzure maps capability.cache.keyvalue attributes + impl to an Azure
// Cache for Redis plan. Every error is a preflight refusal, never a silent drop.
func BuildRedisAzure(environment, capability string,
	attrs, impl map[string]any, generation int) (RedisPlan, error) {
	p := RedisPlan{
		Name:     azResourceName("pv-cache", environment, capability, generation),
		SkuName:  "Basic",
		Capacity: 1,
	}
	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "engine.protocol":
			proto, _ := raw.(string)
			v, err := redisAzureVersion(proto)
			if err != nil {
				return RedisPlan{}, err
			}
			p.RedisVersion = v
		case "location.region":
			p.Region, _ = raw.(string)
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "encryption.atRest":
			if raw != true {
				return RedisPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored by Azure Cache for Redis (always encrypted)")
			}
		case "encryption.inTransit":
			p.InTransit, _ = raw.(bool)
		case "encryption.customerManagedKeys":
			if raw == true {
				return RedisPlan{}, fmt.Errorf(
					"encryption.customerManagedKeys is not honored on Azure Cache for Redis: a " +
						"customer key over the cache is an Enterprise-tier feature, not the standard " +
						"managed resource — refusing rather than silently downgrading (honest one-cloud gap)")
			}
		case "availability.class":
			switch raw {
			case "zonal":
				p.SkuName = "Basic" // single node
			case "regional":
				p.SkuName = "Standard" // two-node replica
			case "multi-regional":
				return RedisPlan{}, fmt.Errorf(
					"availability.class=multi-regional has no single managed primitive on Azure Cache " +
						"for Redis (geo-replication is Premium cross-region topology) — refusing")
			default:
				return RedisPlan{}, fmt.Errorf("availability.class %v has no Azure Cache for Redis mapping", raw)
			}
		case "service.managed":
			if raw != true {
				return RedisPlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure Cache for Redis")
			}
		default:
			return RedisPlan{}, fmt.Errorf(
				"attribute %s has no Azure Cache for Redis mapping — refusing rather than silently "+
					"dropping it (capacity/sku size are implementation sizing)", path)
		}
	}
	if p.RedisVersion == "" {
		return RedisPlan{}, fmt.Errorf("cache requires engine.protocol (e.g. redis/6)")
	}
	if p.Region == "" {
		return RedisPlan{}, fmt.Errorf("cache requires location.region")
	}
	if c, ok := impl["capacity"]; ok {
		switch v := c.(type) {
		case float64:
			p.Capacity = int(v)
		case int:
			p.Capacity = v
		case string:
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return RedisPlan{}, fmt.Errorf("implementation.capacity %q is not a non-negative integer", v)
			}
			p.Capacity = n
		}
	}
	return p, nil
}

// createBody is the Redis PUT body. Family C covers Basic/Standard; the cache is
// SSL-only when inTransit (enableNonSslPort=false + a TLS floor).
func (p RedisPlan) createBody(tags map[string]any) map[string]any {
	access := "Disabled"
	if p.Public {
		access = "Enabled"
	}
	props := map[string]any{
		"sku":                 map[string]any{"name": p.SkuName, "family": "C", "capacity": p.Capacity},
		"redisVersion":        p.RedisVersion,
		"publicNetworkAccess": access,
		"enableNonSslPort":    !p.InTransit,
	}
	if p.InTransit {
		props["minimumTlsVersion"] = "1.2"
	}
	return map[string]any{
		"location":   p.Region,
		"tags":       tags,
		"properties": props,
	}
}
