// GCP Memorystore (Redis) request building (D100): the semantic core of the GCP
// capability.cache.keyvalue driver — the SAME vocabulary AWS ElastiCache and Azure
// Cache for Redis fulfil. Memorystore for Redis is ALWAYS private (VPC-internal, no
// public IP is ever assignable), so network.publicExposure=true is an honest
// refusal here, not a config toggle. Async create/delete via LRO (like Cloud SQL /
// Cloud Functions). memcached is a DIFFERENT service (Memorystore for Memcached) —
// this Redis driver refuses it rather than silently mis-provisioning.
package gcp

import (
	"fmt"
	"strconv"
	"strings"
)

const memorystoreBaseURL = "https://redis.googleapis.com/v1"

// MemorystorePlan is the attribute-derived shape a create assembles into the
// instance body.
type MemorystorePlan struct {
	Name              string
	Region            string
	RedisVersion      string // REDIS_7_0 | REDIS_6_X | ...
	Tier              string // BASIC (zonal) | STANDARD_HA (regional)
	MemorySizeGb      int    // sizing (impl), default 1
	TransitEncryption bool   // SERVER_AUTHENTICATION vs DISABLED
	KmsKey            string // CMEK, from impl; "" = provider-managed
}

// redisVersionFor maps an engine.protocol major (redis/N) to the Memorystore enum.
func redisVersionFor(protocol string) (string, error) {
	engine, ver, ok := strings.Cut(protocol, "/")
	if !ok || strings.ToLower(engine) != "redis" {
		if strings.ToLower(engine) == "memcached" {
			return "", fmt.Errorf(
				"engine.protocol memcached cannot be honored by Memorystore for Redis " +
					"(Memcached is a separate managed service) — refusing rather than mis-provisioning")
		}
		return "", fmt.Errorf("engine.protocol %q is not a redis/N protocol", protocol)
	}
	switch strings.SplitN(ver, ".", 2)[0] {
	case "7":
		return "REDIS_7_0", nil
	case "6":
		return "REDIS_6_X", nil
	case "5":
		return "REDIS_5_0", nil
	case "4":
		return "REDIS_4_0", nil
	default:
		return "", fmt.Errorf("redis version %q has no Memorystore mapping", ver)
	}
}

// BuildMemorystoreCreate maps capability.cache.keyvalue attributes + the impl block
// to a Memorystore create plan. Every error is a refusal apply surfaces in
// preflight, before any mutation — never a silently dropped attribute.
func BuildMemorystoreCreate(project, environment, capability string,
	attrs, impl map[string]any, generation int) (MemorystorePlan, error) {
	p := MemorystorePlan{
		Name:         resourceName(project, environment, capability, generation, 40),
		Tier:         "BASIC", // zonal baseline unless availability says otherwise
		MemorySizeGb: 1,
	}
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "engine.protocol":
			proto, _ := raw.(string)
			v, err := redisVersionFor(proto)
			if err != nil {
				return MemorystorePlan{}, err
			}
			p.RedisVersion = v
		case "location.region":
			p.Region, _ = raw.(string)
		case "network.publicExposure":
			if raw == true {
				return MemorystorePlan{}, fmt.Errorf(
					"network.publicExposure=true cannot be honored by Memorystore for Redis " +
						"(instances are always VPC-private, no public IP is assignable) — refusing " +
						"rather than pretending to expose it")
			}
		case "encryption.atRest":
			if raw != true {
				return MemorystorePlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored by Memorystore (always encrypted at rest)")
			}
		case "encryption.inTransit":
			p.TransitEncryption, _ = raw.(bool)
		case "encryption.customerManagedKeys":
			if raw == true {
				p.KmsKey, _ = impl["kms_key_name"].(string)
				if p.KmsKey == "" {
					return MemorystorePlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_name")
				}
			}
		case "availability.class":
			switch raw {
			case "zonal":
				p.Tier = "BASIC"
			case "regional":
				p.Tier = "STANDARD_HA"
			case "multi-regional":
				return MemorystorePlan{}, fmt.Errorf(
					"availability.class=multi-regional has no single managed Memorystore primitive " +
						"(cross-region is app-level replication topology) — refusing rather than faking it")
			default:
				return MemorystorePlan{}, fmt.Errorf("availability.class %v has no Memorystore mapping", raw)
			}
		case "service.managed":
			if raw != true {
				return MemorystorePlan{}, fmt.Errorf("service.managed=false cannot be honored by Memorystore")
			}
		default:
			return MemorystorePlan{}, fmt.Errorf(
				"attribute %s has no Memorystore mapping — refusing rather than silently dropping it "+
					"(memory size, node type, eviction policy are implementation sizing/tuning)", path)
		}
	}
	if p.RedisVersion == "" {
		return MemorystorePlan{}, fmt.Errorf("cache requires engine.protocol (e.g. redis/7)")
	}
	if p.Region == "" {
		return MemorystorePlan{}, fmt.Errorf("cache requires location.region")
	}
	if !projectOK.MatchString(project) {
		return MemorystorePlan{}, fmt.Errorf("project %q is invalid", project)
	}
	// memory size is sizing (impl); accept an override, default 1GB.
	if ms, ok := impl["memory_size_gb"]; ok {
		switch v := ms.(type) {
		case float64:
			p.MemorySizeGb = int(v)
		case int:
			p.MemorySizeGb = v
		case string:
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return MemorystorePlan{}, fmt.Errorf("implementation.memory_size_gb %q is not a positive integer", v)
			}
			p.MemorySizeGb = n
		}
	}
	if p.MemorySizeGb < 1 {
		p.MemorySizeGb = 1
	}
	return p, nil
}

// createBody is the instances.create request body. Ownership is labels; the
// instance is always private (no public IP field exists to set).
func (p MemorystorePlan) createBody(capability, environment string) map[string]any {
	transit := "DISABLED"
	if p.TransitEncryption {
		transit = "SERVER_AUTHENTICATION"
	}
	body := map[string]any{
		"tier":                  p.Tier,
		"memorySizeGb":          p.MemorySizeGb,
		"redisVersion":          p.RedisVersion,
		"transitEncryptionMode": transit,
		"authEnabled":           true,
		"labels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
	}
	if p.KmsKey != "" {
		body["customerManagedKey"] = p.KmsKey
	}
	return body
}
