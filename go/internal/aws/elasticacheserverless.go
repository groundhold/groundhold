// ElastiCache Serverless request building: a SECOND AWS backend for
// capability.cache.keyvalue, alongside the provisioned `elasticache`
// replication group. Serverless is the pay-per-use cost lever — no node type,
// no shard/replica count, no cluster sizing: capacity auto-scales, so every
// provisioned sizing operand is a REFUSAL or is simply absent, never a silent
// clamp. Dispatched by the service token `elasticache-serverless`; same Query
// protocol / endpoint / SigV4 service (`elasticache`, Version 2015-02-02) as the
// provisioned sibling. Same split as apprunner/ecs — a PURE builder pinned by
// golden tests, a thin httptest-covered net shell. Same rule: REFUSE what cannot
// be honored, never silently drop or clamp an attribute that satisfied a
// constraint.
//
// A serverless cache is VPC-only (no public endpoint), always encrypts at rest
// and always enforces TLS in transit, and is regional (multi-AZ) by
// construction — so publicExposure=true, encryption.*=false and a non-regional
// availability.class are honest refusals, and the always-on encryption is
// satisfied by construction (no field to set), exactly as App Runner's HTTPS.
package aws

import (
	"fmt"
	"strconv"
	"strings"
)

// ECacheServerlessPlan is the attribute-derived shape a create assembles into
// CreateServerlessCache Query params. No sizing fields exist — that is the point.
type ECacheServerlessPlan struct {
	Name               string
	Region             string
	Engine             string // redis | valkey
	MajorEngineVersion string // serverless uses the MAJOR version only ("7"), not the full EngineVersion
	KmsKeyID           string // CMEK; "" = provider-managed at-rest key
	SubnetIDs          []string
	SecurityGroupIDs   []string
}

// ecacheServerlessEngine maps engine.protocol (redis/N | valkey/N) to the
// serverless Engine + MajorEngineVersion. Serverless requires Redis >= 7 (the
// only engine ElastiCache Serverless launched with) or Valkey; memcached is a
// separate path not wired in this slice. Every mismatch is a preflight refusal.
func ecacheServerlessEngine(protocol string) (engine, major string, err error) {
	name, ver, ok := strings.Cut(protocol, "/")
	name = strings.ToLower(name)
	if !ok {
		return "", "", fmt.Errorf("engine.protocol %q is not an engine/N protocol (e.g. redis/7)", protocol)
	}
	majorOf := strings.SplitN(ver, ".", 2)[0]
	switch name {
	case "redis":
		// ElastiCache Serverless requires Redis OSS 7.1 or newer — an older major
		// has no serverless offering, so refuse rather than fake a 7 upgrade.
		if majorOf != "7" {
			return "", "", fmt.Errorf(
				"redis version %q has no ElastiCache Serverless mapping "+
					"(serverless requires Redis 7.1+; use engine.protocol redis/7)", ver)
		}
		return "redis", "7", nil
	case "valkey":
		switch majorOf {
		case "7", "8":
			return "valkey", majorOf, nil
		default:
			return "", "", fmt.Errorf("valkey version %q has no ElastiCache Serverless mapping (7 or 8)", ver)
		}
	case "memcached":
		return "", "", fmt.Errorf(
			"engine.protocol memcached is not wired in this ElastiCache Serverless slice " +
				"(the redis/valkey path carries the encryption + regional guarantees) — refusing")
	default:
		return "", "", fmt.Errorf("engine.protocol %q is not a redis/N or valkey/N protocol", protocol)
	}
}

// BuildElastiCacheServerlessCreate maps capability.cache.keyvalue attributes +
// impl to a serverless-cache plan. Every error is a preflight refusal apply
// surfaces before any mutation, never a silent drop.
func BuildElastiCacheServerlessCreate(account, environment, capability string,
	attrs, impl map[string]any, generation int) (ECacheServerlessPlan, error) {
	p := ECacheServerlessPlan{
		// the serverless cache name obeys the same constraints as a replication
		// group id (1-40, leading letter, no consecutive/trailing hyphens), so the
		// deterministic id generator (and its validator) is shared.
		Name: ecacheID(account, environment, capability, generation),
	}
	var atRestSeen bool
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "engine.protocol":
			proto, _ := raw.(string)
			engine, major, err := ecacheServerlessEngine(proto)
			if err != nil {
				return ECacheServerlessPlan{}, err
			}
			p.Engine, p.MajorEngineVersion = engine, major
		case "location.region":
			p.Region, _ = raw.(string)
		case "network.publicExposure":
			if raw == true {
				return ECacheServerlessPlan{}, fmt.Errorf(
					"network.publicExposure=true cannot be honored by ElastiCache Serverless " +
						"(a serverless cache is VPC-only, no public endpoint) — refusing")
			}
		case "encryption.atRest":
			atRestSeen = true
			if raw != true {
				return ECacheServerlessPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored — ElastiCache Serverless always " +
						"encrypts at rest (never silently ships an unencrypted cache)")
			}
		case "encryption.inTransit":
			// serverless ALWAYS enforces TLS in transit — =true is satisfied by
			// construction (no field to set), =false ("plaintext allowed") cannot be honored.
			if raw != true {
				return ECacheServerlessPlan{}, fmt.Errorf(
					"encryption.inTransit=false cannot be honored — ElastiCache Serverless is TLS-only in transit")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.KmsKeyID, _ = impl["kms_key_id"].(string)
				if p.KmsKeyID == "" {
					return ECacheServerlessPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_id (a customer key)")
				}
			}
		case "availability.class":
			switch raw {
			case "regional":
				// satisfied by construction — serverless spans multiple AZs.
			case "zonal":
				return ECacheServerlessPlan{}, fmt.Errorf(
					"availability.class=zonal cannot be honored by ElastiCache Serverless " +
						"(it is multi-AZ/regional by construction — no single-AZ mode)")
			case "multi-regional":
				return ECacheServerlessPlan{}, fmt.Errorf(
					"availability.class=multi-regional maps to a cross-region topology, " +
						"not a single serverless cache — refusing rather than faking it")
			default:
				return ECacheServerlessPlan{}, fmt.Errorf("availability.class %v has no ElastiCache Serverless mapping", raw)
			}
		case "service.managed":
			if raw != true {
				return ECacheServerlessPlan{}, fmt.Errorf("service.managed=false cannot be honored by ElastiCache Serverless")
			}
		default:
			return ECacheServerlessPlan{}, fmt.Errorf(
				"attribute %s has no ElastiCache Serverless mapping — refusing rather than silently dropping it "+
					"(serverless has no node type, memory or shard sizing to map it to)", path)
		}
	}
	if p.Engine == "" {
		return ECacheServerlessPlan{}, fmt.Errorf("cache requires engine.protocol (e.g. redis/7)")
	}
	if !atRestSeen {
		return ECacheServerlessPlan{}, fmt.Errorf("cache requires encryption.atRest=true")
	}
	if p.Region == "" {
		return ECacheServerlessPlan{}, fmt.Errorf("cache requires location.region")
	}
	if !regionOK.MatchString(p.Region) {
		return ECacheServerlessPlan{}, fmt.Errorf("location.region %q is not a valid AWS region", p.Region)
	}
	// Serverless takes SUBNET IDS directly (SubnetIds.member.N) — there is NO
	// cache subnet group to derive/own (the D278 provisioned concern). Both are
	// optional operands; without them serverless uses the account's default VPC
	// subnets, which do not exist on an account with no default VPC.
	p.SubnetIDs = implStrings(impl, "subnetIds")
	p.SecurityGroupIDs = implStrings(impl, "securityGroupIds")
	return p, nil
}

// createParams builds the CreateServerlessCache Query params (ownership tags at
// birth). No sizing params exist — capacity auto-scales.
func (p ECacheServerlessPlan) createParams(capability, environment string) map[string]string {
	form := map[string]string{
		"Action":              "CreateServerlessCache",
		"Version":             elastiCacheVersion,
		"ServerlessCacheName": p.Name,
		"Description":         "groundhold " + sanitizeTag(capability),
		"Engine":              p.Engine,
		"MajorEngineVersion":  p.MajorEngineVersion,
		"Tags.member.1.Key":   "groundhold-capability",
		"Tags.member.1.Value": sanitizeTag(capability),
		"Tags.member.2.Key":   "groundhold-environment",
		"Tags.member.2.Value": sanitizeTag(environment),
	}
	if p.KmsKeyID != "" {
		form["KmsKeyId"] = p.KmsKeyID
	}
	for i, id := range p.SubnetIDs {
		form["SubnetIds.member."+strconv.Itoa(i+1)] = id
	}
	for i, id := range p.SecurityGroupIDs {
		form["SecurityGroupIds.member."+strconv.Itoa(i+1)] = id
	}
	return form
}

// classifyElastiCacheServerlessChange (D46): PURE — can a cache.keyvalue
// transition be honored IN PLACE on a serverless cache? This slice wires
// create/observe/delete but NO in-place update, so every drift is either
// satisfied-by-construction (encryption/availability/publicExposure — refused at
// create, nothing to patch), a projection property, or a create-time property
// whose reconciliation is a REPLACEMENT (consent-gated: cache.keyvalue is
// stateful, D47/D48). Never a silent "mutable" that would route to an unwired
// UpdateService and stall.
func classifyElastiCacheServerlessChange(path string) (string, string) {
	switch path {
	case "location.region":
		return "immutable", "the region is the cache's home — a change is a new cache (replacement; stateful, consent-gated)"
	case "engine.protocol":
		return "immutable", "a serverless engine/version change is not wired in this slice — reconciling a drift is a replacement (stateful, consent-gated)"
	case "encryption.customerManagedKeys":
		return "immutable", "the KMS key is set at create — reconciling a drift is a replacement (stateful, consent-gated)"
	case "network.publicExposure":
		return "unsupported", "a serverless cache is VPC-only — publicExposure=true is refused at create, never patched"
	case "encryption.atRest", "encryption.inTransit":
		return "unsupported", "ElastiCache Serverless always encrypts at rest and in transit — nothing to patch"
	case "availability.class":
		return "unsupported", "a serverless cache is regional (multi-AZ) by construction — nothing to patch"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no ElastiCache Serverless in-place mapping for " + path
	}
}
