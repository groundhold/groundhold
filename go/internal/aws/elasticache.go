// ElastiCache request building (D100): the semantic core of the AWS
// capability.cache.keyvalue driver — the SAME vocabulary GCP Memorystore and
// Azure Cache for Redis fulfil. The bound resource is a Redis REPLICATION GROUP
// (the primitive that carries encryption + automatic failover; a bare cache
// cluster is the legacy single-node path). AWS Query protocol, async — the shell
// polls DescribeReplicationGroups to "available". Like Memorystore, ElastiCache is
// VPC-only (no public endpoint), so network.publicExposure=true is an honest
// refusal. memcached is a separate cache-cluster path, not wired in this slice.
package aws

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const elastiCacheVersion = "2015-02-02"

// ecacheIDOK bounds a replication group id before param/ARN interpolation:
// ElastiCache allows 1-40, start with a letter, alphanumeric + hyphen, no
// consecutive or trailing hyphens.
var ecacheIDOK = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)

// ECachePlan is the attribute-derived shape a create assembles into Query params.
type ECachePlan struct {
	ID            string
	Region        string
	EngineVersion string
	AtRest        bool
	Transit       bool
	KmsKeyID      string // CMEK (requires at-rest); "" = provider-managed
	MultiAZ       bool   // regional HA (automatic failover + a replica)
	NodeType      string // sizing (impl), default cache.t3.micro
	SubnetGroup   string // impl; "" = account default

	// DeriveSubnetGroup + SubnetIDs (D278): subnet ids given (typically
	// {$ref: vpc.privateSubnetIds}) instead of a pre-created cache subnet
	// group — the driver derives and OWNS the group as a sub-resource.
	DeriveSubnetGroup string
	SubnetIDs         []string
}

// ecacheID is the deterministic replication group id (idempotency key).
func ecacheID(account, environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	var b strings.Builder
	prevHyphen := false
	for _, r := range strings.ToLower(slug) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			prevHyphen = false
		} else if !prevHyphen {
			b.WriteByte('-')
			prevHyphen = true
		}
	}
	slug = strings.Trim(b.String(), "-")
	tail := "-" + letterHash(account+"|"+environment+"|"+capability+genSuffix(generation), 8)
	const maxLen = 40
	if len(slug)+len(tail) > maxLen {
		slug = slug[:maxLen-len(tail)]
		slug = strings.TrimRight(slug, "-")
	}
	name := slug + tail
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		name = "c" + strings.TrimLeft(name, "-")
	}
	return name
}

func ecacheEngineVersion(protocol string) (string, error) {
	engine, ver, ok := strings.Cut(protocol, "/")
	if !ok || strings.ToLower(engine) != "redis" {
		if strings.ToLower(engine) == "memcached" {
			return "", fmt.Errorf(
				"engine.protocol memcached is not wired in this ElastiCache slice " +
					"(Memcached uses the separate cache-cluster path, no encryption/failover) — refusing")
		}
		return "", fmt.Errorf("engine.protocol %q is not a redis/N protocol", protocol)
	}
	switch strings.SplitN(ver, ".", 2)[0] {
	case "7":
		return "7.0", nil
	case "6":
		return "6.2", nil
	case "5":
		return "5.0.6", nil
	default:
		return "", fmt.Errorf("redis version %q has no ElastiCache mapping", ver)
	}
}

// BuildElastiCacheCreate maps capability.cache.keyvalue attributes + impl to a
// replication-group plan. Every error is a preflight refusal, never a silent drop.
func BuildElastiCacheCreate(account, environment, capability string,
	attrs, impl map[string]any, generation int) (ECachePlan, error) {
	p := ECachePlan{
		ID:       ecacheID(account, environment, capability, generation),
		NodeType: "cache.t3.micro",
	}
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "engine.protocol":
			proto, _ := raw.(string)
			v, err := ecacheEngineVersion(proto)
			if err != nil {
				return ECachePlan{}, err
			}
			p.EngineVersion = v
		case "location.region":
			p.Region, _ = raw.(string)
		case "network.publicExposure":
			if raw == true {
				return ECachePlan{}, fmt.Errorf(
					"network.publicExposure=true cannot be honored by ElastiCache " +
						"(a replication group is VPC-only, no public endpoint) — refusing")
			}
		case "encryption.atRest":
			p.AtRest, _ = raw.(bool)
			if raw != true {
				return ECachePlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored — this driver always enables " +
						"at-rest encryption (never silently ships an unencrypted cache)")
			}
		case "encryption.inTransit":
			p.Transit, _ = raw.(bool)
		case "encryption.customerManagedKeys":
			if raw == true {
				p.KmsKeyID, _ = impl["kms_key_id"].(string)
				if p.KmsKeyID == "" {
					return ECachePlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_id (a customer key)")
				}
			}
		case "availability.class":
			switch raw {
			case "zonal":
				p.MultiAZ = false
			case "regional":
				p.MultiAZ = true
			case "multi-regional":
				return ECachePlan{}, fmt.Errorf(
					"availability.class=multi-regional maps to ElastiCache Global Datastore " +
						"(cross-region topology), not a single replication group — refusing rather than faking it")
			default:
				return ECachePlan{}, fmt.Errorf("availability.class %v has no ElastiCache mapping", raw)
			}
		case "service.managed":
			if raw != true {
				return ECachePlan{}, fmt.Errorf("service.managed=false cannot be honored by ElastiCache")
			}
		default:
			return ECachePlan{}, fmt.Errorf(
				"attribute %s has no ElastiCache mapping — refusing rather than silently dropping it "+
					"(node type, memory, shards are implementation sizing)", path)
		}
	}
	if p.EngineVersion == "" {
		return ECachePlan{}, fmt.Errorf("cache requires engine.protocol (e.g. redis/7)")
	}
	if !p.AtRest {
		return ECachePlan{}, fmt.Errorf("cache requires encryption.atRest=true")
	}
	if p.Region == "" {
		return ECachePlan{}, fmt.Errorf("cache requires location.region")
	}
	if !regionOK.MatchString(p.Region) {
		return ECachePlan{}, fmt.Errorf("location.region %q is not a valid AWS region", p.Region)
	}
	if nt, ok := impl["node_type"].(string); ok && nt != "" {
		p.NodeType = nt
	}
	// F26: accept the SAME key Aurora uses (implementation.subnetGroupName) so an
	// operator does not have to learn a second name for the same concept; keep the
	// old cache_subnet_group as a back-compat fallback. Without a subnet group,
	// ElastiCache falls back to the account's default subnets, which do not exist on
	// accounts with no default VPC — surfacing as a mid-flight "account does not have
	// any default subnets" 400.
	p.SubnetGroup, _ = impl["subnetGroupName"].(string)
	if p.SubnetGroup == "" {
		p.SubnetGroup, _ = impl["cache_subnet_group"].(string)
	}
	// D278: subnet ids as the placement operand (typically {$ref:
	// vpc.privateSubnetIds}) — the driver derives and owns the cache subnet
	// group. One source of truth with subnetGroupName, never two.
	if ids := implStrings(impl, "subnetIds"); len(ids) > 0 {
		if p.SubnetGroup != "" {
			return ECachePlan{}, fmt.Errorf(
				"implementation.subnetGroupName and implementation.subnetIds are both set — one source of truth, refusing")
		}
		p.DeriveSubnetGroup = derivedSubnetGroupName(environment, capability)
		p.SubnetIDs = ids
		p.SubnetGroup = p.DeriveSubnetGroup
	}
	return p, nil
}

// createParams builds the CreateReplicationGroup Query params (ownership tags at
// birth). transit/at-rest/CMEK and automatic failover ride inline.
func (p ECachePlan) createParams(capability, environment string) map[string]string {
	form := map[string]string{
		"Action":                      "CreateReplicationGroup",
		"Version":                     elastiCacheVersion,
		"ReplicationGroupId":          p.ID,
		"ReplicationGroupDescription": "groundhold " + sanitizeTag(capability),
		"Engine":                      "redis",
		"EngineVersion":               p.EngineVersion,
		"CacheNodeType":               p.NodeType,
		"AtRestEncryptionEnabled":     strconv.FormatBool(p.AtRest),
		"TransitEncryptionEnabled":    strconv.FormatBool(p.Transit),
		"Tags.member.1.Key":           "groundhold-capability",
		"Tags.member.1.Value":         sanitizeTag(capability),
		"Tags.member.2.Key":           "groundhold-environment",
		"Tags.member.2.Value":         sanitizeTag(environment),
	}
	if p.MultiAZ {
		form["MultiAZEnabled"] = "true"
		form["AutomaticFailoverEnabled"] = "true"
		form["ReplicasPerNodeGroup"] = "1"
		form["NumNodeGroups"] = "1"
	} else {
		form["AutomaticFailoverEnabled"] = "false"
		form["NumCacheClusters"] = "1"
	}
	if p.KmsKeyID != "" {
		form["KmsKeyId"] = p.KmsKeyID
	}
	if p.SubnetGroup != "" {
		form["CacheSubnetGroupName"] = p.SubnetGroup
	}
	return form
}
