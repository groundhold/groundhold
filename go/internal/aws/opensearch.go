// OpenSearch request building (D113): the semantic core of the AWS
// capability.search.index driver — the SAME vocabulary Azure AI Search fulfils
// (GCP has no managed search twin, so the domain is honestly two-cloud). AWS
// OpenSearch Service is a managed regional search cluster. Node type, instance
// count, EBS size and shard/replica counts are implementation sizing; residency,
// exposure, availability and encryption are the capability. encryption.atRest and
// encryption.inTransit are true-only (a search cluster with neither is not a
// capability anyone should ask for, and matches the Azure twin's always-on shape).
package aws

import (
	"fmt"
	"regexp"
	"strings"
)

// osNameOK bounds an OpenSearch domain name (3-28: lowercase letter start, then
// lowercase letters, digits, hyphens).
var osNameOK = regexp.MustCompile(`^[a-z][a-z0-9-]{2,27}$`)

// OpenSearchDomainName is the deterministic domain name (the idempotency handle).
func OpenSearchDomainName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, slug)
	slug = strings.Trim(slug, "-")
	tail := "-" + letterHash(environment+"|"+capability+genSuffix(generation), 8)
	const maxLen = 28
	if len(slug)+len(tail) > maxLen {
		slug = strings.TrimRight(slug[:maxLen-len(tail)], "-")
	}
	name := slug + tail
	if name[0] < 'a' || name[0] > 'z' {
		name = "s" + strings.TrimLeft(name, "-")
	}
	return name
}

// OpenSearchPlan is the attribute-derived shape a create assembles.
type OpenSearchPlan struct {
	Domain         string
	EngineVersion  string
	InstanceCount  int
	ZoneAwareness  bool
	Public         bool
	SubnetIDs      []string
	SecurityGroups []string
	CMEK           bool
	KmsKeyId       string
}

// BuildOpenSearch maps capability.search.index attributes + impl to a plan. Every
// error is a preflight refusal, never a silent drop.
func BuildOpenSearch(environment, capability string,
	attrs, impl map[string]any, generation int) (OpenSearchPlan, error) {
	p := OpenSearchPlan{
		Domain:        OpenSearchDomainName(environment, capability, generation),
		EngineVersion: "OpenSearch_2.11",
		InstanceCount: 1,
	}
	inTransitSet := false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			// region is the driver scope (createScope); nothing in the body.
		case "availability.class":
			switch raw {
			case "zonal":
				p.ZoneAwareness = false
				p.InstanceCount = 1
			case "regional":
				p.ZoneAwareness = true
				p.InstanceCount = 2 // zone awareness needs an even count across AZs
			default:
				return OpenSearchPlan{}, fmt.Errorf("availability.class %v has no OpenSearch mapping", raw)
			}
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "encryption.atRest":
			if raw != true {
				return OpenSearchPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored — a managed search index is encrypted at rest")
			}
		case "encryption.inTransit":
			inTransitSet = true
			if raw != true {
				return OpenSearchPlan{}, fmt.Errorf(
					"encryption.inTransit=false cannot be honored — TLS is enforced (HTTPS-only)")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.CMEK = true
				p.KmsKeyId, _ = impl["kms_key_id"].(string)
				if p.KmsKeyId == "" {
					return OpenSearchPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_id")
				}
			}
		case "service.managed":
			if raw != true {
				return OpenSearchPlan{}, fmt.Errorf("service.managed=false cannot be honored by OpenSearch")
			}
		default:
			return OpenSearchPlan{}, fmt.Errorf(
				"attribute %s has no OpenSearch mapping — refusing rather than silently dropping it "+
					"(instance type/count, EBS, shard/replica counts are implementation sizing)", path)
		}
	}
	_ = inTransitSet
	if ev, ok := impl["engine_version"].(string); ok && ev != "" {
		p.EngineVersion = ev
	}
	if n, ok, err := implIntOperand(impl, "instance_count", "implementation"); err != nil {
		return OpenSearchPlan{}, err
	} else if ok {
		p.InstanceCount = n
	}
	// a private domain is placed in a VPC — subnets/security groups are topology.
	if !p.Public {
		p.SubnetIDs = implStrings(impl, "subnet_ids")
		p.SecurityGroups = implStrings(impl, "security_group_ids")
		if len(p.SubnetIDs) == 0 || len(p.SecurityGroups) == 0 {
			return OpenSearchPlan{}, fmt.Errorf(
				"a PRIVATE search domain (network.publicExposure=false) requires implementation." +
					"subnet_ids AND implementation.security_group_ids (VPC placement is topology)")
		}
	}
	if !osNameOK.MatchString(p.Domain) {
		return OpenSearchPlan{}, fmt.Errorf("derived domain name %q is invalid", p.Domain)
	}
	return p, nil
}

// implInt reads a whole-number operand. D674: it returned (0, false) for a value
// that is PRESENT and unreadable, exactly as for one that is absent — so a caller
// with a default silently used the default. Measured on the load balancer, whose
// operands decide the public front door:
//
//	operand port=8443    -> listener Port=8443  TargetPort=8080
//	operand port="8443"  -> listener Port=80    TargetPort=8080
//
// and the two candidates HASH IDENTICALLY, because the canonical form renders every
// number as a string (NUMSTR). One sealed identity, two different front doors, and
// preflight said `{"ready": true}` for both.
//
// `present` now distinguishes the two, so a caller can default on absence and
// refuse on an unreadable value. The old two-value signature is kept for the sites
// that already refuse when the operand is missing.
func implIntPresent(impl map[string]any, key string) (val int, ok bool, present bool) {
	raw, present := impl[key]
	if !present || raw == nil {
		return 0, false, false
	}
	switch v := raw.(type) {
	case float64:
		// D695: `int(v)` alone truncated. `period_seconds: 60.5` became 60 and passed
		// a "must be a multiple of 60" check the author's own value fails — the D674
		// shape exactly: a value the loader could not honestly read, silently built
		// as a different one. A fractional operand is unreadable, not rounded.
		if v != float64(int64(v)) {
			return 0, false, true
		}
		return int(v), true, true
	case int:
		return v, true, true
	case int64:
		// yaml.v3 hands back int64 once a literal exceeds int's range on the platform;
		// without this arm such an operand read as unreadable and refused by name.
		return int(v), true, true
	}
	return 0, false, true
}

// implIntOperand is the reading a caller with a DEFAULT must use: an absent operand
// leaves the default alone, a present-but-unreadable one refuses by name.
func implIntOperand(impl map[string]any, key, where string) (int, bool, error) {
	v, ok, present := implIntPresent(impl, key)
	if !present {
		return 0, false, nil
	}
	if !ok {
		return 0, false, fmt.Errorf(
			"%s.%s must be a whole number, got %T (%v) — refusing rather than "+
				"falling back to a default, which would build a different resource "+
				"than the candidate declares (D674)", where, key, impl[key], impl[key])
	}
	return v, true, nil
}

func implInt(impl map[string]any, key string) (int, bool) {
	v, ok, _ := implIntPresent(impl, key)
	return v, ok
}

func implStrings(impl map[string]any, key string) []string {
	raw, ok := impl[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		if s, ok := r.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// createBody is the CreateDomain request body. Ownership is tags.
func (p OpenSearchPlan) createBody(region, account, capability, environment string) map[string]any {
	body := map[string]any{
		"DomainName":    p.Domain,
		"EngineVersion": p.EngineVersion,
		"ClusterConfig": map[string]any{
			"InstanceType":         "t3.small.search",
			"InstanceCount":        p.InstanceCount,
			"ZoneAwarenessEnabled": p.ZoneAwareness,
		},
		"EBSOptions":                  map[string]any{"EBSEnabled": true, "VolumeSize": 10, "VolumeType": "gp3"},
		"EncryptionAtRestOptions":     map[string]any{"Enabled": true},
		"NodeToNodeEncryptionOptions": map[string]any{"Enabled": true},
		"DomainEndpointOptions":       map[string]any{"EnforceHTTPS": true, "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07"},
		"TagList": []any{
			map[string]any{"Key": "groundhold-capability", "Value": sanitizeTag(capability)},
			map[string]any{"Key": "groundhold-environment", "Value": sanitizeTag(environment)},
		},
	}
	if p.CMEK {
		body["EncryptionAtRestOptions"] = map[string]any{"Enabled": true, "KmsKeyId": p.KmsKeyId}
	}
	if p.Public {
		// an account-scoped access policy (never anonymous *): the domain endpoint
		// is public, but access is IAM-gated to the owning account.
		body["AccessPolicies"] = fmt.Sprintf(
			`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"es:*","Resource":"arn:aws:es:%s:%s:domain/%s/*"}]}`,
			account, region, account, p.Domain)
	} else {
		subnets := make([]any, len(p.SubnetIDs))
		for i, s := range p.SubnetIDs {
			subnets[i] = s
		}
		sgs := make([]any, len(p.SecurityGroups))
		for i, s := range p.SecurityGroups {
			sgs[i] = s
		}
		body["VPCOptions"] = map[string]any{"SubnetIds": subnets, "SecurityGroupIds": sgs}
	}
	return body
}
