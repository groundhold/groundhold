// EKS provisioning (slice 2, D147): the PURE forward map of the AWS
// capability.cluster.kubernetes driver. BuildEKS turns capability attributes +
// operator operands (implementation: block, D26) into the two request bodies of
// the composite groundhold OWNS — the CLUSTER and ONE managed NODE GROUP. Everything
// else the cluster needs (the IAM roles, the subnets, the KMS key, the VPC) is an
// OPERAND: a separate capability supplied by the implementation block, never
// stood up here (the operand boundary, D26). This file is PURE: it validates the
// shape and REFUSES before any mutation — an unmapped capability attribute or a
// missing required operand is a preflight refusal, never a silent drop. The net
// shell (eks_net.go) drives the parsed plan through the EKS REST-JSON API.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// eksCompositeName is the deterministic cluster name (D29 — the pid is knowable
// before the response). Bounded to leave room for the "-ng" node-group suffix
// under the EKS 100-char name limit, so the delete path recovers the node-group
// name from the cluster name in the providerId alone. A replacement (generation
// >= 2) coexists with its predecessor via a distinct hash tail.
func eksCompositeName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(cfBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	tail := "-" + hex.EncodeToString(sum[:])[:8]
	const maxLen = 90 // leaves headroom for the "-ng" node-group suffix under 100
	if len(slug)+len(tail) > maxLen {
		slug = strings.TrimRight(slug[:maxLen-len(tail)], "-")
	}
	name := slug + tail
	// must begin with an alphanumeric (not a hyphen) per the EKS name grammar.
	if name == "" || name[0] == '-' {
		name = "a" + strings.TrimLeft(name, "-")
	}
	return name
}

// EKSPlan is the attribute+operand-derived shape a create assembles. The SHAPE
// (version, endpoint exposure, secrets encryption) is driven by CAPABILITY
// attributes; the placement operands (IAM roles, subnets, security groups, KMS
// key, node-group sizing) are OPERATOR input from the candidate implementation:
// block (D26) — separate capabilities, never provisioned by this driver.
type EKSPlan struct {
	Name          string // cluster name (deterministic, OR an explicit adopt name — see AdoptByName)
	NodeGroupName string // <Name>-ng — recoverable from the pid for teardown
	Version       string // cluster.version (capability, required)

	// AdoptByName is set when the candidate supplies implementation.clusterName: the
	// plan targets an EXISTING cluster by its real (custom) name instead of the
	// deterministic eks-prod-<hash>. D261: a brownfield cluster (eksctl/TF-named, e.g.
	// "acme") never matches the deterministic name, so without this the create path
	// describes a name that does not exist and stands up a DUPLICATE. When AdoptByName
	// is set, createEKS REFUSES to create if the named cluster is absent (never a
	// duplicate), and the create-only operands (role/subnets/nodeGroup) are optional.
	AdoptByName bool

	EndpointPublic  bool // network.apiExposure -> endpointPublicAccess
	EndpointPrivate bool // network.apiExposure -> endpointPrivateAccess
	EncryptSecrets  bool // encryption.secrets

	// --- operands (implementation: block) ---
	ClusterRoleArn   string   // required
	SubnetIds        []string // >=2, required
	SecurityGroupIds []string // optional
	KmsKeyArn        string   // required iff EncryptSecrets
	NodeRoleArn      string   // required
	InstanceTypes    []string // node group (required, >=1)
	MinSize          int      // node group scaling
	DesiredSize      int
	MaxSize          int
}

// BuildEKS maps capability.cluster.kubernetes attributes + implementation operands
// to a plan, or REFUSES. Every error is a preflight refusal (never a half-build):
// an unmapped attribute, or a missing/invalid required operand, is refused here,
// before the first EKS mutation (invariant #4, D26).
func BuildEKS(environment, capability string,
	attrs, impl map[string]any, generation int) (EKSPlan, error) {
	if generation < 1 {
		generation = 1
	}
	name := eksCompositeName(environment, capability, generation)
	adoptByName := false
	// D261: an explicit clusterName operand targets an EXISTING custom-named cluster
	// (mirror eks_addon.go's parent clusterName operand). Present -> adopt that name;
	// absent -> the deterministic greenfield name.
	if explicit := strings.TrimSpace(implString(impl, "clusterName")); explicit != "" {
		name = explicit
		adoptByName = true
	}
	p := EKSPlan{
		Name:            name,
		NodeGroupName:   name + "-ng",
		AdoptByName:     adoptByName,
		EndpointPublic:  true, // the AWS default; overridden by network.apiExposure
		EndpointPrivate: false,
	}
	if !eksNameOK.MatchString(p.Name) || !eksNameOK.MatchString(p.NodeGroupName) {
		return EKSPlan{}, fmt.Errorf("cluster/node-group name %q/%q is invalid", p.Name, p.NodeGroupName)
	}

	// --- CAPABILITY attributes drive the SHAPE (refuse any unmapped attribute) ---
	// a missing network.apiExposure keeps the AWS default (public).
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "cluster.version":
			v, ok := raw.(string)
			if !ok || strings.TrimSpace(v) == "" {
				return EKSPlan{}, fmt.Errorf("cluster.version must be a non-empty string (e.g. \"1.29\")")
			}
			p.Version = strings.TrimSpace(v)
		case "network.apiExposure":
			s, ok := raw.(string)
			if !ok {
				return EKSPlan{}, fmt.Errorf("network.apiExposure must be a string (public|private|mixed)")
			}
			switch s {
			case "public":
				p.EndpointPublic, p.EndpointPrivate = true, false
			case "private":
				p.EndpointPublic, p.EndpointPrivate = false, true
			case "mixed":
				p.EndpointPublic, p.EndpointPrivate = true, true
			default:
				return EKSPlan{}, fmt.Errorf("network.apiExposure %q is not one of public|private|mixed", s)
			}
		case "encryption.secrets":
			b, ok := raw.(bool)
			if !ok {
				return EKSPlan{}, fmt.Errorf("encryption.secrets must be a bool")
			}
			p.EncryptSecrets = b
		case "service.managed":
			if raw != true {
				return EKSPlan{}, fmt.Errorf("service.managed=false cannot be honored by EKS (an EKS cluster IS managed by construction)")
			}
		case "availability.class":
			// informational at the control plane — the real HA comes from the node
			// group's subnet AZ spread (an operand), not a cluster body field. Accept
			// the declared value but do not map it to a request field.
			if _, ok := raw.(string); !ok {
				return EKSPlan{}, fmt.Errorf("availability.class must be a string")
			}
		case "location.region":
			// location.region scopes the create (resolved by the dispatch, not here);
			// cost.monthly is a projection — neither is a build input.
		default:
			return EKSPlan{}, fmt.Errorf(
				"attribute %s has no EKS cluster mapping — refusing rather than silently dropping it "+
					"(the cluster.kubernetes vocab governs version + apiExposure + secrets encryption)", path)
		}
	}

	if p.Version == "" {
		return EKSPlan{}, fmt.Errorf("cluster.version is required — refusing to let AWS pick a default Kubernetes version")
	}

	// The create-only operands (cluster role, subnets, node group) build a NEW
	// cluster; when adopting an existing one by name they are unused, so they are
	// optional in that mode (a minimal adopt candidate: clusterName + version). A
	// greenfield create still requires them all.
	if p.AdoptByName {
		return p, nil
	}

	// --- OPERATOR operands supply the placement (implementation: block, D26) ---
	if p.ClusterRoleArn = strings.TrimSpace(implString(impl, "clusterRoleArn")); p.ClusterRoleArn == "" {
		return EKSPlan{}, fmt.Errorf("implementation.clusterRoleArn is required (the EKS cluster service role — a separate capability/operand)")
	}
	p.SubnetIds = implStrings(impl, "subnetIds")
	if len(p.SubnetIds) < 2 {
		return EKSPlan{}, fmt.Errorf(
			"implementation.subnetIds requires >=2 subnets in distinct availability zones — " +
				"refusing to build a single-AZ control plane")
	}
	p.SecurityGroupIds = implStrings(impl, "securityGroupIds")

	// KMS key is REQUIRED iff the contract asks for encryption.secrets — envelope
	// encryption of Kubernetes secrets cannot be enabled without a key. The ARN is a
	// REFERENCE (it names a key), never key material — safe to carry (D53).
	p.KmsKeyArn = strings.TrimSpace(implString(impl, "kmsKeyArn"))
	if p.EncryptSecrets && p.KmsKeyArn == "" {
		return EKSPlan{}, fmt.Errorf(
			"encryption.secrets=true requires implementation.kmsKeyArn (a KMS key ARN) for envelope " +
				"encryption of Kubernetes secrets — refusing to claim secrets encryption with no key")
	}
	if !p.EncryptSecrets && p.KmsKeyArn != "" {
		return EKSPlan{}, fmt.Errorf(
			"implementation.kmsKeyArn was given but encryption.secrets is not true — " +
				"a key only attaches to secrets encryption; refusing an ambiguous shape")
	}

	// --- node group operand (required) ---
	if p.NodeRoleArn = strings.TrimSpace(implString(impl, "nodeRoleArn")); p.NodeRoleArn == "" {
		return EKSPlan{}, fmt.Errorf("implementation.nodeRoleArn is required (the managed node group's instance role — a separate capability/operand)")
	}
	ng, ok := impl["nodeGroup"].(map[string]any)
	if !ok {
		return EKSPlan{}, fmt.Errorf("implementation.nodeGroup is required (the managed node group: instanceTypes, minSize, desiredSize, maxSize)")
	}
	p.InstanceTypes = implStrings(ng, "instanceTypes")
	if len(p.InstanceTypes) == 0 {
		return EKSPlan{}, fmt.Errorf("implementation.nodeGroup.instanceTypes requires >=1 instance type")
	}
	var okMin, okDes, okMax bool
	p.MinSize, okMin = implInt(ng, "minSize")
	p.DesiredSize, okDes = implInt(ng, "desiredSize")
	p.MaxSize, okMax = implInt(ng, "maxSize")
	if !okMin || !okDes || !okMax {
		return EKSPlan{}, fmt.Errorf("implementation.nodeGroup requires integer minSize, desiredSize and maxSize")
	}
	if p.MinSize < 0 || p.MaxSize < 1 || p.MinSize > p.MaxSize ||
		p.DesiredSize < p.MinSize || p.DesiredSize > p.MaxSize {
		return EKSPlan{}, fmt.Errorf(
			"implementation.nodeGroup sizing is inconsistent (need 0<=minSize<=desiredSize<=maxSize, maxSize>=1): min=%d desired=%d max=%d",
			p.MinSize, p.DesiredSize, p.MaxSize)
	}
	return p, nil
}

// createClusterBody is the CreateCluster request body: name, version, the cluster
// service role, the VPC config (subnets, security groups, endpoint exposure), the
// optional secrets encryptionConfig (only when asked), and ownership tags. Cited:
// EKS CreateCluster (REST-JSON).
func (p EKSPlan) createClusterBody(capability, environment string) []byte {
	vpc := map[string]any{
		"subnetIds":             p.SubnetIds,
		"endpointPublicAccess":  p.EndpointPublic,
		"endpointPrivateAccess": p.EndpointPrivate,
	}
	if len(p.SecurityGroupIds) > 0 {
		vpc["securityGroupIds"] = p.SecurityGroupIds
	}
	body := map[string]any{
		"name":               p.Name,
		"version":            p.Version,
		"roleArn":            p.ClusterRoleArn,
		"resourcesVpcConfig": vpc,
		"tags": map[string]any{
			"groundhold-capability":  sanitizeTag(capability),
			"groundhold-environment": sanitizeTag(environment),
		},
	}
	if p.EncryptSecrets {
		body["encryptionConfig"] = []any{
			map[string]any{
				"resources": []any{"secrets"},
				"provider":  map[string]any{"keyArn": p.KmsKeyArn},
			},
		}
	}
	return []byte(jsonBody(body))
}

// createNodegroupBody is the CreateNodegroup request body: the cluster + node-group
// names, the node instance role, the placement subnets, the scaling config, the
// instance types, and ownership tags. Cited: EKS CreateNodegroup (REST-JSON).
func (p EKSPlan) createNodegroupBody(capability, environment string) []byte {
	body := map[string]any{
		"clusterName":   p.Name,
		"nodegroupName": p.NodeGroupName,
		"nodeRole":      p.NodeRoleArn,
		"subnets":       p.SubnetIds,
		"scalingConfig": map[string]any{
			"minSize":     p.MinSize,
			"desiredSize": p.DesiredSize,
			"maxSize":     p.MaxSize,
		},
		"instanceTypes": p.InstanceTypes,
		"tags": map[string]any{
			"groundhold-capability":  sanitizeTag(capability),
			"groundhold-environment": sanitizeTag(environment),
		},
	}
	return []byte(jsonBody(body))
}

// implString reads a string operand (trimmed by the caller). A non-string or
// absent key yields "".
func implString(impl map[string]any, key string) string {
	if s, ok := impl[key].(string); ok {
		return s
	}
	return ""
}
