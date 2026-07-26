// Redshift Serverless request building (D122): the semantic core of the AWS
// capability.warehouse.analytics driver. A serverless warehouse is a COMPOSITE of two
// resources under ONE binding: a NAMESPACE (holds the databases/tables — the stateful
// data unit, carries the CMK) and a WORKGROUP (the compute endpoint — carries
// publiclyAccessible). Both share one deterministic base name so the pid is a single
// handle. D53: no admin username/password is ever set (the namespace is created for
// IAM auth); a warehouse credential is a secret groundhold must never manage. Node
// sizing (baseCapacity RPUs), subnets and security groups are opaque impl (invariant
// #4). The admin credential, snapshot schedule and query config are out of scope.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// rssNameOK bounds a namespace/workgroup name: 3-64, lowercase letters, digits, and
// hyphens (the shared subset Redshift Serverless accepts for both).
var rssNameOK = regexp.MustCompile(`^[a-z0-9-]{3,64}$`)
var rssBad = regexp.MustCompile(`[^a-z0-9-]+`)

// RSSName is the deterministic base name shared by the namespace and workgroup (the
// idempotency/recovery handle). generation >= 2 salts a replacement (D48).
func RSSName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(rssBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	tail := "-" + hex.EncodeToString(sum[:])[:8]
	const maxLen = 64
	if len(slug)+len(tail) > maxLen {
		slug = strings.TrimRight(slug[:maxLen-len(tail)], "-")
	}
	name := slug + tail
	if name == "" || !(name[0] >= 'a' && name[0] <= 'z') {
		name = "w" + strings.TrimLeft(name, "-")
	}
	return name
}

// RSSPlan is the attribute-derived shape a create assembles.
type RSSPlan struct {
	Name     string
	Region   string
	Public   bool
	KmsKeyID string // "" = AWS-managed default; else a customer key (CMK)
}

// BuildRedshiftServerless maps capability.warehouse.analytics attributes + impl to a
// plan. Every error is a preflight refusal, never a silent drop.
func BuildRedshiftServerless(environment, capability string,
	attrs, impl map[string]any, generation int) (RSSPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := RSSPlan{Name: RSSName(environment, capability, generation)}
	cmk := false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "encryption.atRest":
			if raw == false {
				return RSSPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored — Redshift Serverless always encrypts at rest")
			}
		case "encryption.customerManagedKeys":
			cmk = (raw == true)
		case "service.managed":
			if raw != true {
				return RSSPlan{}, fmt.Errorf("service.managed=false cannot be honored by Redshift Serverless")
			}
		default:
			return RSSPlan{}, fmt.Errorf(
				"attribute %s has no Redshift Serverless mapping — refusing rather than silently "+
					"dropping it (schemas, base capacity, subnets are opaque impl)", path)
		}
	}
	if !regionOK.MatchString(p.Region) {
		return RSSPlan{}, fmt.Errorf("capability.warehouse.analytics requires a valid location.region")
	}
	if cmk {
		key, _ := impl["kms_key_id"].(string)
		if key == "" {
			return RSSPlan{}, fmt.Errorf(
				"encryption.customerManagedKeys=true requires implementation.kms_key_id " +
					"(the customer key id is implementation detail, never a capability path)")
		}
		p.KmsKeyID = key
	}
	if !rssNameOK.MatchString(p.Name) {
		return RSSPlan{}, fmt.Errorf("derived name %q is invalid", p.Name)
	}
	return p, nil
}

// namespaceBody / workgroupBody are the JSON-protocol create bodies. Ownership is
// tags applied at birth. NO admin credentials (D53 — the namespace uses IAM auth).
func (p RSSPlan) namespaceBody(capability, environment string) map[string]any {
	body := map[string]any{
		"namespaceName": p.Name,
		"tags":          rssTags(capability, environment),
	}
	if p.KmsKeyID != "" {
		body["kmsKeyId"] = p.KmsKeyID
	}
	return body
}

func (p RSSPlan) workgroupBody(capability, environment string) map[string]any {
	return map[string]any{
		"workgroupName":      p.Name,
		"namespaceName":      p.Name,
		"publiclyAccessible": p.Public,
		"tags":               rssTags(capability, environment),
	}
}

func rssTags(capability, environment string) []map[string]string {
	return []map[string]string{
		{"key": "groundhold-capability", "value": sanitizeTag(capability)},
		{"key": "groundhold-environment", "value": sanitizeTag(environment)},
	}
}
