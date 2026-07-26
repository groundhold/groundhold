// IAM role request building (D121): the semantic core of the AWS
// capability.identity.serviceaccount driver — the SAME vocabulary GCP service
// accounts and Azure managed identities fulfil. An IAM role is a keyless machine
// identity a workload assumes (no downloadable key exists — an assumed role issues
// short-lived credentials). D53: key.exportable=true is refused. IAM is a GLOBAL
// service (signed us-east-1). The role's granted permissions (attached policies) and
// its trust policy are opaque config, out of this identity capability's scope.
package aws

import (
	"fmt"
	"regexp"
	"strings"
)

// iamRoleNameOK bounds an IAM role name (1-64: letters, digits, and +=,.@_- ).
var iamRoleNameOK = regexp.MustCompile(`^[a-zA-Z0-9+=,.@_-]{1,64}$`)

// IAMRoleName is the deterministic role name (the idempotency/recovery handle).
func IAMRoleName(environment, capability string, generation int) string {
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
	return "pv-" + slug + "-" + letterHash(environment+"|"+capability+genSuffix(generation), 8)
}

// IAMRolePlan is the attribute-derived shape a create assembles.
type IAMRolePlan struct {
	RoleName    string
	Description string
	TrustPolicy string // opaque impl; a minimal same-account default when absent
}

// BuildIAMRole maps capability.identity.serviceaccount attributes + impl to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildIAMRole(account, environment, capability string,
	attrs, impl map[string]any, generation int) (IAMRolePlan, error) {
	p := IAMRolePlan{RoleName: IAMRoleName(environment, capability, generation)}
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "display.name":
			p.Description, _ = raw.(string)
		case "key.exportable":
			if raw == true {
				return IAMRolePlan{}, fmt.Errorf(
					"key.exportable=true cannot be honored — an IAM role is keyless (it issues " +
						"short-lived assumed credentials); groundhold never manages a downloadable key (D53)")
			}
		case "service.managed":
			if raw != true {
				return IAMRolePlan{}, fmt.Errorf("service.managed=false cannot be honored by an IAM role")
			}
		default:
			return IAMRolePlan{}, fmt.Errorf(
				"attribute %s has no IAM role mapping — refusing rather than silently dropping it "+
					"(trust policy, attached policies are opaque authorization config, out of scope)", path)
		}
	}
	// the trust policy (who may assume the role) is opaque config; a minimal
	// same-account default lets the identity exist without granting anything broad.
	p.TrustPolicy, _ = impl["assume_role_policy"].(string)
	if p.TrustPolicy == "" {
		p.TrustPolicy = fmt.Sprintf(
			`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sts:AssumeRole"}]}`,
			account)
	}
	// an EXPLICIT role name (D277, the D261 adopt-by-name twin): a service role
	// other things reference by name (an EKS cluster role, a grant's principal)
	// should not be forced through the deterministic hash — and the ownership-tag
	// gate on the EntityAlreadyExists branch still refuses a foreign same-named
	// role, so an explicit name can bind ours, never take over someone else's.
	if given, ok := impl["roleName"]; ok {
		name, isStr := given.(string)
		if !isStr || !iamRoleNameOK.MatchString(name) {
			return IAMRolePlan{}, fmt.Errorf(
				"implementation.roleName %v is not a valid IAM role name", given)
		}
		p.RoleName = name
	}
	if !iamRoleNameOK.MatchString(p.RoleName) {
		return IAMRolePlan{}, fmt.Errorf("derived role name %q is invalid", p.RoleName)
	}
	return p, nil
}

// createParams is the CreateRole Query-protocol parameter map. Ownership is tags.
func (p IAMRolePlan) createParams(capability, environment string) map[string]string {
	desc := p.Description
	if desc == "" {
		desc = "groundhold-managed identity"
	}
	return map[string]string{
		"Action":                   "CreateRole",
		"Version":                  iamVersion,
		"RoleName":                 p.RoleName,
		"AssumeRolePolicyDocument": p.TrustPolicy,
		"Description":              desc,
		"Tags.member.1.Key":        "groundhold-capability",
		"Tags.member.1.Value":      sanitizeTag(capability),
		"Tags.member.2.Key":        "groundhold-environment",
		"Tags.member.2.Value":      sanitizeTag(environment),
	}
}
