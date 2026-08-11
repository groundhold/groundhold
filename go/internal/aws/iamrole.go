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
// awsServicePrincipalOK bounds a service principal before it is interpolated into a
// trust policy document (D73 boundary, D740).
var awsServicePrincipalOK = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,62}\.amazonaws\.com$`)

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
	// The trust policy decides WHO may assume the role, which is the whole content of an
	// identity. A minimal same-account default lets one exist without granting anything
	// broad — but a default is only safe while the author who wanted something else can
	// tell they did not get it (D740).
	if raw, has := impl["assume_role_policy"]; has {
		s, ok := raw.(string)
		if !ok {
			// D740: this was `p.TrustPolicy, _ = impl[...].(string)`, so a policy written
			// as a YAML MAPPING — the natural shape, and legal everywhere else in
			// `implementation:` — vanished and the account-root default was written
			// instead. The author sees a role they thought they had scoped; the service
			// they scoped it to cannot assume it. Same class as D627 and D674: a field
			// the builder cannot read must never fall back to something weaker in
			// silence.
			return IAMRolePlan{}, fmt.Errorf(
				"implementation.assume_role_policy must be a JSON STRING, got %T — a "+
					"trust policy the builder cannot read must not fall back to the "+
					"same-account default, which trusts nothing this role was scoped for. "+
					"Use implementation.trust_service ONLY if the role's trust carries no "+
					"CONDITION — it writes a bare Service principal and nothing else. Any "+
					"aws:SourceAccount, ArnLike or similar guard belongs in "+
					"assume_role_policy, written from the role as it stands (D776)", raw)
		}
		p.TrustPolicy = s
	}
	// D740: the operand for the case that keeps recurring — a role an AWS SERVICE must
	// assume. Hand-written JSON is where this goes wrong: a field report created a
	// flow-log delivery role trusted only by the account root, so the flow log AWS
	// accepted delivered nothing (D727), and the create that now REFUSES such a role
	// would otherwise leave no way to build a correct one without writing the document
	// by hand. `trust_service: vpc-flow-logs.amazonaws.com` is that way.
	//
	// D776, from the field: it writes a BARE service principal and no condition, and it
	// read as one of two equivalent spellings. All six of the reporter's roles carried a
	// condition (aws:SourceAccount, one with ArnLike on the VPC), so declaring them with
	// trust_service would have recorded trust WEAKER than the trust that stands — and
	// with no `trust.principals` attribute to compare against, the divergence would
	// surface only at the next re-create, as a silent weakening. The two operands are
	// not equivalent: this one is the shortcut for an UNCONDITIONED role.
	if svc, has := impl["trust_service"]; has {
		if p.TrustPolicy != "" {
			return IAMRolePlan{}, fmt.Errorf(
				"implementation carries both assume_role_policy and trust_service — one " +
					"trust policy or the other, never both spellings of the same thing")
		}
		name, ok := svc.(string)
		if !ok || !awsServicePrincipalOK.MatchString(name) {
			return IAMRolePlan{}, fmt.Errorf(
				"implementation.trust_service %v is not an AWS service principal "+
					"(e.g. vpc-flow-logs.amazonaws.com)", svc)
		}
		p.TrustPolicy = fmt.Sprintf(
			`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":%q},"Action":"sts:AssumeRole"}]}`,
			name)
	}
	// D751, from the field: five roles on a live account trusted `<acct>:root` and
	// NOTHING else, so Lambda answered `The role defined for the function cannot be
	// assumed by Lambda` — and the roles were meanwhile ASSUMABLE by every principal in
	// the account that its identity policy lets call sts:AssumeRole. Both bad ends at
	// once: the service it was built for cannot take it, and principals it was not
	// built for can. `Principal: root` is not a narrower service role. It is a WIDER one.
	//
	// This silence was the last fallback of its kind in this builder. Twenty lines up,
	// an UNREADABLE trust policy already refuses, with the reason spelled out: "a field
	// the builder cannot read must never fall back to something weaker in silence". An
	// ABSENT one took the same fallback and said nothing. Missing and malformed are
	// different inputs, but they are the same ignorance, and they now get the same
	// answer.
	//
	// Nothing legitimate is lost. A role a HUMAN assumes still says so, in
	// assume_role_policy, where it is visible in the candidate and in review.
	if p.TrustPolicy == "" {
		return IAMRolePlan{}, fmt.Errorf(
			"a role needs a trust policy and this candidate declares none — set " +
				"implementation.trust_service (a bare service principal, e.g. " +
				"lambda.amazonaws.com, and NO condition) or implementation.assume_role_policy " +
				"(the full JSON document, which is what any CONDITION requires — an " +
				"aws:SourceAccount or ArnLike guard cannot be expressed by trust_service, " +
				"and adopting a conditioned role with it would record trust WEAKER than the " +
				"one that stands, undetectably). Defaulting to the account root would build " +
				"a role NO service can assume and EVERY principal in the account can, which " +
				"is wider than anything you would have written by hand")
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
