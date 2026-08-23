// AWS customer-managed policy request building (D105): the semantic core of the AWS
// capability.authorization.role driver — the SAME vocabulary GCP custom roles and
// Azure custom roleDefinitions fulfil. On AWS a custom role is a customer-managed
// policy, and this is where invariant #4 bites hardest: a policy IS a document. The
// resolution is to admit ONLY the flat set — the driver assembles the TRIVIAL single
// Allow statement (Action = the permission set, Resource "*", no Condition), and
// refuses everything that would reintroduce the expression language. access.mutating
// / access.privileged are DERIVED from the action verbs.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// awsActionOK bounds an IAM action string (service:Verb, service:* or a lone *).
var awsActionOK = regexp.MustCompile(`^([A-Za-z0-9]+:[A-Za-z0-9*]+|\*)$`)

// awsPolicyNameOK bounds a policy name.
var awsPolicyNameOK = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{1,128}$`)

// CustomPolicyPlan is the attribute-derived shape a create assembles.
type CustomPolicyPlan struct {
	PolicyName  string
	Permissions []string
	Document    string // the assembled single-Allow policy document JSON
}

func awsPolicyName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(iamRoleBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	tail := "-" + hex.EncodeToString(sum[:])[:8]
	const maxLen = 128
	if len(slug)+len(tail) > maxLen {
		slug = strings.TrimRight(slug[:maxLen-len(tail)], "-")
	}
	name := "pv-" + slug + tail
	return name
}

// iamRoleBad collapses everything outside the generated policy-name charset.
var iamRoleBad = regexp.MustCompile(`[^a-z0-9-]+`)

// BuildCustomPolicy maps capability.authorization.role attributes to a policy plan.
// Every error is a preflight refusal, never a silent drop.
func BuildCustomPolicy(environment, capability string,
	attrs, impl map[string]any, generation int) (CustomPolicyPlan, error) {
	p := CustomPolicyPlan{PolicyName: awsPolicyName(environment, capability, generation)}
	declaredMut, mutSet := false, false
	declaredPriv, privSet := false, false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "role.permissions":
			perms, err := toStringListAWS(raw)
			if err != nil {
				return CustomPolicyPlan{}, fmt.Errorf("role.permissions is not a list of strings: %v", err)
			}
			for _, a := range perms {
				if !awsActionOK.MatchString(a) {
					return CustomPolicyPlan{}, fmt.Errorf("action %q is not a valid IAM action (service:Verb)", a)
				}
			}
			p.Permissions = perms
		case "access.mutating":
			declaredMut, _ = raw.(bool)
			mutSet = true
		case "access.privileged":
			declaredPriv, _ = raw.(bool)
			privSet = true
		case "service.managed":
			if raw != true {
				return CustomPolicyPlan{}, fmt.Errorf("service.managed=false cannot be honored by IAM")
			}
		default:
			return CustomPolicyPlan{}, fmt.Errorf(
				"attribute %s has no custom-policy mapping — refusing rather than silently dropping it "+
					"(a role is a flat action SET; resources/conditions/effects are the expression language, refused)", path)
		}
	}
	if len(p.Permissions) == 0 {
		return CustomPolicyPlan{}, fmt.Errorf("a custom role requires a non-empty role.permissions set")
	}
	if mutSet && awsPolicyMutating(p.Permissions) != declaredMut {
		return CustomPolicyPlan{}, fmt.Errorf(
			"access.mutating=%t contradicts the action set — refusing a false claim", declaredMut)
	}
	if privSet && awsPolicyPrivileged(p.Permissions) != declaredPriv {
		return CustomPolicyPlan{}, fmt.Errorf(
			"access.privileged=%t contradicts the action set — refusing a false claim", declaredPriv)
	}
	if !awsPolicyNameOK.MatchString(p.PolicyName) {
		return CustomPolicyPlan{}, fmt.Errorf("derived policy name %q is invalid", p.PolicyName)
	}
	// assemble the trivial single-Allow document (Resource "*", no Condition).
	doc, _ := json.Marshal(map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{map[string]any{
			"Effect":   "Allow",
			"Action":   p.Permissions,
			"Resource": "*",
		}},
	})
	p.Document = string(doc)
	return p, nil
}

func awsActionMutating(a string) bool {
	if a == "*" {
		return true
	}
	verb := a
	if i := strings.IndexByte(a, ':'); i >= 0 {
		verb = a[i+1:]
	}
	if verb == "*" {
		return true // service:* includes writes
	}
	return !(strings.HasPrefix(verb, "Get") || strings.HasPrefix(verb, "List") || strings.HasPrefix(verb, "Describe"))
}

func awsPolicyMutating(perms []string) bool {
	for _, a := range perms {
		if awsActionMutating(a) {
			return true
		}
	}
	return false
}

// awsStsMints are the STS actions that hand out CREDENTIALS. Everything else STS
// offers is inert — `sts:GetCallerIdentity` is the most harmless call in AWS and is
// in almost every read-only policy.
//
// D1231 sub-finding: this function fired on `svc == "sts"` WHOLESALE, while the
// published mapping in capability.authorization.role.yaml says "any iam:* /
// sts:AssumeRole". Code broader than the published claim, and broader in a way that
// matters now: with D1231 the classifier decides a MEASURED emission for arbitrary
// customer policies, so a clone of ReadOnlyAccess or SecurityAudit — both of which
// carry sts:GetCallerIdentity — would have measured privileged=true. A false alarm
// at estate scale erodes the alarm, and on the role path (which emits `false` too) it
// also refused a candidate's true least-privilege claim.
//
// Narrowed to the credential-minting verbs, which is WIDER than the vocab's literal
// "sts:AssumeRole" — AssumeRoleWithSAML/WithWebIdentity and the token-getters mint
// credentials just as surely — so the vocabulary moves to meet it rather than the
// code shrinking to a claim that was itself too narrow.
var awsStsMints = map[string]bool{
	"AssumeRole": true, "AssumeRoleWithSAML": true, "AssumeRoleWithWebIdentity": true,
	"GetFederationToken": true, "GetSessionToken": true,
}

func awsActionPrivileged(a string) bool {
	if a == "*" {
		return true
	}
	svc, verb := a, ""
	if i := strings.IndexByte(a, ':'); i >= 0 {
		svc, verb = a[:i], a[i+1:]
	}
	if verb == "*" {
		return true
	}
	if svc == "iam" {
		// The vocabulary defines privilege as "the power to GRANT FURTHER ACCESS".
		// Reading IAM is not that: iam:GetRole / iam:ListPolicies / iam:SimulatePolicy
		// are reconnaissance, and they are in every read-only baseline. The mapping's
		// shorthand ("any iam:*") over-reached its own definition; the definition wins
		// and the mapping is corrected to match (D1231).
		return !awsReadVerb(verb)
	}
	return svc == "sts" && awsStsMints[verb]
}

// awsReadVerb reports whether an IAM action verb only READS. AWS's own naming
// convention carries this: Get*, List* and Simulate* are the read surface, and
// everything else in the iam namespace writes or mints. Inverting (exempt the reads)
// rather than enumerating the writes is deliberate — a NEW iam write verb is then
// privileged by default, which is the safe direction for a security-floored attribute.
func awsReadVerb(verb string) bool {
	return strings.HasPrefix(verb, "Get") ||
		strings.HasPrefix(verb, "List") ||
		strings.HasPrefix(verb, "Simulate")
}

func awsPolicyPrivileged(perms []string) bool {
	for _, a := range perms {
		if awsActionPrivileged(a) {
			return true
		}
	}
	return false
}

func toStringListAWS(raw any) ([]string, error) {
	if ss, ok := raw.([]string); ok {
		return ss, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("not a list")
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := it.(string)
		if !ok {
			return nil, fmt.Errorf("element %v is not a string", it)
		}
		out = append(out, s)
	}
	return out, nil
}
