// GCP service account request building (D121): the semantic core of the GCP
// capability.identity.serviceaccount driver — the SAME vocabulary AWS IAM roles and
// Azure managed identities fulfil. A service account is a keyless machine identity
// (workload identity). D53: key.exportable=true is refused — groundhold never creates a
// downloadable private key (a secret). Service accounts carry NO labels, so ownership
// is a DESCRIPTION MARKER (the VPC/tagless discipline). The trust policy / granted
// roles are opaque config, out of this identity capability's scope (authorization).
package gcp

import (
	"fmt"
	"regexp"
	"strings"
)

// gsaAccountIDOK bounds a service-account id: 6-30 chars, lowercase letter start,
// then lowercase letters/digits/hyphens.
var gsaAccountIDOK = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

// GServiceAccountID is the deterministic account id (the idempotency handle).
func GServiceAccountID(project, environment, capability string, generation int) string {
	return resourceName(project, environment, capability, generation, 30)
}

// GServiceAccountPlan is the attribute-derived shape a create assembles.
type GServiceAccountPlan struct {
	AccountID   string
	DisplayName string
}

// BuildGServiceAccount maps capability.identity.serviceaccount attributes to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildGServiceAccount(project, environment, capability string,
	attrs, impl map[string]any, generation int) (GServiceAccountPlan, error) {
	p := GServiceAccountPlan{AccountID: GServiceAccountID(project, environment, capability, generation)}
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "display.name":
			p.DisplayName, _ = raw.(string)
			p.DisplayName = strings.TrimSpace(p.DisplayName)
		case "key.exportable":
			if raw == true {
				return GServiceAccountPlan{}, fmt.Errorf(
					"key.exportable=true cannot be honored — groundhold never creates a downloadable " +
						"private key (a secret, D53); a service account is keyless (workload identity)")
			}
		case "service.managed":
			if raw != true {
				return GServiceAccountPlan{}, fmt.Errorf("service.managed=false cannot be honored by a service account")
			}
		default:
			return GServiceAccountPlan{}, fmt.Errorf(
				"attribute %s has no service-account mapping — refusing rather than silently dropping it "+
					"(trust policy, granted roles are opaque authorization config, out of scope)", path)
		}
	}
	if p.DisplayName == "" {
		p.DisplayName = capability + "-" + environment
	}
	if !gsaAccountIDOK.MatchString(p.AccountID) {
		return GServiceAccountPlan{}, fmt.Errorf("derived account id %q is invalid", p.AccountID)
	}
	if !projectOK.MatchString(project) {
		return GServiceAccountPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	return p, nil
}

// createBody is the serviceAccounts.create request body. Ownership is the description
// marker (no labels exist on this resource).
func (p GServiceAccountPlan) createBody(capability, environment string) map[string]any {
	return map[string]any{
		"accountId": p.AccountID,
		"serviceAccount": map[string]any{
			"displayName": p.DisplayName,
			"description": vpcOwnerMarker(capability, environment),
		},
	}
}
