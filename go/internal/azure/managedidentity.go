// Azure user-assigned managed identity request building (D121): the semantic core
// of the Azure capability.identity.serviceaccount driver — the SAME vocabulary GCP
// service accounts and AWS IAM roles fulfil. A user-assigned managed identity is a
// keyless machine identity a workload references; Azure holds the credential and
// issues short-lived tokens (there is NO downloadable key). D53: key.exportable=true
// is refused. The identity's role assignments (what it may DO) are opaque
// authorization config, out of this identity capability's scope. The identity is a
// regional ARM resource, so a location rides in the impl block (Azure substrate
// detail, like resource_group) even though the vocabulary is conceptually location-
// free — an implementation shape, never a silent default.
package azure

import (
	"fmt"
	"regexp"
)

const managedIdentityAPIVersion = "2023-01-31"

// uamiLocationOK bounds the impl-provided region before it enters the ARM body.
var uamiLocationOK = regexp.MustCompile(`^[a-z0-9]{1,40}$`)

// ManagedIdentityPlan is the attribute-derived shape a create assembles.
type ManagedIdentityPlan struct {
	Name        string
	Location    string
	DisplayName string // carried in a tag; ARM UAMI has no display field
}

// BuildManagedIdentity maps capability.identity.serviceaccount attributes + impl to
// a plan. Every error is a preflight refusal, never a silent drop.
func BuildManagedIdentity(environment, capability string,
	attrs, impl map[string]any, generation int) (ManagedIdentityPlan, error) {
	p := ManagedIdentityPlan{Name: azResourceName("id", environment, capability, generation)}
	for _, path := range sortedAttrKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "display.name":
			p.DisplayName, _ = raw.(string)
		case "key.exportable":
			if raw == true {
				return ManagedIdentityPlan{}, fmt.Errorf(
					"key.exportable=true cannot be honored — a user-assigned managed identity is keyless " +
						"(Azure issues short-lived tokens); groundhold never manages a downloadable key (D53)")
			}
		case "service.managed":
			if raw != true {
				return ManagedIdentityPlan{}, fmt.Errorf("service.managed=false cannot be honored by a managed identity")
			}
		default:
			return ManagedIdentityPlan{}, fmt.Errorf(
				"attribute %s has no managed-identity mapping — refusing rather than silently dropping it "+
					"(role assignments are opaque authorization config, out of scope)", path)
		}
	}
	loc, _ := impl["location"].(string)
	if !uamiLocationOK.MatchString(loc) {
		return ManagedIdentityPlan{}, fmt.Errorf(
			"azure managed identity requires implementation.location (a region, e.g. eastus) — " +
				"the identity is a regional ARM resource; groundhold will not guess a region")
	}
	p.Location = loc
	if !azNameOK.MatchString(p.Name) {
		return ManagedIdentityPlan{}, fmt.Errorf("derived identity name %q is invalid", p.Name)
	}
	return p, nil
}
