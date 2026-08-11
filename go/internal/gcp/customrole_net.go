// GCP IAM custom role network shell (D105): the bearer-signed half of the
// capability.authorization.role driver. projects.roles.create is synchronous; the
// role is content-addressed by a deterministic roleId. No ownership tags — a role at
// our deterministic id is ours; a 409 with a DIFFERENT permission set is a real
// conflict (refused), a matching one is idempotent. Delete is a 7-day soft-delete.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"groundhold/internal/provider"
)

const iamCustomRoleBaseURL = "https://iam.googleapis.com/v1"

var gcRoleIDOK = regexp.MustCompile(`^[a-zA-Z0-9_.]{3,64}$`)

func (d *Driver) iamBase() string {
	if d.IAMBaseURL != "" {
		return d.IAMBaseURL
	}
	return iamCustomRoleBaseURL
}

func gcRoleProviderID(project, roleID string) string { return "gcrole:" + project + ":" + roleID }

func splitGCRoleProviderID(providerID string) (project, roleID string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "gcrole" {
		return "", "", fmt.Errorf("providerId %q is not gcrole:project:roleId", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !gcRoleIDOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId roleId %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

func (p CustomRolePlan) createBody() map[string]any {
	return map[string]any{
		"roleId": p.RoleID,
		"role": map[string]any{
			"title":               "groundhold " + p.RoleID,
			"description":         "groundhold-managed custom role",
			"includedPermissions": p.Permissions,
			"stage":               "GA",
		},
	}
}

type customRoleDoc struct {
	Name                string   `json:"name"`
	IncludedPermissions []string `json:"includedPermissions"`
	Deleted             bool     `json:"deleted"`
}

func (d *Driver) getCustomRole(project, roleID string) (customRoleDoc, bool, error) {
	const op = "customRole.get"
	url := fmt.Sprintf("%s/projects/%s/roles/%s", d.iamBase(), project, roleID)
	st, body, err := d.call("GET", url, nil)
	if err != nil {
		return customRoleDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return customRoleDoc{}, false, nil
	}
	if st != http.StatusOK {
		return customRoleDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc customRoleDoc
	if json.Unmarshal(body, &doc) != nil {
		return customRoleDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func (d *Driver) createCustomRole(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildCustomRole(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := gcRoleProviderID(d.Project, plan.RoleID)
	url := fmt.Sprintf("%s/projects/%s/roles", d.iamBase(), d.Project)
	st, body, e := d.call("POST", url, plan.createBody())
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", e)}
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st == http.StatusConflict:
		// a role at our deterministic id already exists — idempotent ONLY if its
		// permission set matches ours (else it is a real conflict, refused).
		doc, found, rerr := d.getCustomRole(d.Project, plan.RoleID)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "id conflict, existing role gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || !sameStringSet(doc.IncludedPermissions, plan.Permissions) {
			return provider.CreateResult{Status: "failed", Reason: "a custom role with this id exists with a DIFFERENT permission set — refusing to overwrite (adopt explicitly)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
	}
}

func (d *Driver) observeCustomRole(capability, providerID string) ([]provider.Observation, []string, error) {
	project, roleID, err := splitGCRoleProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getCustomRole(project, roleID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found || doc.Deleted {
		// F-LC3 (D521): a BOUND resource the API says is GONE. A diagnostic
		// alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"custom role not found (or soft-deleted) — bound resource is gone (will re-create)"}, nil
	}
	perms := doc.IncludedPermissions
	return []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "role.permissions", Value: perms, Derivation: "measured"},
		{Path: "access.mutating", Value: gcRoleMutating(perms), Derivation: "measured"},
		{Path: "access.privileged", Value: gcRolePrivilegedSet(perms), Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}, nil, nil
}

func (d *Driver) deleteCustomRole(capability, environment, providerID string) provider.CreateResult {
	project, roleID, err := splitGCRoleProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// OWNERSHIP (D451): a GCP custom role carries NO LABELS — IAM offers none — so its
	// deterministic id is the only ownership evidence. Deleting a stranger's role revokes
	// every permission it grants, from every principal bound to it, at once.
	if !nameLooksOursGCP(roleID, capability, environment, "pv_", "_", gcRoleIDBad, 8) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("role %q is not named by groundhold for %s/%s — refusing to "+
				"delete a role this contract does not own (a custom role carries no labels, "+
				"so its id is the only ownership evidence there is)", roleID, capability, environment)}
	}
	url := fmt.Sprintf("%s/projects/%s/roles/%s", d.iamBase(), project, roleID)
	st, body, e := d.call("DELETE", url, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, gcpErrCode(body), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded", Reason: "custom role deleted (7-day undelete window)"}
}
