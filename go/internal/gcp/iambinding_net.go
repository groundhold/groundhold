// GCP IAM binding network shell (D104): the bearer-signed half of the
// capability.authorization.grant driver. A grant is a read-modify-write on the
// PROJECT IAM policy (cloudresourcemanager projects:getIamPolicy/setIamPolicy): add
// the {role, member} pair on create, remove exactly that member on delete. The
// binding is content-addressed (project, role, member), so there are no ownership
// tags — groundhold touches ONLY the member it granted, never another principal's
// access. A lost setIamPolicy is unknown (D29). The policy etag rides the RMW so a
// concurrent editor cannot be silently clobbered.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"errors"
	"groundhold/internal/provider"
)

func iamBindingProviderID(project, role, member string) string {
	return "gauth:" + project + ":" + role + ":" + member
}

func splitIAMBindingProviderID(providerID string) (project, role, member string, err error) {
	parts := strings.SplitN(providerID, ":", 5)
	if len(parts) != 5 || parts[0] != "gauth" {
		return "", "", "", fmt.Errorf("providerId %q is not gauth:project:role:memberType:memberId", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	role = parts[2]
	member = parts[3] + ":" + parts[4]
	if !gcpRoleOK.MatchString(role) {
		return "", "", "", fmt.Errorf("providerId role %q is invalid", role)
	}
	if !gcpMemberOK.MatchString(member) {
		return "", "", "", fmt.Errorf("providerId member %q is invalid", member)
	}
	return parts[1], role, member, nil
}

type iamPolicy struct {
	Version  int                `json:"version,omitempty"`
	Etag     string             `json:"etag,omitempty"`
	Bindings []iamPolicyBinding `json:"bindings"`
}

type iamPolicyBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

// crmGetProjectPolicy reads the project's IAM policy. A non-nil error names why
// the read did not answer — never a fabricated empty policy (which would read as
// "the grant is absent" and re-grant, or as "nothing to delete").
func (d *Driver) crmGetProjectPolicy(project string) (iamPolicy, error) {
	const op = "projects.getIamPolicy"
	url := fmt.Sprintf("%s/projects/%s:getIamPolicy", d.crmBase(), project)
	st, body, err := d.call("POST", url, map[string]any{})
	if err != nil {
		return iamPolicy{}, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		// F-LC3 (D522): a readable absence, not a failure to read.
		return iamPolicy{}, errGCPAbsent
	}
	if st != http.StatusOK {
		return iamPolicy{}, readHTTP(op, st, gcpErrCode(body))
	}
	var pol iamPolicy
	if json.Unmarshal(body, &pol) != nil {
		return iamPolicy{}, readBody(op, st)
	}
	return pol, nil
}

// memberInRole reports whether the policy already grants member the role.
func memberInRole(pol iamPolicy, role, member string) bool {
	for _, b := range pol.Bindings {
		if b.Role != role {
			continue
		}
		for _, m := range b.Members {
			if m == member {
				return true
			}
		}
	}
	return false
}

func (d *Driver) createIAMBinding(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildIAMBinding(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := iamBindingProviderID(d.Project, plan.Role, plan.Member)
	pol, perr := d.crmGetProjectPolicy(d.Project)
	if perr != nil {
		return provider.CreateResult{Status: "unknown", Reason: "getIamPolicy gave no answer — reconcile: " + perr.Error()}
	}
	if memberInRole(pol, plan.Role, plan.Member) {
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // idempotent
	}
	// add the member to the role binding (creating the binding if absent).
	added := false
	for i := range pol.Bindings {
		if pol.Bindings[i].Role == plan.Role {
			pol.Bindings[i].Members = append(pol.Bindings[i].Members, plan.Member)
			added = true
			break
		}
	}
	if !added {
		pol.Bindings = append(pol.Bindings, iamPolicyBinding{Role: plan.Role, Members: []string{plan.Member}})
	}
	if r := d.crmSetProjectPolicy(d.Project, pol, pid); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// crmSetProjectPolicy writes the modified policy back (etag-guarded). nil = ok.
func (d *Driver) crmSetProjectPolicy(project string, pol iamPolicy, pid string) *provider.CreateResult {
	url := fmt.Sprintf("%s/projects/%s:setIamPolicy", d.crmBase(), project)
	st, body, err := d.call("POST", url, map[string]any{"policy": pol})
	if err != nil {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("setIamPolicy outcome unknown (may have landed): %v", err)}
		return &r
	}
	if st == http.StatusConflict {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "setIamPolicy etag conflict (a concurrent edit) — reconcile and retry"}
		return &r
	}
	if st >= 500 {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("setIamPolicy HTTP %d (server error) — reconcile", st)}
		return &r
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "setIamPolicy"); r != nil {
			return r
		}
		r := provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("setIamPolicy HTTP %d: %s", st, mutDetail(body))}
		return &r
	}
	return nil
}

func (d *Driver) observeIAMBinding(capability, providerID string) ([]provider.Observation, []string, error) {
	project, role, member, err := splitIAMBindingProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	pol, perr := d.crmGetProjectPolicy(project)
	if errors.Is(perr, errGCPAbsent) {
		// The project policy itself is gone, so the binding inside it is too
		// (F-LC3, D522) — a 404 here is a readable absence, not a read failure.
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"project policy not found — bound resource is gone (will re-create)"}, nil
	}
	if perr != nil {
		return nil, nil, perr
	}
	if !memberInRole(pol, role, member) {
		// F-LC3 (D522): the binding IS the resource — a member no longer in the
		// role is a bound grant that no longer exists, not an empty reading.
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"grant not present in the project policy — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3).
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "grant.role", Value: role, Derivation: "measured"},
		{Path: "grant.principal", Value: member, Derivation: "measured"},
		{Path: "access.scope", Value: "account", Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	// least-privilege: report the classification ONLY for a role groundhold knows;
	// an unclassifiable role leaves access.privileged unverifiable, never guessed.
	if priv, known := classifyGCPRole(role); known {
		obs = append(obs, provider.Observation{Path: "access.privileged", Value: priv, Derivation: "measured"})
	} else if priv, known, why := d.bindingPrivilegeFromRole(role); known {
		// D1231: the ID did not settle it, so read the role DEFINITION. This reaches
		// both populations — custom roles (D1228) and the predefined roles outside the
		// curated set, which in a real project was 37 of 49 bindings.
		obs = append(obs, provider.Observation{Path: "access.privileged", Value: priv, Derivation: "measured"})
	} else if why != "" {
		// The wording says what the DEFINITION includes, never what the principal CAN
		// do: a deny policy or an org policy can narrow effective access below it.
		diags = append(diags, "access.privileged not observed: role "+role+" — "+why)
	} else {
		// D1225: name the cause the id actually proves. The old wording said "a custom
		// role's privilege is not guessed" for EVERY unclassifiable role, which is a
		// claim about the estate that this code never checked — and in the field it is
		// usually false (37 of 49 role bindings in a real project are predefined roles
		// outside the curated set; none were custom). The remedy differs by cause:
		// a predefined role is groundhold's gap to close, a custom one is not.
		if gcpRoleIsPredefined(role) {
			diags = append(diags, "access.privileged not observed: role "+role+" is PREDEFINED by Google "+
				"but is not in groundhold's curated privileged-role set — the gap is groundhold's, and privilege is not guessed")
		} else {
			diags = append(diags, "access.privileged not observed: role "+role+" is a CUSTOM role "+
				"— its id was chosen by whoever wrote it, so it is not evidence about the permissions "+
				"behind it, and privilege is not guessed (D1228)")
		}
	}
	return obs, diags, nil
}

func (d *Driver) deleteIAMBinding(capability, environment, providerID string) provider.CreateResult {
	project, role, member, err := splitIAMBindingProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pol, perr := d.crmGetProjectPolicy(project)
	if perr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete getIamPolicy gave no answer — reconcile: " + perr.Error()}
	}
	if !memberInRole(pol, role, member) {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	// remove ONLY our member from the role binding; drop the binding if now empty.
	out := pol.Bindings[:0]
	for _, b := range pol.Bindings {
		if b.Role == role {
			kept := make([]string, 0, len(b.Members))
			for _, m := range b.Members {
				if m != member {
					kept = append(kept, m)
				}
			}
			if len(kept) == 0 {
				continue // drop the now-empty binding
			}
			b.Members = kept
		}
		out = append(out, b)
	}
	pol.Bindings = out
	if r := d.crmSetProjectPolicy(project, pol, providerID); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// rolePermissionsCached fetches a role's includedPermissions, memoized for ONE sweep.
//
// Per sweep, not per process, for the reason the AWS twin gives: a long-lived driver
// would otherwise serve one instant's definition under another instant's clock,
// against the --at thesis. Failures are cached too — a project with many bindings on
// one unreadable role would otherwise re-ask (and re-fail) once per binding.
//
// The URL shape differs by role kind, and both are the role id verbatim under v1:
// `roles/<id>` for predefined, `projects/<p>/roles/<id>` (or organizations/...) for
// custom. So the id IS the resource path — no reassembly, nothing to get wrong.
func (d *Driver) rolePermissionsCached(role string) ([]string, error) {
	if d.rolePerms == nil {
		d.rolePerms = map[string]cachedPerms{}
	}
	if c, ok := d.rolePerms[role]; ok {
		return c.perms, c.err
	}
	p, e := d.getRolePermissions(role)
	d.rolePerms[role] = cachedPerms{perms: p, err: e}
	return p, e
}

type cachedPerms struct {
	perms []string
	err   error
}

func (d *Driver) getRolePermissions(role string) ([]string, error) {
	const op = "roles.get"
	url := d.iamBase() + "/" + role
	st, body, err := d.call("GET", url, nil)
	if err != nil {
		return nil, readTransport(op, err)
	}
	if st != http.StatusOK {
		return nil, readHTTP(op, st, gcpErrCode(body))
	}
	var doc struct {
		IncludedPermissions []string `json:"includedPermissions"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil, readBody(op, st)
	}
	return doc.IncludedPermissions, nil
}
