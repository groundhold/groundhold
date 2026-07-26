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
	if perr != nil {
		return nil, nil, perr
	}
	if !memberInRole(pol, role, member) {
		return nil, []string{"grant not present in the project policy — nothing to observe"}, nil
	}
	obs := []provider.Observation{
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
	} else {
		diags = append(diags, "access.privileged not observed: role "+role+" is not in groundhold's known privileged-role set (a custom role's privilege is not guessed)")
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
