// GKE Workload Identity network shell (D76 parity): the bearer-signed half of the
// GCP capability.identity.podidentity driver. A WI binding is a read-modify-write on
// the GSA's OWN IAM policy (iam.serviceAccounts.getIamPolicy/setIamPolicy): add the
// {roles/iam.workloadIdentityUser, KSA-member} pair on create, remove exactly that
// member on delete. Content-addressed — no ownership labels; groundhold touches ONLY
// the member it granted. A lost setIamPolicy is unknown (D29). The policy etag rides
// the RMW so a concurrent editor cannot be silently clobbered (never a blind retry).
//
// The iamPolicy / iamPolicyBinding structs and memberInRole are shared with
// iambinding_net.go (same package) — a policy is a policy.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

// saIamPolicyURL targets the GSA's IAM policy. The project segment is the '-'
// wildcard: the GSA (an operand) may live in a different project than the pinned
// one, and GCP resolves the project from the (strictly-validated) email — so no
// project component is interpolated into the path (confused-deputy safe).
func (d *Driver) saIamPolicyURL(gsaEmail, verb string) string {
	return fmt.Sprintf("%s/projects/-/serviceAccounts/%s:%s", d.iamBase(), gsaEmail, verb)
}

// saGetIamPolicy reads the GSA's IAM policy. A non-nil error is a read that did
// not answer (transport, non-200 — including a 404 GSA — or an unparseable
// body); it is never a fabricated empty policy.
func (d *Driver) saGetIamPolicy(gsaEmail string) (iamPolicy, error) {
	const op = "serviceAccounts.getIamPolicy"
	st, body, err := d.gcpGetRetry("POST", d.saIamPolicyURL(gsaEmail, "getIamPolicy"), map[string]any{})
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

// saSetIamPolicy writes the modified GSA policy back (etag-guarded). nil = ok. A
// 409 etag conflict is a concurrent edit — unknown WITH a reconcile-and-retry hint,
// NEVER a blind retry that would clobber the other writer.
func (d *Driver) saSetIamPolicy(gsaEmail string, pol iamPolicy, pid string) *provider.CreateResult {
	st, body, err := d.call("POST", d.saIamPolicyURL(gsaEmail, "setIamPolicy"),
		map[string]any{"policy": pol})
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
		r := provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("setIamPolicy HTTP %d: %s", st, mutDetail(body))}
		return &r
	}
	return nil
}

// createGKEWorkloadIdentity binds the KSA member to workloadIdentityUser on the GSA,
// four-valued throughout. Pre-read is idempotent (member already present = repair);
// else RMW adds it. Transport/5xx/etag-conflict are unknown WITH the pid (D29).
func (d *Driver) createGKEWorkloadIdentity(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildGKEWorkloadIdentity(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := gkeWIProviderID(plan.PoolProject, plan.GSAEmail, plan.Namespace, plan.ServiceAccount)
	member := plan.Member()

	pol, perr := d.saGetIamPolicy(plan.GSAEmail)
	if perr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "pre-create getIamPolicy on the GSA gave no answer — reconcile before provisioning: " + perr.Error()}
	}
	if memberInRole(pol, wiRole, member) {
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // ours already — repair/no-op
	}
	// add the member to the workloadIdentityUser binding (creating it if absent).
	added := false
	for i := range pol.Bindings {
		if pol.Bindings[i].Role == wiRole {
			pol.Bindings[i].Members = append(pol.Bindings[i].Members, member)
			added = true
			break
		}
	}
	if !added {
		pol.Bindings = append(pol.Bindings, iamPolicyBinding{Role: wiRole, Members: []string{member}})
	}
	if r := d.saSetIamPolicy(plan.GSAEmail, pol, pid); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// observeGKEWorkloadIdentity reverse-maps a WI binding to
// capability.identity.podidentity: read the GSA IAM policy, confirm the member holds
// workloadIdentityUser. An unreadable policy is an error (unknown), never a
// fabricated absence; a missing member is "nothing to observe".
func (d *Driver) observeGKEWorkloadIdentity(capability, providerID string) ([]provider.Observation, []string, error) {
	poolProject, gsaEmail, namespace, serviceAccount, err := splitGKEWIProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	pol, perr := d.saGetIamPolicy(gsaEmail)
	if perr != nil {
		return nil, nil, perr
	}
	member := wiMember(poolProject, namespace, serviceAccount)
	if !memberInRole(pol, wiRole, member) {
		return []provider.Observation{
			// F-LC3 (D802): a BOUND resource the API authoritatively 404s is GONE. An
			// empty return leaves the last good observations standing as the freshest
			// word, so posture reads managed-ok and audit stays satisfied about a
			// resource that does not exist (D513/D518, fixed here last).
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"workload identity binding not present on the GSA — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		{Path: "workload.namespace", Value: namespace, Derivation: "measured"},
		{Path: "workload.serviceAccount", Value: serviceAccount, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	return obs, nil, nil
}

// deleteGKEWorkloadIdentity removes ONLY our member from the GSA's
// workloadIdentityUser binding (dropping the binding if it becomes empty).
// Idempotent on already-gone; transport/5xx/etag-conflict are unknown WITH the pid.
func (d *Driver) deleteGKEWorkloadIdentity(capability, environment, providerID string) provider.CreateResult {
	poolProject, gsaEmail, namespace, serviceAccount, err := splitGKEWIProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pol, perr := d.saGetIamPolicy(gsaEmail)
	if perr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete getIamPolicy on the GSA gave no answer — reconcile: " + perr.Error()}
	}
	member := wiMember(poolProject, namespace, serviceAccount)
	if !memberInRole(pol, wiRole, member) {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	out := pol.Bindings[:0]
	for _, b := range pol.Bindings {
		if b.Role == wiRole {
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
	if r := d.saSetIamPolicy(gsaEmail, pol, providerID); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// discoverGKEWorkloadIdentity enumerates every Workload Identity binding in the
// project as capability.identity.podidentity: list the project's service accounts,
// then read each GSA's IAM policy and reverse every workloadIdentityUser member of
// the WI form into a pid (the pool project rides in the member string, so a
// cross-project cluster binding is still recovered). A per-GSA policy read failure is
// a diagnostic — it never hides the bindings another GSA returned. region does not
// filter (a WI binding has no region). Reuses observeGKEWorkloadIdentity's reverse map.
func (d *Driver) discoverGKEWorkloadIdentity(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/serviceAccounts", d.iamBase(), d.Project), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("serviceAccounts.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("serviceAccounts.list: HTTP %d", status)
	}
	var resp struct {
		Accounts []struct {
			Email string `json:"email"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("serviceAccounts.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, a := range resp.Accounts {
		if !gsaEmailOK.MatchString(a.Email) {
			continue // an email we cannot address safely — skip rather than misreport
		}
		pol, perr := d.saGetIamPolicy(a.Email)
		if perr != nil {
			diags = append(diags, a.Email+": getIamPolicy gave no answer ("+perr.Error()+") — skipped")
			continue
		}
		for _, b := range pol.Bindings {
			if b.Role != wiRole {
				continue
			}
			for _, m := range b.Members {
				g := wiMemberRE.FindStringSubmatch(m)
				if g == nil {
					diags = append(diags, a.Email+"/"+m+": not a parseable workload-identity member — skipped")
					continue
				}
				poolProject, namespace, ksa := g[1], g[2], g[3]
				pid := gkeWIProviderID(poolProject, a.Email, namespace, ksa)
				obs, od, oerr := d.observeGKEWorkloadIdentity("", pid)
				if oerr != nil {
					diags = append(diags, a.Email+"/"+m+": "+oerr.Error())
					continue
				}
				diags = append(diags, od...)
				out = append(out, provider.Discovered{
					ProviderID: pid, ResourceType: "capability.identity.podidentity", Observations: provider.WithoutAbsence(obs)})
			}
		}
	}
	return out, diags, nil
}
