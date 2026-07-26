package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// orgpolicy_net.go resolves the EFFECTIVE Public Access Prevention org policy for
// a project (D238, API-drift #5). buckets.get returns a bucket's OWN PAP
// ("enforced" | "inherited"), not an org policy that ENFORCES PAP above it — so a
// bucket with PAP="inherited" plus a stale allUsers binding reads as public even
// when an org constraint makes it definitively private (a false positive on the
// privacy constraint). This resolver asks the Org Policy API for the effective
// constraints/storage.publicAccessPrevention on the project, and observeGCS
// downgrades publicExposure to false ONLY on positive enforcement evidence — an
// unreadable policy never fabricates "private" (never-fabricate: the false
// negative is the dangerous direction, so absence of proof keeps the conservative
// public verdict).

// orgPolicyBaseURL is the Org Policy v2 API (the current surface; the legacy
// cloudresourcemanager v1 getEffectiveOrgPolicy is deliberately NOT used).
const orgPolicyBaseURL = "https://orgpolicy.googleapis.com/v2"

func (d *Driver) orgPolicyBase() string {
	if d.OrgPolicyBaseURL != "" {
		return d.OrgPolicyBaseURL
	}
	return orgPolicyBaseURL
}

// papConstraint is the boolean org constraint that governs GCS public access.
// The v2 policy resource path uses the SHORT constraint name (no "constraints/"
// prefix), unlike the docs' "constraints/storage.publicAccessPrevention".
const papConstraint = "storage.publicAccessPrevention"

// effectivePAPEnforced reports whether the effective PAP org policy on a project
// is ENFORCED. A non-nil error names why the policy could not be determined
// (permission denied, API disabled, transport error, unparseable) — the caller
// then keeps its conservative verdict, never a fabricated "private". Positive
// enforcement requires an unconditional rule with enforce:true; a missing spec,
// empty rules, or enforce:false is authoritative "not enforced" (nil error).
func (d *Driver) effectivePAPEnforced(project string) (enforced bool, err error) {
	const op = "orgPolicy.getEffectivePolicy"
	url := fmt.Sprintf("%s/projects/%s/policies/%s:getEffectivePolicy",
		d.orgPolicyBase(), project, papConstraint)
	status, body, cerr := d.call("GET", url, nil)
	if cerr != nil {
		return false, readTransport(op, cerr) // the caller stays conservative
	}
	if status != http.StatusOK {
		return false, readHTTP(op, status, gcpErrCode(body))
	}
	var p struct {
		Spec struct {
			Rules []struct {
				Enforce *bool `json:"enforce"`
			} `json:"rules"`
		} `json:"spec"`
	}
	if json.Unmarshal(body, &p) != nil {
		return false, readBody(op, status) // never read as "not enforced"
	}
	for _, r := range p.Spec.Rules {
		if r.Enforce != nil && *r.Enforce {
			return true, nil // positive enforcement evidence
		}
	}
	return false, nil // authoritatively not enforced
}
