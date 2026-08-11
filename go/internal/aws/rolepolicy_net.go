// IAM role-policy attachment network shell (D104): the SigV4-signed (global,
// us-east-1) half of the AWS capability.authorization.grant driver. IAM is the Query
// protocol; the attachment is content-addressed by (roleName, policyArn), so the
// providerId is deterministic and a lost outcome (D29) always carries it. No
// ownership tags — groundhold detaches ONLY the policy it attached, never another.
//
// NOTE: iamBase/iamPost/iamVersion + the Driver.IAMBaseURL field are the shared IAM
// Query plumbing; the capability.identity.workload driver (D103) introduces the same
// helpers. When both land they are ONE copy (dedup at rebase).
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

const iamVersion = "2010-05-08"

func (d *Driver) iamBase() string {
	if d.IAMBaseURL != "" {
		return d.IAMBaseURL
	}
	return "https://iam.amazonaws.com"
}

// iamPost signs (global, us-east-1) and sends a Query-protocol POST.
func (d *Driver) iamPost(body string) (int, []byte, error) {
	return d.doSigned("POST", d.iamBase()+"/", "iam", "us-east-1",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(body))
}

func rolePolicyProviderID(roleName, policyArn string) string {
	return "aauth:" + roleName + ":" + policyArn
}

func splitRolePolicyProviderID(providerID string) (roleName, policyArn string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "aauth" {
		return "", "", fmt.Errorf("providerId %q is not aauth:roleName:policyArn", providerID)
	}
	if !awsGrantRoleNameOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId role name %q is invalid", parts[1])
	}
	if !awsPolicyArnOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId policy arn %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

func (d *Driver) createRolePolicyAttachment(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildRolePolicyAttachment(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := rolePolicyProviderID(plan.RoleName, plan.PolicyArn)
	// AttachRolePolicy is idempotent — attaching an already-attached policy is a
	// no-op success, so no pre-read is needed.
	st, resp, e := d.iamPost(encodeForm(map[string]string{
		"Action": "AttachRolePolicy", "Version": iamVersion,
		"RoleName": plan.RoleName, "PolicyArn": plan.PolicyArn}))
	if e != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("attach outcome unknown: %v", e)}
	}
	switch {
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case strings.Contains(rdsErrCode(resp), "NoSuchEntity"):
		// the ROLE (principal) does not exist — a real refusal, not our resource
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("attach failed: role %q does not exist (grant.principal must name an existing role)", plan.RoleName)}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("attach: HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	default:
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, pid, "attach"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("attach: HTTP %d (%s): %s", st, rdsErrCode(resp), mutDetail(resp))}
	}
}

// iamAttachedPolicy reports whether policyArn is attached to roleName. found=false
// + readable=true is an authoritative "not attached"; readable=false is transport/
// HTTP/parse failure.
func (d *Driver) iamAttachedPolicy(roleName, policyArn string) (attached bool, err error) {
	const op = "ListAttachedRolePolicies"
	st, resp, cerr := d.iamPost(encodeForm(map[string]string{
		"Action": "ListAttachedRolePolicies", "Version": iamVersion, "RoleName": roleName}))
	if cerr != nil {
		return false, readTransport(op, cerr)
	}
	if st == http.StatusNotFound || strings.Contains(rdsErrCode(resp), "NoSuchEntity") {
		return false, nil // the role is gone -> the attachment is not present
	}
	if st != http.StatusOK {
		return false, readHTTP(op, st, rdsErrCode(resp))
	}
	var r struct {
		Arns []string `xml:"ListAttachedRolePoliciesResult>AttachedPolicies>member>PolicyArn"`
	}
	if xml.Unmarshal(resp, &r) != nil {
		return false, readBody(op, st)
	}
	for _, a := range r.Arns {
		if a == policyArn {
			return true, nil
		}
	}
	return false, nil
}

func (d *Driver) observeRolePolicyAttachment(capability, providerID string) ([]provider.Observation, []string, error) {
	roleName, policyArn, err := splitRolePolicyProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	attached, rerr := d.iamAttachedPolicy(roleName, policyArn)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !attached {
		// F-LC3 (D522): the attachment IS the resource here — an unattached policy
		// is a bound grant that no longer exists, not an empty reading.
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"policy not attached — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "grant.role", Value: policyArn, Derivation: "measured"},
		{Path: "grant.principal", Value: roleName, Derivation: "measured"},
		{Path: "access.scope", Value: "account", Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	if priv, known := classifyAWSPolicy(policyArn); known {
		obs = append(obs, provider.Observation{Path: "access.privileged", Value: priv, Derivation: "measured"})
	} else {
		diags = append(diags, "access.privileged not observed: policy "+policyArn+" is not in groundhold's known privileged-policy set (a custom policy's privilege is not guessed)")
	}
	return obs, diags, nil
}

func (d *Driver) deleteRolePolicyAttachment(capability, environment, providerID string) provider.CreateResult {
	roleName, policyArn, err := splitRolePolicyProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// OWNERSHIP (D445). An attachment carries no tags and no name of its own — only the
	// pair it joins — so for a while this looked like the one delete in the family with
	// nothing to check. It is not: the ROLE has tags, and detaching a policy from a role
	// MODIFIES that role. Detaching from a stranger's role removes a permission their
	// workload is using; that it is reversible by re-attaching is a mitigation, not a
	// licence. So the role is the ownership surface, and it is read before the detach.
	//
	// An unreadable role is unknown rather than a refusal: the detach may be legitimate
	// and we cannot tell, which is exactly what unknown is for.
	role, found, rerr := d.getRole(roleName)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-detach role read gave no answer — reconcile: " + rerr.Error()}
	}
	if found && !groundholdTagsMatch(role.tags(), capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("role %q is not ours (tags do not match) — refusing to "+
				"detach a policy from a role this contract does not own", roleName)}
	}
	st, resp, e := d.iamPost(encodeForm(map[string]string{
		"Action": "DetachRolePolicy", "Version": iamVersion,
		"RoleName": roleName, "PolicyArn": policyArn}))
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("detach outcome unknown: %v", e)}
	}
	if strings.Contains(rdsErrCode(resp), "NoSuchEntity") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("detach: HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, providerID, "detach"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("detach: HTTP %d (%s)", st, rdsErrCode(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
