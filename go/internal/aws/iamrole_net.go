// IAM role network shell (D121): the SigV4-signed, Query-protocol half of the AWS
// capability.identity.serviceaccount driver. IAM is GLOBAL (signed us-east-1, one
// endpoint). The role name is deterministic, so the providerId is knowable before the
// response (D29). Ownership is TAGS (returned inline by GetRole). D29/D87 honesty.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// iamBase / iamPost are the shared IAM Query plumbing, defined once in
// rolepolicy_net.go (D104) and reused here (D121 dedup on rebase).

func iamRoleProviderID(account, roleName string) string {
	return "iamrole:" + account + ":" + roleName
}

func splitIAMRoleProviderID(providerID string) (account, roleName string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "iamrole" {
		return "", "", fmt.Errorf("providerId %q is not iamrole:account:roleName", providerID)
	}
	if !account12.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId account %q is invalid", parts[1])
	}
	if !iamRoleNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId role %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

type iamRole struct {
	RoleName    string `xml:"RoleName"`
	Arn         string `xml:"Arn"`
	Description string `xml:"Description"`
	Tags        []struct {
		Key   string `xml:"Key"`
		Value string `xml:"Value"`
	} `xml:"Tags>member"`
}

func (r iamRole) tags() map[string]string {
	m := map[string]string{}
	for _, t := range r.Tags {
		m[t.Key] = t.Value
	}
	return m
}

// getRole reads a role via GetRole. found=false + readable=true is an authoritative
// "does not exist"; readable=false is a transport/HTTP/parse failure.
// getRole reads the resource. D296: a failed read names its cause; an
// authoritative absence stays found=false with NO error.
func (d *Driver) getRole(roleName string) (iamRole, bool, error) {
	const op = "GetRole"
	st, resp, err := d.iamPost(encodeForm(map[string]string{
		"Action": "GetRole", "Version": iamVersion, "RoleName": roleName}))
	if err != nil {
		return iamRole{}, false, readTransport(op, err)
	}
	if strings.Contains(rdsErrCode(resp), "NoSuchEntity") {
		return iamRole{}, false, nil
	}
	if st != http.StatusOK {
		return iamRole{}, false, readHTTP(op, st, rdsErrCode(resp))
	}
	var r struct {
		Role iamRole `xml:"GetRoleResult>Role"`
	}
	if xml.Unmarshal(resp, &r) != nil {
		return iamRole{}, false, readBody(op, st)
	}
	return r.Role, true, nil
}

func (d *Driver) createIAMRole(account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildIAMRole(account, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := iamRoleProviderID(account, plan.RoleName)
	st, resp, err := d.iamPost(encodeForm(plan.createParams(capability, environment)))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // synchronous
	case strings.Contains(rdsErrCode(resp), "EntityAlreadyExists"):
		role, found, rerr := d.getRole(plan.RoleName)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing role gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || !groundholdTagsMatch(role.tags(), capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a role with this name exists and is not ours (tags do not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // ours, present
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	default:
		// D237: throttle/503/live-403 -> unknown WITH the pid (the role name is
		// deterministic, keep the handle); only a clean 4xx refusal fails.
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d (%s)", st, rdsErrCode(resp))}
	}
}

func (d *Driver) observeIAMRole(capability, providerID string) ([]provider.Observation, []string, error) {
	_, roleName, err := splitIAMRoleProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	role, found, rerr := d.getRole(roleName)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"role not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// an assumed role has no downloadable key.
		{Path: "key.exportable", Value: false, Derivation: "config-intent"},
	}
	if role.Description != "" {
		obs = append(obs, provider.Observation{Path: "display.name", Value: role.Description, Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteIAMRole(capability, environment, providerID string) provider.CreateResult {
	_, roleName, err := splitIAMRoleProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	role, found, rerr := d.getRole(roleName)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !groundholdTagsMatch(role.tags(), capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "role tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, e := d.iamPost(encodeForm(map[string]string{
		"Action": "DeleteRole", "Version": iamVersion, "RoleName": roleName}))
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if strings.Contains(rdsErrCode(resp), "NoSuchEntity") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if strings.Contains(rdsErrCode(resp), "DeleteConflict") {
		return provider.CreateResult{Status: "failed",
			Reason: "the role still has attached policies / instance profiles and cannot be deleted — detach them first (never forced)"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		// D237: throttle/503/live-403 -> unknown WITH the pid, never failed.
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d (%s)", st, rdsErrCode(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
