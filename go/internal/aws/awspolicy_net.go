// AWS customer-managed policy network shell (D105): the SigV4-signed (global,
// us-east-1) half of the AWS capability.authorization.role driver. The policy name
// is deterministic and the Arn is derivable from (account, name), so the pid is
// knowable before the response (D29). One version is created; observe reads it back
// and parses the flat action set out of the document. No ownership tags — the policy
// is content-addressed by its Arn.
//
// NOTE: iamBase/iamPost/iamVersion + Driver.IAMBaseURL are the shared IAM Query
// plumbing (also introduced by D103/D104); ONE copy when they land (dedup at rebase).
package aws

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"groundhold/internal/provider"
)

// iamVersion / iamBase / iamPost are the shared IAM Query plumbing, defined once in
// rolepolicy_net.go (D104) and reused here (D105 dedup on rebase).

var awsCustomPolicyArnOK = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:policy/[A-Za-z0-9+=,.@_/-]+$`)

func customPolicyProviderID(arn string) string { return "acrole:" + arn }

func splitCustomPolicyProviderID(providerID string) (arn string, err error) {
	parts := strings.SplitN(providerID, ":", 2)
	if len(parts) != 2 || parts[0] != "acrole" {
		return "", fmt.Errorf("providerId %q is not acrole:policyArn", providerID)
	}
	if !awsCustomPolicyArnOK.MatchString(parts[1]) {
		return "", fmt.Errorf("providerId policy arn %q is invalid", parts[1])
	}
	return parts[1], nil
}

func customPolicyArn(account, name string) string {
	return "arn:aws:iam::" + account + ":policy/" + name
}

func (d *Driver) createCustomPolicy(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildCustomPolicy(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.CreateResult{Status: "unknown", Reason: err.Error()}
	}
	arn := customPolicyArn(account, plan.PolicyName)
	pid := customPolicyProviderID(arn)
	st, resp, e := d.iamPost(encodeForm(map[string]string{
		"Action": "CreatePolicy", "Version": iamVersion,
		"PolicyName": plan.PolicyName, "PolicyDocument": plan.Document}))
	if e != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown: %v", e)}
	}
	switch {
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case strings.Contains(rdsErrCode(resp), "EntityAlreadyExists"):
		// a policy at our name exists — idempotent ONLY if its action set matches.
		actions, aerr := d.getCustomPolicyActions(arn)
		if aerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "name conflict, existing policy gave no answer — reconcile: " + aerr.Error()}
		}
		if !sameActionSet(actions, plan.Permissions) {
			return provider.CreateResult{Status: "failed", Reason: "a customer policy with this name exists with a DIFFERENT action set — refusing to overwrite (adopt explicitly)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	default:
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d (%s): %s", st, rdsErrCode(resp), mutDetail(resp))}
	}
}

// getCustomPolicyActions reads the flat action set out of a policy's default
// version. readable=false is a transport/HTTP/parse failure.
func (d *Driver) getCustomPolicyActions(arn string) (actions []string, err error) {
	// GetPolicy -> DefaultVersionId
	const getOp = "GetPolicy"
	st, resp, cerr := d.iamPost(encodeForm(map[string]string{
		"Action": "GetPolicy", "Version": iamVersion, "PolicyArn": arn}))
	if cerr != nil {
		return nil, readTransport(getOp, cerr)
	}
	if st != http.StatusOK {
		return nil, readHTTP(getOp, st, rdsErrCode(resp))
	}
	var gp struct {
		VersionID string `xml:"GetPolicyResult>Policy>DefaultVersionId"`
	}
	if xml.Unmarshal(resp, &gp) != nil || gp.VersionID == "" {
		return nil, readBody(getOp, st)
	}
	// GetPolicyVersion -> the URL-encoded document
	const verOp = "GetPolicyVersion"
	vst, vresp, verr := d.iamPost(encodeForm(map[string]string{
		"Action": "GetPolicyVersion", "Version": iamVersion, "PolicyArn": arn, "VersionId": gp.VersionID}))
	if verr != nil {
		return nil, readTransport(verOp, verr)
	}
	if vst != http.StatusOK {
		return nil, readHTTP(verOp, vst, rdsErrCode(vresp))
	}
	var gpv struct {
		Document string `xml:"GetPolicyVersionResult>PolicyVersion>Document"`
	}
	if xml.Unmarshal(vresp, &gpv) != nil {
		return nil, readBody(verOp, vst)
	}
	decoded, derr := url.QueryUnescape(gpv.Document)
	if derr != nil {
		return nil, readBody(verOp, vst)
	}
	acts, perr := actionsFromDocument(decoded)
	if perr != nil {
		return nil, readBody(verOp, vst)
	}
	return acts, nil
}

// actionsFromDocument extracts the Action set from a single-statement policy. The
// Action field may be a string or a []string.
func actionsFromDocument(doc string) ([]string, error) {
	var d struct {
		Statement []struct {
			Action json.RawMessage `json:"Action"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		return nil, err
	}
	if len(d.Statement) == 0 {
		return nil, fmt.Errorf("policy has no statement")
	}
	var one string
	if json.Unmarshal(d.Statement[0].Action, &one) == nil {
		return []string{one}, nil
	}
	var many []string
	if json.Unmarshal(d.Statement[0].Action, &many) == nil {
		return many, nil
	}
	return nil, fmt.Errorf("Action is neither a string nor a list")
}

func sameActionSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, y := range b {
		m[y]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

func (d *Driver) observeCustomPolicy(capability, providerID string) ([]provider.Observation, []string, error) {
	arn, err := splitCustomPolicyProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	actions, aerr := d.getCustomPolicyActions(arn)
	if aerr != nil {
		return nil, []string{"nothing to observe: " + aerr.Error()}, nil
	}
	return []provider.Observation{
		{Path: "role.permissions", Value: actions, Derivation: "measured"},
		{Path: "access.mutating", Value: awsPolicyMutating(actions), Derivation: "measured"},
		{Path: "access.privileged", Value: awsPolicyPrivileged(actions), Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}, nil, nil
}

func (d *Driver) deleteCustomPolicy(capability, environment, providerID string) provider.CreateResult {
	arn, err := splitCustomPolicyProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	st, resp, e := d.iamPost(encodeForm(map[string]string{
		"Action": "DeletePolicy", "Version": iamVersion, "PolicyArn": arn}))
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if strings.Contains(rdsErrCode(resp), "NoSuchEntity") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d (%s)", st, rdsErrCode(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
