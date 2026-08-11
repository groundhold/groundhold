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
	"sort"
	"strings"

	"errors"
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

// errPolicyAbsent marks an authoritative "the policy does not exist" from the
// IAM read, so the caller can tell it apart from a failure to read (D522).
var errPolicyAbsent = errors.New("custom policy does not exist")

// errPolicyComplement marks a policy that grants "everything EXCEPT ..." (an Allow with
// NotAction). D797: such a grant is real and WIDE, and it cannot be reduced to a list of
// actions — so observe reports privilege conservatively and withholds the list, rather
// than folding a complement into whatever actions sat beside it.
var errPolicyComplement = errors.New("policy grants a complement (Allow NotAction)")

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
	if strings.Contains(rdsErrCode(resp), "NoSuchEntity") {
		return nil, errPolicyAbsent // authoritative "gone", not a failure to read
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
	acts, complement, perr := actionsFromDocument(decoded)
	if perr != nil {
		return nil, readBody(verOp, vst)
	}
	if complement {
		// D797: "Allow everything EXCEPT ..." — real, and not a list of actions.
		return nil, errPolicyComplement
	}
	return acts, nil
}

// actionsFromDocument extracts the granted Action set from a policy document.
//
// D797. It used to read Statement[0] and nothing else — a policy document was assumed
// to be the one this driver AUTHORS (a single statement). But observe does not only see
// our policies: discoverCustomPolicies enumerates EVERY customer-managed policy in the
// account and reverse-maps each one, and a real policy routinely has several statements.
// Reading the first meant that a policy whose privileged grant lived in the second
// reported access.privileged=false — an under-report of privilege, which is the most
// dangerous direction this tool has.
//
// Three shapes have to be handled honestly rather than skipped:
//
//   - Statement may be an OBJECT, not a list. IAM accepts both. The old struct decoded
//     only a list, so a single-object policy failed to parse and the whole read errored.
//   - Effect DENY does not grant anything. Deny statements are excluded from the granted
//     set. Note the direction: ignoring the NARROWING effect a Deny has on other
//     statements over-reports privilege, and over-reporting is the safe side of a
//     security attribute.
//   - NotAction means "everything EXCEPT these", which cannot be enumerated into a list
//     of actions at all. It is reported as such by the caller (ok=false), never silently
//     folded into whatever actions happened to be listed next to it.
func actionsFromDocument(doc string) (actions []string, complement bool, err error) {
	var d struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		return nil, false, err
	}
	type stmt struct {
		Effect    string          `json:"Effect"`
		Action    json.RawMessage `json:"Action"`
		NotAction json.RawMessage `json:"NotAction"`
	}
	var stmts []stmt
	if err := json.Unmarshal(d.Statement, &stmts); err != nil {
		var one stmt
		if err2 := json.Unmarshal(d.Statement, &one); err2 != nil {
			return nil, false, fmt.Errorf("Statement is neither an object nor a list")
		}
		stmts = []stmt{one}
	}
	if len(stmts) == 0 {
		return nil, false, fmt.Errorf("policy has no statement")
	}
	seen := map[string]bool{}
	for _, s := range stmts {
		// IAM requires Effect; anything that is not an explicit Allow grants nothing.
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		if len(s.NotAction) > 0 {
			// "Allow everything except X" — not a set this driver can enumerate, and
			// assuming it is narrow would be exactly the under-report D797 fixed.
			return nil, true, nil
		}
		vals, verr := actionValues(s.Action)
		if verr != nil {
			return nil, false, verr
		}
		for _, v := range vals {
			if !seen[v] {
				seen[v] = true
				actions = append(actions, v)
			}
		}
	}
	sort.Strings(actions)
	return actions, false, nil
}

// actionValues reads an Action field, which IAM allows to be a string or a list.
func actionValues(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}, nil
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
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
	if errors.Is(aerr, errPolicyAbsent) {
		// F-LC3 (D522): GONE, said with the reserved marker.
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"custom policy not found — bound resource is gone (will re-create)"}, nil
	}
	if errors.Is(aerr, errPolicyComplement) {
		// D797: "Allow everything except X" is not narrow, and it is not enumerable.
		// Say what is known (it is wide) and withhold what is not (the exact set) —
		// silence on both would repeat D513.
		return []provider.Observation{
				{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
				{Path: "access.mutating", Value: true, Derivation: "measured"},
				{Path: "access.privileged", Value: true, Derivation: "measured"},
				{Path: "service.managed", Value: true, Derivation: "measured"},
			}, []string{"role.permissions not observed: the policy grants a COMPLEMENT " +
				"(Allow with NotAction), which is everything except a listed few — a set " +
				"this driver cannot enumerate, and one that is wide rather than narrow, so " +
				"access.mutating/privileged are reported true"}, nil
	}
	if aerr != nil {
		// D522: EVERY error used to become "nothing to observe", so a transport
		// failure read as an empty world and converge agreed with it. A failure to
		// read is not a fact about the resource — it blocks, it does not converge.
		return nil, nil, aerr
	}
	return []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
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
	// OWNERSHIP (D444): an IAM policy at an arbitrary ARN is not ours to delete. The
	// create path proves ownership by NAME plus action-set (D407); the delete had no
	// check at all and removed whatever ARN it was handed. See nameLooksOurs.
	if !nameLooksOurs(policyNameFromARN(arn), capability, environment, iamRoleBad, 8, true) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("policy %q is not named by groundhold for %s/%s — refusing "+
				"to delete a policy this contract does not own", arn, capability, environment)}
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

// policyNameFromARN takes the last path segment of an IAM policy ARN, which is the
// policy NAME (arn:aws:iam::<acct>:policy/<path...>/<name>).
func policyNameFromARN(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}
