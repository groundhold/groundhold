// IAM role network shell (D121): the SigV4-signed, Query-protocol half of the AWS
// capability.identity.serviceaccount driver. IAM is GLOBAL (signed us-east-1, one
// endpoint). The role name is deterministic, so the providerId is knowable before the
// response (D29). Ownership is TAGS (returned inline by GetRole). D29/D87 honesty.
package aws

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"groundhold/internal/provider"
	"net/http"
	"net/url"
	"sort"
	"strings"
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
	// AssumeRolePolicyDocument is URL-encoded JSON. D727 reads it to answer the one
	// question a consumer of a role needs answered before handing it work: can the
	// service that must assume this role actually assume it?
	AssumeRolePolicyDocument string `xml:"AssumeRolePolicyDocument"`
}

// trustsService reports whether this role's trust policy names the given AWS service
// principal (D727). A policy this driver cannot decode returns ok=false — "we could not
// tell", which the caller must not read as "no".
func (r iamRole) trustsService(service string) (trusts bool, ok bool) {
	raw, err := url.QueryUnescape(r.AssumeRolePolicyDocument)
	if err != nil || raw == "" {
		return false, false
	}
	var doc struct {
		Statement []struct {
			Effect    string `json:"Effect"`
			Action    any    `json:"Action"`
			Principal struct {
				Service any `json:"Service"`
			} `json:"Principal"`
		} `json:"Statement"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return false, false
	}
	for _, st := range doc.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		for _, svc := range asStringList(st.Principal.Service) {
			if strings.EqualFold(svc, service) {
				return true, true
			}
		}
	}
	return false, true
}

// trustsOnlyAccountRoot reports whether every Allow statement in this role's trust
// policy names an account-root AWS principal and no service at all (D751). ok=false
// means the document could not be decoded — "we could not tell", never "no".
func (r iamRole) trustsOnlyAccountRoot() (onlyRoot bool, ok bool) {
	raw, err := url.QueryUnescape(r.AssumeRolePolicyDocument)
	if err != nil || raw == "" {
		return false, false
	}
	var doc struct {
		Statement []struct {
			Effect    string `json:"Effect"`
			Principal struct {
				Service any `json:"Service"`
				AWS     any `json:"AWS"`
			} `json:"Principal"`
		} `json:"Statement"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return false, false
	}
	sawRoot := false
	for _, st := range doc.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		if len(asStringList(st.Principal.Service)) > 0 {
			return false, true // a service can assume it; nothing to report
		}
		for _, a := range asStringList(st.Principal.AWS) {
			if strings.HasSuffix(a, ":root") {
				sawRoot = true
			}
		}
	}
	return sawRoot, true
}

// asStringList accepts the string-or-array shape IAM policy documents use throughout.
func asStringList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
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
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"role not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// an assumed role has no downloadable key.
		{Path: "key.exportable", Value: false, Derivation: "platform-invariant"},
	}
	if role.Description != "" {
		obs = append(obs, provider.Observation{Path: "display.name", Value: role.Description, Derivation: "measured"})
	}
	// D751 wrote that the trust policy is the first property of a role — "a set of
	// permissions plus who may take them" — and that the vocabulary had no attribute for
	// it, so a contract could not ask. D868 added the attribute: `trust.principals` is
	// observed below, and a contract can now constrain it. The account-root diagnostic
	// stays, because a fact with a consequence is worth naming even where a verdict now
	// exists — the attribute says WHO, the diagnostic says what that means.
	var diags []string
	// D868: WHO may assume this identity. Recorded only when the trust document decoded —
	// an empty set from an unreadable one would be the safest-looking possible answer about
	// who can pick up a role, invented out of missing data.
	if tp, ok := role.trustPrincipals(); ok {
		obs = append(obs, provider.Observation{
			Path: "trust.principals", Value: tp, Derivation: "measured"})
	} else {
		diags = append(diags, "trust.principals not observed: the role's trust policy did "+
			"not decode, so who may assume this identity was not established")
	}

	if onlyRoot, ok := role.trustsOnlyAccountRoot(); ok && onlyRoot {
		diags = append(diags, "trust policy names only the account root: no AWS service "+
			"can assume this role, and every principal in the account whose identity "+
			"policy allows sts:AssumeRole can")
	}
	return obs, diags, nil
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

// trustPrincipals renders WHO may assume this role, and under what condition, as the
// deterministic set `trust.principals` compares against (D868).
//
// The condition rides WITH the principal, and that is the whole point rather than a
// detail. D776 came from the field: a bare service principal and the same principal
// guarded by `aws:SourceAccount` are not two spellings of one trust, and a set of bare
// principals compares them equal — which records trust WEAKER than the trust that stands.
// That entry could name the divergence and could not detect it, because nothing compared
// a role's trust to anything at all.
//
// ok=false means the document did not decode — "we could not tell", never an empty set.
// An empty set from an unreadable document would be the safest-looking possible answer
// about who can assume a role, invented out of missing data (D847).
func (r iamRole) trustPrincipals() (principals []string, ok bool) {
	raw, err := url.QueryUnescape(r.AssumeRolePolicyDocument)
	if err != nil || raw == "" {
		return nil, false
	}
	var doc struct {
		Statement []struct {
			Effect    string `json:"Effect"`
			Action    any    `json:"Action"`
			Principal struct {
				Service   any `json:"Service"`
				AWS       any `json:"AWS"`
				Federated any `json:"Federated"`
			} `json:"Principal"`
			Condition map[string]map[string]any `json:"Condition"`
		} `json:"Statement"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return nil, false
	}
	seen := map[string]bool{}
	for _, st := range doc.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		// Only the statements that grant ASSUMPTION. A trust document can carry other
		// actions (sts:TagSession, sts:SetSourceIdentity) whose presence says nothing
		// about who may pick the identity up.
		assume := false
		for _, a := range asStringList(st.Action) {
			if strings.HasPrefix(strings.ToLower(a), "sts:assumerole") {
				assume = true
				break
			}
		}
		if !assume {
			continue
		}
		cond := trustConditionSuffix(st.Condition)
		for _, p := range asStringList(st.Principal.Service) {
			seen["service:"+p+cond] = true
		}
		for _, p := range asStringList(st.Principal.AWS) {
			seen[p+cond] = true // an ARN, or the bare "*" worth seeing at a glance
		}
		for _, p := range asStringList(st.Principal.Federated) {
			seen["federated:"+p+cond] = true
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, true
}

// trustConditionSuffix renders a statement's conditions as ` if k=v[,k=v]`, sorted, or ""
// when there are none. The OPERATOR is deliberately dropped: StringEquals and ArnLike on
// the same key narrow the same axis, and carrying the operator would make two spellings of
// one guard compare unequal — the mirror of the mistake this attribute exists to prevent.
func trustConditionSuffix(cond map[string]map[string]any) string {
	var parts []string
	for _, keys := range cond {
		for k, v := range keys {
			for _, s := range asStringList(v) {
				parts = append(parts, k+"="+s)
			}
		}
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	return " if " + strings.Join(parts, ",")
}
