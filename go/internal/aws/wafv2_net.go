// WAFv2 network shell (D116): the SigV4-signed, JSON-protocol half of the AWS
// capability.security.waf driver. A CLOUDFRONT-scope WebACL is global and served
// by the us-east-1 endpoint. The WebACL Id + LockToken are SERVER-ASSIGNED, but the
// name is deterministic, so the providerId is the name (D29) and Id/ARN/LockToken
// are resolved by ListWebACLs. Ownership is TAGS. D29/D87 honesty throughout.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

const wafTarget = "AWSWAF_20190729"

// wafRegion is the endpoint region for CLOUDFRONT-scope WAFv2 (always us-east-1).
const wafRegion = "us-east-1"

func (d *Driver) wafBase() string {
	if d.WAFBaseURL != "" {
		return d.WAFBaseURL
	}
	return "https://wafv2." + wafRegion + ".amazonaws.com"
}

func wafProviderID(account, name string) string {
	return "waf:" + account + ":" + name
}

func splitWAFProviderID(providerID string) (account, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "waf" {
		return "", "", fmt.Errorf("providerId %q is not waf:account:name", providerID)
	}
	if !account12.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId account %q is invalid", parts[1])
	}
	if !wafNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId name %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

func (d *Driver) wafCall(action, body string) (int, []byte, error) {
	h := map[string]string{
		"Content-Type": "application/x-amz-json-1.1",
		"X-Amz-Target": wafTarget + "." + action,
	}
	return d.doSigned("POST", d.wafBase()+"/", "wafv2", wafRegion, h, []byte(body))
}

type wafSummary struct {
	Name      string `json:"Name"`
	Id        string `json:"Id"`
	ARN       string `json:"ARN"`
	LockToken string `json:"LockToken"`
}

// wafListByName resolves the WebACL our deterministic name identifies (ListWebACLs
// returns Id, ARN and LockToken inline). found=false + readable=true is
// authoritative "does not exist".
func (d *Driver) wafListByName(name string) (wafSummary, bool, error) {
	const op = "ListWebACLs"
	st, resp, err := d.wafCall("ListWebACLs", jsonBody(map[string]any{"Scope": "CLOUDFRONT", "Limit": 100}))
	if err != nil || st != http.StatusOK {
		return wafSummary{}, false, readTransport(op, err)
	}
	var out struct {
		WebACLs []wafSummary `json:"WebACLs"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return wafSummary{}, false, readBody(op, st)
	}
	for _, s := range out.WebACLs {
		if s.Name == name {
			return s, true, nil
		}
	}
	return wafSummary{}, false, nil
}

type wafACL struct {
	DefaultAction map[string]any `json:"DefaultAction"`
	Rules         []struct {
		Statement struct {
			ManagedRuleGroupStatement struct {
				Name string `json:"Name"`
			} `json:"ManagedRuleGroupStatement"`
		} `json:"Statement"`
		OverrideAction map[string]any `json:"OverrideAction"`
	} `json:"Rules"`
}

func (d *Driver) wafGet(name, id string) (wafACL, error) {
	const op = "GetWebACL"
	st, resp, cerr := d.wafCall("GetWebACL", jsonBody(map[string]any{"Name": name, "Scope": "CLOUDFRONT", "Id": id}))
	if cerr != nil {
		return wafACL{}, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return wafACL{}, readHTTP(op, st, ecsErr(resp))
	}
	var out struct {
		WebACL wafACL `json:"WebACL"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return wafACL{}, readBody(op, st)
	}
	return out.WebACL, nil
}

func (d *Driver) wafTags(arn string) (map[string]string, error) {
	const op = "ListTagsForResource"
	st, resp, err := d.wafCall("ListTagsForResource", jsonBody(map[string]any{"ResourceARN": arn}))
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, ecsErr(resp))
	}
	var out struct {
		TagInfoForResource struct {
			TagList []struct {
				Key   string `json:"Key"`
				Value string `json:"Value"`
			} `json:"TagList"`
		} `json:"TagInfoForResource"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range out.TagInfoForResource.TagList {
		m[t.Key] = t.Value
	}
	return m, nil
}

// wafErr pulls a message/type out of a WAFv2 JSON error body.
func wafErr(body []byte) string {
	var e struct {
		Type    string `json:"__type"`
		Message string `json:"message"`
		Msg     string `json:"Message"`
	}
	_ = json.Unmarshal(body, &e)
	s := strings.TrimSpace(e.Type + " " + e.Message + " " + e.Msg)
	if s == "" {
		return "" // D309: never the raw body — this string reaches a persisted receipt
	}
	return boundMsg(s)
}

func (d *Driver) createWAF(account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildWAF(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := wafProviderID(account, plan.Name)
	st, resp, err := d.wafCall("CreateWebACL", jsonBody(plan.createBody(capability, environment)))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case strings.Contains(wafErr(resp), "WAFDuplicateItem"):
		s, found, rerr := d.wafListByName(plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing WebACL gave no answer — reconcile: " + rerr.Error()}
		}
		if !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "name conflict but not found — reconcile"}
		}
		tags, terr := d.wafTags(s.ARN)
		if terr != nil || !groundholdTagsMatch(tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a WebACL with this name exists and is not ours (tags do not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // ours, present
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	default:
		if r := provider.MutationResult(st, wafErr(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d (%s)", st, wafErr(resp))}
	}
}

func (d *Driver) observeWAF(capability, providerID string) ([]provider.Observation, []string, error) {
	_, name, err := splitWAFProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	s, found, rerr := d.wafListByName(name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"WebACL not found — nothing to observe"}, nil
	}
	acl, gerr := d.wafGet(name, s.Id)
	if gerr != nil {
		return nil, nil, gerr
	}
	managed, bot, prevention := false, false, true
	for _, r := range acl.Rules {
		switch r.Statement.ManagedRuleGroupStatement.Name {
		case "AWSManagedRulesCommonRuleSet":
			managed = true
		case "AWSManagedRulesBotControlRuleSet":
			bot = true
		}
		if _, count := r.OverrideAction["Count"]; count {
			prevention = false // any managed group in Count => detection mode
		}
	}
	mode := "prevention"
	if !prevention {
		mode = "detection"
	}
	return []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "policy.mode", Value: mode, Derivation: "measured"},
		{Path: "managed.ruleset", Value: managed, Derivation: "measured"},
		{Path: "bot.protection", Value: bot, Derivation: "measured"},
	}, nil, nil
}

func (d *Driver) deleteWAF(capability, environment, providerID string) provider.CreateResult {
	_, name, err := splitWAFProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	s, found, rerr := d.wafListByName(name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	tags, terr := d.wafTags(s.ARN)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "WebACL tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, e := d.wafCall("DeleteWebACL", jsonBody(map[string]any{
		"Name": name, "Scope": "CLOUDFRONT", "Id": s.Id, "LockToken": s.LockToken}))
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if strings.Contains(wafErr(resp), "WAFNonexistentItem") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		if r := provider.MutationResult(st, wafErr(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d (%s)", st, wafErr(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
