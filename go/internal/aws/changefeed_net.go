// EventBridge change-feed network shell (D143): the SigV4-signed, JSON-protocol
// (X-Amz-Target: AWSEvents.<Action>) half of the AWS capability.observability.changefeed
// driver. The endpoint is events.<region>.amazonaws.com; the signing service is "events".
// A feed is two resources — a rule (PutRule) and its target (PutTargets) — so a create is
// two mutating calls: the rule landing but the target attach failing is unknown WITH the
// pid, never a silent success. The rule name is deterministic, so the pid is knowable
// before the response (D29). Ownership is the Description marker, read back via
// DescribeRule. D29/D87 honesty throughout.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

const eventsTarget = "AWSEvents"

func (d *Driver) eventsBase(region string) string {
	if d.EventBridgeBaseURL != "" {
		return d.EventBridgeBaseURL
	}
	return "https://events." + region + ".amazonaws.com"
}

// eventsCall signs and sends a JSON-protocol EventBridge request (X-Amz-Target).
func (d *Driver) eventsCall(region, action, body string) (int, []byte, error) {
	h := map[string]string{
		"Content-Type": "application/x-amz-json-1.1",
		"X-Amz-Target": eventsTarget + "." + action,
	}
	return d.doSigned("POST", d.eventsBase(region)+"/", "events", region, h, []byte(body))
}

func changefeedProviderID(region, rule string) string { return "eventbridge:" + region + ":" + rule }

func splitChangefeedProviderID(providerID string) (region, rule string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "eventbridge" {
		return "", "", fmt.Errorf("providerId %q is not eventbridge:region:rule", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !cfRuleNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId rule %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

type cfRuleDoc struct {
	Name         string `json:"Name"`
	Arn          string `json:"Arn"`
	State        string `json:"State"`
	Description  string `json:"Description"`
	EventPattern string `json:"EventPattern"`
}

type cfTarget struct {
	Id  string `json:"Id"`
	Arn string `json:"Arn"`
}

// describeRule reads a rule. found=false + readable=true is an authoritative "does not
// exist" (EventBridge returns ResourceNotFoundException as an HTTP 400, so the error
// string is checked BEFORE the status); readable=false is transport/HTTP/parse failure.
func (d *Driver) describeRule(region, name string) (cfRuleDoc, bool, error) {
	const op = "DescribeRule"
	st, resp, err := d.eventsCall(region, "DescribeRule", jsonBody(map[string]any{"Name": name}))
	if err != nil {
		return cfRuleDoc{}, false, readTransport(op, err)
	}
	if strings.Contains(ecsErr(resp), "ResourceNotFoundException") {
		return cfRuleDoc{}, false, nil
	}
	if st != http.StatusOK {
		return cfRuleDoc{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var doc cfRuleDoc
	if json.Unmarshal(resp, &doc) != nil {
		return cfRuleDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

// listRuleTargets reads the rule's targets. found=false + readable=true is "rule/targets
// absent"; readable=false is a transport/HTTP/parse failure.
func (d *Driver) listRuleTargets(region, rule string) ([]cfTarget, bool, error) {
	const op = "ListTargetsByRule"
	st, resp, cerr := d.eventsCall(region, "ListTargetsByRule", jsonBody(map[string]any{"Rule": rule}))
	if cerr != nil {
		return nil, false, readTransport(op, cerr)
	}
	if strings.Contains(ecsErr(resp), "ResourceNotFoundException") {
		return nil, false, nil
	}
	if st != http.StatusOK {
		return nil, false, readHTTP(op, st, ecsErr(resp))
	}
	var out struct {
		Targets []cfTarget `json:"Targets"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return nil, false, readBody(op, st)
	}
	return out.Targets, len(out.Targets) > 0, nil
}

// cfFailedEntryCount pulls the FailedEntryCount from a PutTargets/RemoveTargets response.
// A 200 with FailedEntryCount > 0 is a PARTIAL failure, not a success — the entry the
// service rejected (e.g. an unreachable target) must not be reported as landed.
func cfFailedEntryCount(resp []byte) int {
	var out struct {
		FailedEntryCount int `json:"FailedEntryCount"`
	}
	_ = json.Unmarshal(resp, &out)
	return out.FailedEntryCount
}

func (d *Driver) createChangeFeed(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildChangeFeed(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	region := plan.Region // derived from the feed.target ARN
	pid := changefeedProviderID(region, plan.RuleName)

	// ownership pre-read: PutRule is an UPSERT (it overwrites an existing rule at our
	// name), so refuse to clobber a foreign rule at our deterministic name.
	doc, found, rerr := d.describeRule(region, plan.RuleName)
	if rerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "pre-create ownership read gave no answer — reconcile before overwriting: " + rerr.Error()}
	}
	if found && !awsMarkerOurs(doc.Description, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "a rule with this name exists and is not ours (marker does not match)"}
	}

	// PutRule (create-or-update the matching rule).
	st, resp, err := d.eventsCall(region, "PutRule", jsonBody(plan.putRuleBody(capability, environment)))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("PutRule outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// rule landed — attach the target below.
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("PutRule HTTP %d (server error — may have landed): %s", st, ecsErr(resp))}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("PutRule HTTP %d: %s", st, ecsErr(resp))}
	}

	// PutTargets (attach the feed.target queue). The rule already landed, so any
	// ambiguity here is unknown WITH the pid — the feed is half-built, reconcile.
	st, resp, err = d.eventsCall(region, "PutTargets", jsonBody(plan.putTargetsBody()))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("rule created but target attach outcome unknown: %v", err)}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("rule created but PutTargets HTTP %d (server error) — reconcile", st)}
	case st != http.StatusOK:
		return provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("rule created but attaching the feed target failed: HTTP %d: %s", st, ecsErr(resp))}
	}
	if n := cfFailedEntryCount(resp); n > 0 {
		return provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("rule created but the feed target was rejected (FailedEntryCount=%d) — "+
				"the target queue must exist and allow events.amazonaws.com to send", n)}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

func (d *Driver) observeChangeFeed(capability, providerID string) ([]provider.Observation, []string, error) {
	region, name, err := splitChangefeedProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	_, found, rerr := d.describeRule(region, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"rule not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	// reverse-map feed.target from the attached target — the capability's core semantic.
	targets, hasTargets, terr := d.listRuleTargets(region, name)
	if terr != nil {
		diags = append(diags, "feed.target not observed this cycle: "+terr.Error())
	} else if !hasTargets {
		diags = append(diags, "rule has no target — feed captures events but delivers them nowhere")
	} else {
		obs = append(obs, provider.Observation{Path: "feed.target", Value: targets[0].Arn, Derivation: "measured"})
	}
	return obs, diags, nil
}

func (d *Driver) deleteChangeFeed(capability, environment, providerID string) provider.CreateResult {
	region, name, err := splitChangefeedProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.describeRule(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !awsMarkerOurs(doc.Description, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "rule marker does not match — refusing to delete a resource that is not ours"}
	}

	// a rule cannot be deleted while it still has targets — RemoveTargets first.
	targets, hasTargets, terr := d.listRuleTargets(region, name)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete target list gave no answer — reconcile: " + terr.Error()}
	}
	if hasTargets {
		ids := make([]string, 0, len(targets))
		for _, t := range targets {
			ids = append(ids, t.Id)
		}
		st, resp, e := d.eventsCall(region, "RemoveTargets", jsonBody(map[string]any{"Rule": name, "Ids": ids}))
		switch {
		case e != nil:
			return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("RemoveTargets outcome unknown: %v", e)}
		case strings.Contains(ecsErr(resp), "ResourceNotFoundException"):
			// rule/targets already gone — fall through to DeleteRule (idempotent).
		case st >= 500:
			return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("RemoveTargets HTTP %d (server error) — reconcile", st)}
		case st != http.StatusOK:
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("RemoveTargets HTTP %d: %s", st, ecsErr(resp))}
		default:
			if n := cfFailedEntryCount(resp); n > 0 {
				return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("RemoveTargets left %d entries (partial) — reconcile before deleting the rule", n)}
			}
		}
	}

	st, resp, e := d.eventsCall(region, "DeleteRule", jsonBody(map[string]any{"Name": name}))
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if strings.Contains(ecsErr(resp), "ResourceNotFoundException") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, ecsErr(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
