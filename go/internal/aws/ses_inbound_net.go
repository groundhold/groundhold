// AWS SES inbound network shell (D154): the SigV4-signed, Query-protocol half of
// the AWS capability.email.inbound composite. SES receiving is the SES v1 API
// (version 2010-12-01) — a form-encoded POST to email.<region>.amazonaws.com
// (the SAME host SESv2 sending uses; the base is reused from the sending shell),
// SigV4 service "ses", XML responses. A create composes a receipt RULE inside a
// receipt RULE SET and then ACTIVATES the set — an inactive rule set receives
// nothing (the StartLogging-in-CloudTrail shape). Four-valued throughout
// (D29/D87): once the rule lands, a failed SetActiveReceiptRuleSet is unknown WITH
// the providerId (the rule exists but is inactive — nothing is received —
// reconcile), never a silent half-provision and never a bare "failed" that hides a
// standing rule. Ownership is the DETERMINISTIC rule-set + rule NAME (there are no
// tags on a receipt rule); the pid carries the exact names groundhold bound.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// sesInboundVersion is the SES v1 (receiving) API version.
const sesInboundVersion = "2010-12-01"

// sesInbCall signs and sends a SES v1 Query-protocol request. The endpoint is the
// SESv2 sending host (email.<region>.amazonaws.com) reused via d.sesBase — SES
// receiving and sending share the service endpoint; only the wire protocol differs
// (Query here vs REST-JSON there). Service "ses", signed for the region.
func (d *Driver) sesInbCall(region, action string, params map[string]string) (int, []byte, error) {
	p := map[string]string{"Action": action, "Version": sesInboundVersion}
	for k, v := range params {
		p[k] = v
	}
	return d.doSigned("POST", d.sesBase(region)+"/", "ses", region,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(encodeForm(p)))
}

// sesInbIsNotFound reports a receipt rule / rule-set that authoritatively does not
// exist (RuleDoesNotExist / RuleSetDoesNotExist) — a readable absence, not an error.
func sesInbIsNotFound(status int, body []byte) bool {
	c := rdsErrCode(body) // <Error><Code> — shared Query-protocol error shape
	return strings.Contains(c, "DoesNotExist") || strings.Contains(c, "NotFound")
}

// sesInbIsAlreadyExists reports an idempotent already-there (AlreadyExists) — a
// rule set/rule at our deterministic name from a prior partial create.
func sesInbIsAlreadyExists(status int, body []byte) bool {
	return strings.Contains(rdsErrCode(body), "AlreadyExists")
}

// sesInbRule is the projection of a receipt rule the driver reverse-maps.
type sesInbRule struct {
	Name        string   `xml:"Name"`
	Enabled     bool     `xml:"Enabled"`
	TlsPolicy   string   `xml:"TlsPolicy"`
	ScanEnabled bool     `xml:"ScanEnabled"`
	Recipients  []string `xml:"Recipients>member"`
	Actions     []struct {
		S3Action *struct {
			BucketName      string `xml:"BucketName"`
			ObjectKeyPrefix string `xml:"ObjectKeyPrefix"`
			TopicArn        string `xml:"TopicArn"`
		} `xml:"S3Action"`
	} `xml:"Actions>member"`
}

// hasS3Sink reports whether the rule delivers to a durable S3 sink — any action
// with an S3Action naming a bucket. This is the delivery.sink shape (paired with
// the rule set being active, checked separately).
func (r sesInbRule) hasS3Sink() bool {
	for _, a := range r.Actions {
		if a.S3Action != nil && a.S3Action.BucketName != "" {
			return true
		}
	}
	return false
}

// describeReceiptRule resolves one rule in a rule set. A RuleDoesNotExist /
// RuleSetDoesNotExist is found=false with a nil error (an absent rule, not a
// failure); a transport error or any other non-200 names itself (unknown —
// never a fabricated absence).
func (d *Driver) describeReceiptRule(region, ruleSet, rule string) (sesInbRule, bool, error) {
	const op = "DescribeReceiptRule"
	st, resp, err := d.sesInbCall(region, "DescribeReceiptRule", map[string]string{
		"RuleSetName": ruleSet, "RuleName": rule})
	if err != nil {
		return sesInbRule{}, false, readTransport(op, err)
	}
	if sesInbIsNotFound(st, resp) {
		return sesInbRule{}, false, nil
	}
	if st != http.StatusOK {
		return sesInbRule{}, false, readHTTP(op, st, rdsErrCode(resp))
	}
	var out struct {
		Rule sesInbRule `xml:"DescribeReceiptRuleResult>Rule"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return sesInbRule{}, false, readBody(op, st)
	}
	return out.Rule, true, nil
}

// activeReceiptRuleSetName reads the name of the region's ACTIVE receipt rule set.
// A non-nil error is a transport/HTTP/parse failure; a nil error with an empty
// name is an authoritative "no active rule set". Only ONE rule set is active per
// account+region — the pipeline receives nothing unless OUR set is the active one.
func (d *Driver) activeReceiptRuleSetName(region string) (name string, err error) {
	const op = "DescribeActiveReceiptRuleSet"
	st, resp, cerr := d.sesInbCall(region, "DescribeActiveReceiptRuleSet", nil)
	if cerr != nil {
		return "", readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return "", readHTTP(op, st, rdsErrCode(resp))
	}
	var out struct {
		Name string `xml:"DescribeActiveReceiptRuleSetResult>Metadata>Name"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return "", readBody(op, st)
	}
	return out.Name, nil
}

// receiptRuleSetRuleNames lists the rule names in a rule set (DescribeReceiptRuleSet).
// (names, found, why-not): NotFound is found=false with a nil error; a transport
// or other failure names itself.
func (d *Driver) receiptRuleSetRuleNames(region, ruleSet string) ([]string, bool, error) {
	const op = "DescribeReceiptRuleSet"
	st, resp, cerr := d.sesInbCall(region, "DescribeReceiptRuleSet", map[string]string{"RuleSetName": ruleSet})
	if cerr != nil {
		return nil, false, readTransport(op, cerr)
	}
	if sesInbIsNotFound(st, resp) {
		return nil, false, nil
	}
	if st != http.StatusOK {
		return nil, false, readHTTP(op, st, rdsErrCode(resp))
	}
	var out struct {
		Names []string `xml:"DescribeReceiptRuleSetResult>Rules>member>Name"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return nil, false, readBody(op, st)
	}
	return out.Names, true, nil
}

// createSESInbound provisions the composite (D26): ensure the receipt RULE SET,
// create the receipt RULE (recipients + TLS + scanning + the S3 sink iff a sink),
// then ACTIVATE the rule set. Four-valued: once the rule lands, a failed activation
// is unknown WITH the providerId (a rule that receives nothing until activated —
// reconcile), never a silent success and never a bare "failed". Ownership is the
// deterministic name; a rule already at our names is ours (repair the composite).
func (d *Driver) createSESInbound(region, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildSESInbound(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := sesInboundProviderID(region, plan.RuleSetName, plan.RuleName)

	// ownership pre-read: a rule at our deterministic names is ours (the NAME is the
	// marker — there are no tags). Not-found continues to a fresh create; ours-already
	// repairs a partial (re-put the rule + re-activate). Unreadable -> reconcile.
	_, found, rerr := d.describeReceiptRule(region, plan.RuleSetName, plan.RuleName)
	if rerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "pre-create read gave no answer — reconcile before provisioning: " + rerr.Error()}
	}
	if found {
		// ours (by name) — repair to the desired shape and ensure activation.
		return d.ensureSESInboundActive(region, pid, plan, true)
	}

	// (1) CreateReceiptRuleSet (idempotent: AlreadyExists is a prior partial).
	st, body, err := d.sesInbCall(region, "CreateReceiptRuleSet", map[string]string{"RuleSetName": plan.RuleSetName})
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateReceiptRuleSet outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK || sesInbIsAlreadyExists(st, body):
		// created or already there — fall through
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateReceiptRuleSet HTTP %d (server error — may have landed): %s", st, rdsErrCode(body))}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateReceiptRuleSet HTTP %d: %s", st, rdsErrCode(body))}
	}

	// (2) CreateReceiptRule. Before this lands nothing receives; a 4xx is a clean
	// refusal (failed), an err/5xx may have landed (unknown WITH the pid).
	st, body, err = d.sesInbCall(region, "CreateReceiptRule", plan.ruleParams())
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateReceiptRule outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK || sesInbIsAlreadyExists(st, body):
		// created or already there — fall through to activation
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateReceiptRule HTTP %d (server error — may have landed): %s", st, rdsErrCode(body))}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateReceiptRule HTTP %d: %s", st, rdsErrCode(body))}
	}

	// (3) SetActiveReceiptRuleSet — the crux. The rule has landed; ANY failure here
	// is unknown WITH the pid (the rule exists but is inactive — receives nothing).
	return d.setActiveOutcome(region, pid, plan.RuleSetName)
}

// ensureSESInboundActive repairs an existing rule to the desired shape
// (UpdateReceiptRule) and — when activate is set — ensures the rule set is the
// active one. The rule ALREADY exists, so every failure is unknown WITH the pid
// (a partial to reconcile), never a bare "failed" that hides the standing rule.
func (d *Driver) ensureSESInboundActive(region, pid string, plan SESInboundPlan, activate bool) provider.CreateResult {
	st, body, err := d.sesInbCall(region, "UpdateReceiptRule", plan.ruleParams())
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("rule exists but UpdateReceiptRule outcome unknown — reconcile: %v", err)}
	case st == http.StatusOK:
		// updated
	default:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("rule exists but could not be updated (HTTP %d: %s) — reconcile", st, rdsErrCode(body))}
	}
	if !activate {
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	}
	return d.setActiveOutcome(region, pid, plan.RuleSetName)
}

// setActiveOutcome issues SetActiveReceiptRuleSet and folds the result four-valued:
// a success is succeeded WITH the pid; ANY failure is unknown WITH the pid (the
// rule stands but is inactive — the pipeline receives nothing — reconcile). There
// is NO "failed" branch: the rule already exists, so a failed activation is never a
// clean nothing-happened.
func (d *Driver) setActiveOutcome(region, pid, ruleSet string) provider.CreateResult {
	st, body, err := d.sesInbCall(region, "SetActiveReceiptRuleSet", map[string]string{"RuleSetName": ruleSet})
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("rule exists but SetActiveReceiptRuleSet outcome unknown — the pipeline receives nothing until active: %v", err)}
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	default:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("rule exists but is INACTIVE — SetActiveReceiptRuleSet HTTP %d (%s); nothing is received until the rule set is activated — reconcile", st, rdsErrCode(body))}
	}
}

// observeSESInbound reverse-maps a live receipt rule to capability.email.inbound:
// spam.filtered is ScanEnabled; delivery.sink is TRUE only when the rule has an S3
// action AND our rule set is the ACTIVE one (an inactive rule receives nothing, so
// nothing is durably delivered). An unreadable rule is unknown (an error); an
// unreadable active-set read OMITS delivery.sink with a diagnostic (never a
// fabricated "not delivered").
func (d *Driver) observeSESInbound(capability, providerID string) ([]provider.Observation, []string, error) {
	region, ruleSet, rule, err := splitSESInboundProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	r, found, rerr := d.describeReceiptRule(region, ruleSet, rule)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"receipt rule not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "spam.filtered", Value: r.ScanEnabled, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	// delivery.sink needs BOTH the S3 action AND the rule set being active. An
	// unreadable active-set read is UNKNOWN: omit the attribute with a diagnostic
	// rather than fabricate "not delivered".
	activeName, activeErr := d.activeReceiptRuleSetName(region)
	if activeErr != nil {
		diags = append(diags, "delivery.sink not derivable ("+activeErr.Error()+") — omitted rather than fabricated")
	} else {
		obs = append(obs, provider.Observation{
			Path: "delivery.sink", Value: r.hasS3Sink() && activeName == ruleSet, Derivation: "measured"})
	}
	return obs, diags, nil
}

// deleteSESInbound tears the composite down, ownership-guarded by the deterministic
// NAME (there are no tags): DeleteReceiptRule, then — best-effort, non-fatal — an
// auto-delete of the rule SET iff it is one WE generated (pv- prefix), now EMPTY,
// and NOT the active set (SES refuses to delete the active rule set; leaving an
// empty inactive set is harmless). Idempotent on already-gone; a transport/5xx is
// unknown WITH the pid (reconcile), never a claimed success.
func (d *Driver) deleteSESInbound(capability, environment, providerID string) provider.CreateResult {
	// the region is read from the provider ID, which carries the authoritative location.
	region, ruleSet, rule, err := splitSESInboundProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}

	_, found, rerr := d.describeReceiptRule(region, ruleSet, rule)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	// DeleteReceiptRule. The NAME is the ownership marker — the pid carries the name
	// groundhold bound, and a foreign rule at a foreign name is never addressed here.
	st, body, err := d.sesInbCall(region, "DeleteReceiptRule", map[string]string{
		"RuleSetName": ruleSet, "RuleName": rule})
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("DeleteReceiptRule outcome unknown: %v", err)}
	case st == http.StatusOK || sesInbIsNotFound(st, body):
		// deleted or idempotent already-gone — fall through to the rule-set cleanup
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("DeleteReceiptRule HTTP %d (server error) — reconcile", st)}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("DeleteReceiptRule HTTP %d: %s", st, rdsErrCode(body))}
	}
	d.maybeDeleteEmptyRuleSet(region, ruleSet)
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// maybeDeleteEmptyRuleSet best-effort tears down a rule set WE generated once it is
// empty and inactive. Non-fatal: any ambiguity leaves the (harmless, empty) set
// standing rather than risk deleting a shared or active container.
func (d *Driver) maybeDeleteEmptyRuleSet(region, ruleSet string) {
	if !strings.HasPrefix(ruleSet, sesInboundGeneratedPrefix) {
		return // an operator-named set — never auto-deleted
	}
	names, found, rerr := d.receiptRuleSetRuleNames(region, ruleSet)
	if rerr != nil || !found || len(names) != 0 {
		return
	}
	if active, aerr := d.activeReceiptRuleSetName(region); aerr != nil || active == ruleSet {
		return // active (SES refuses to delete it) or no answer — leave it
	}
	_, _, _ = d.sesInbCall(region, "DeleteReceiptRuleSet", map[string]string{"RuleSetName": ruleSet})
}

// updateSESInbound patches a bound receiving pipeline in place (D46): spam.filtered
// and delivery.sink both re-put the whole rule (UpdateReceiptRule), and a
// delivery.sink change also re-asserts activation. Ownership is the deterministic
// NAME; the desired shape is re-derived (refuse-before-mutate) from the hash-pinned
// candidate; four-valued throughout (an ambiguous outcome is unknown WITH the pid).
func (d *Driver) updateSESInbound(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, ruleSet, rule, err := splitSESInboundProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// refuse-before-mutate: re-derive + validate the full desired shape (e.g.
	// delivery.sink=true with no s3BucketName refuses here, before any patch).
	plan, err := BuildSESInbound(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// pin the plan to the BOUND identity (the pid), not a re-derived name, so the
	// patch addresses the existing rule regardless of the generation discriminator.
	plan.RuleSetName, plan.RuleName = ruleSet, rule

	// ownership re-check: the NAME is the marker; the rule must still exist.
	_, found, rerr := d.describeReceiptRule(region, ruleSet, rule)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read gave no answer — reconcile before patching: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "receipt rule no longer exists — cannot update"}
	}

	var needRulePut, needActivate bool
	for _, path := range changes {
		switch path {
		case "spam.filtered":
			needRulePut = true
		case "delivery.sink":
			needRulePut, needActivate = true, true
		default:
			// ClassifyChange gates this (unsupported); refuse honestly rather than no-op.
			return provider.CreateResult{Status: "failed",
				Reason: "no in-place SES inbound mapping for " + path}
		}
	}
	if needRulePut {
		st, body, e := d.sesInbCall(region, "UpdateReceiptRule", plan.ruleParams())
		switch {
		case e != nil:
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("UpdateReceiptRule outcome unknown (may have landed): %v", e)}
		case st == http.StatusOK:
			// patched
		case st >= 500:
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("UpdateReceiptRule HTTP %d (server error — may have landed)", st)}
		default:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("UpdateReceiptRule HTTP %d: %s", st, rdsErrCode(body))}
		}
	}
	if needActivate {
		if res := d.setActiveOutcome(region, providerID, ruleSet); res.Status != "succeeded" {
			return res
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// discoverSESInbound enumerates the region's SES receipt rules as
// capability.email.inbound — so `discover --provider aws` surfaces a receiving
// pipeline for adoption. ListReceiptRuleSets -> DescribeReceiptRuleSet (rule names)
// -> the SAME reverse map observe uses. Per-rule-set isolation: one unreadable
// rule set never sinks the others.
func (d *Driver) discoverSESInbound(region string) ([]provider.Discovered, []string, error) {
	st, resp, err := d.sesInbCall(region, "ListReceiptRuleSets", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("ses ListReceiptRuleSets: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("ses ListReceiptRuleSets: HTTP %d: %s", st, rdsErrCode(resp))
	}
	var out struct {
		Names []string `xml:"ListReceiptRuleSetsResult>RuleSets>member>Name"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return nil, nil, readBody("ses ListReceiptRuleSets", st)
	}
	var found []provider.Discovered
	var diags []string
	for _, ruleSet := range out.Names {
		if !sesInboundNameOK.MatchString(ruleSet) {
			diags = append(diags, ruleSet+": rule-set name not representable as a providerId")
			continue
		}
		names, rsFound, rsErr := d.receiptRuleSetRuleNames(region, ruleSet)
		if rsErr != nil {
			diags = append(diags, ruleSet+": "+rsErr.Error()+" — skipped")
			continue
		}
		if !rsFound {
			diags = append(diags, ruleSet+": rule set no longer exists — skipped")
			continue
		}
		for _, rule := range names {
			if !sesInboundNameOK.MatchString(rule) {
				diags = append(diags, ruleSet+"/"+rule+": rule name not representable as a providerId")
				continue
			}
			pid := sesInboundProviderID(region, ruleSet, rule)
			obs, od, oerr := d.observeSESInbound("", pid)
			if oerr != nil {
				diags = append(diags, ruleSet+"/"+rule+": "+oerr.Error())
				continue
			}
			for _, dg := range od {
				diags = append(diags, ruleSet+"/"+rule+": "+dg)
			}
			found = append(found, provider.Discovered{
				ProviderID: pid, ResourceType: "capability.email.inbound", Observations: obs})
		}
	}
	return found, diags, nil
}
