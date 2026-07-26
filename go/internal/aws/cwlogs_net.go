// CloudWatch Logs log group network shell: the SigV4-signed, JSON-1.1 half of the AWS
// capability.monitoring.logs driver. It reuses the same endpoint/call helpers as the
// metric-filter driver (logsBase / logsCall, X-Amz-Target Logs_20140328). A create is
// a COMPOSITE: CreateLogGroup (+ ownership tags) then PutRetentionPolicy (a group
// without a retention policy never expires — cost + an unstated compliance posture),
// then AssociateKmsKey iff a customer key was asked. The name is deterministic (or a
// pinned operand), so the providerId is knowable BEFORE the response (D29/D87) and
// rides every ambiguous outcome. Ownership is CloudWatch Logs tags, read via
// ListTagsForResource against the group's own ARN (returned by DescribeLogGroups, so
// the account never has to be resolved separately). Delete is ownership-tag-gated and
// four-valued; a log group HOLDS logs, so retirement is conservative (D47, stateful).
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func cwLogsProviderID(region, logGroup string) string {
	return "cwlogs:" + region + ":" + logGroup
}

func splitCWLogsProviderID(providerID string) (region, logGroup string, err error) {
	// a log group name never contains a colon (logGroupOK excludes it), so a 3-way
	// split is unambiguous.
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "cwlogs" {
		return "", "", fmt.Errorf("providerId %q is not cwlogs:region:logGroupName", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !logGroupOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId log group %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

type cwLogGroupDesc struct {
	LogGroupName    string `json:"logGroupName"`
	RetentionInDays int    `json:"retentionInDays"`
	Arn             string `json:"arn"`
	KmsKeyId        string `json:"kmsKeyId"`
	StoredBytes     int64  `json:"storedBytes"`
}

// describeCWLogGroup reads one log group by EXACT name (DescribeLogGroups is a
// prefix search, so a returned group whose name is not exactly ours is not a match).
// found=false + readable=true is an authoritative "does not exist"; readable=false is
// a transport/HTTP/parse failure.
func (d *Driver) describeCWLogGroup(region, name string) (cwLogGroupDesc, bool, error) {
	const op = "DescribeLogGroups"
	body, _ := json.Marshal(map[string]any{"logGroupNamePrefix": name})
	st, resp, err := d.logsCall(region, "DescribeLogGroups", string(body))
	if err != nil {
		return cwLogGroupDesc{}, false, readTransport(op, err)
	}
	if st != http.StatusOK {
		return cwLogGroupDesc{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var r struct {
		LogGroups []cwLogGroupDesc `json:"logGroups"`
	}
	if json.Unmarshal(resp, &r) != nil {
		return cwLogGroupDesc{}, false, readBody(op, st)
	}
	for _, g := range r.LogGroups {
		if g.LogGroupName == name {
			return g, true, nil
		}
	}
	return cwLogGroupDesc{}, false, nil
}

// stripLogGroupArnWildcard turns the DescribeLogGroups arn (…:log-group:name:*) into
// the tagging/RGT resource arn (…:log-group:name) ListTagsForResource expects.
func stripLogGroupArnWildcard(arn string) string {
	return strings.TrimSuffix(arn, ":*")
}

// cwlogsTags reads ownership tags via ListTagsForResource against the group ARN.
// ok=false on any transport/HTTP/parse failure (never treated as "not ours" for a
// destructive act).
func (d *Driver) cwlogsTags(region, arn string) (map[string]string, error) {
	const op = "ListTagsForResource"
	body, _ := json.Marshal(map[string]any{"resourceArn": stripLogGroupArnWildcard(arn)})
	st, resp, err := d.logsCall(region, "ListTagsForResource", string(body))
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, ecsErr(resp))
	}
	var r struct {
		Tags map[string]string `json:"tags"`
	}
	if json.Unmarshal(resp, &r) != nil {
		return nil, readBody(op, st)
	}
	return r.Tags, nil
}

// createCWLogs is the composite: CreateLogGroup (+tags) -> PutRetentionPolicy ->
// AssociateKmsKey (iff CMK). The name is deterministic/pinned so the pid is known
// before the response and rides every ambiguous outcome (D29/D87). An existing group
// at our name is honored only if its ownership tags match (else refuse).
func (d *Driver) createCWLogs(region, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildCWLogs(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if plan.Region != "" {
		region = plan.Region
	}
	pid := cwLogsProviderID(region, plan.LogGroupName)

	// ---- CreateLogGroup ----
	body, _ := json.Marshal(plan.createBody(capability, environment))
	st, resp, err := d.logsCall(region, "CreateLogGroup", string(body))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateLogGroup outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// created — fall through to retention
	case strings.Contains(ecsErr(resp), "ResourceAlreadyExists"):
		// a group at our name exists. Confirm it is ours by its tags before we
		// (idempotently) re-assert retention/encryption on it.
		desc, found, rerr := d.describeCWLogGroup(region, plan.LogGroupName)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing log group gave no answer — reconcile: " + rerr.Error()}
		}
		if !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "AlreadyExists reported but log group not found on re-read — reconcile"}
		}
		tags, terr := d.cwlogsTags(region, desc.Arn)
		if terr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing log group tags gave no answer — reconcile: " + terr.Error()}
		}
		if !groundholdTagsMatch(tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a log group with this name exists and is not ours (tags do not match)"}
		}
		// ours — fall through to (idempotently) ensure retention + encryption
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateLogGroup HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateLogGroup HTTP %d: %s", st, ecsErr(resp))}
	}

	// ---- PutRetentionPolicy (the whole point — a group with no policy never expires) ----
	rbody, _ := json.Marshal(map[string]any{
		"logGroupName": plan.LogGroupName, "retentionInDays": plan.RetentionDays})
	st, resp, err = d.logsCall(region, "PutRetentionPolicy", string(rbody))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "log group created; retention policy outcome unknown — reconcile"}
	case st == http.StatusOK:
		// retention enforced
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("log group created; PutRetentionPolicy HTTP %d (server error) — reconcile", st)}
	default:
		return provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("log group created but retention NOT enforced: PutRetentionPolicy HTTP %d (%s)", st, ecsErr(resp))}
	}

	// ---- AssociateKmsKey (iff a customer key was asked) ----
	if plan.CMK {
		kbody, _ := json.Marshal(map[string]any{
			"logGroupName": plan.LogGroupName, "kmsKeyId": plan.KmsKeyArn})
		st, resp, err = d.logsCall(region, "AssociateKmsKey", string(kbody))
		switch {
		case err != nil:
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "log group + retention created; CMK association outcome unknown — reconcile"}
		case st == http.StatusOK:
			// encrypted with the customer key
		case st >= 500:
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("log group created; AssociateKmsKey HTTP %d (server error) — reconcile", st)}
		default:
			return provider.CreateResult{ProviderID: pid, Status: "failed",
				Reason: fmt.Sprintf("log group created but CMK NOT associated: AssociateKmsKey HTTP %d (%s)", st, ecsErr(resp))}
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// observeCWLogs reverse-maps a live log group: location.region, retention.days
// (retentionInDays -> a duration), encryption.customerManagedKeys (a kmsKeyId is
// present ONLY when a customer key is associated — CloudWatch Logs' default
// encryption exposes no key id, so kmsKeyId present is honestly CMK=true) and
// service.managed. A group with no retentionInDays keeps logs forever; that is a real
// (unbounded) posture, so retention.days is simply not emitted rather than faked.
func (d *Driver) observeCWLogs(capability, providerID string) ([]provider.Observation, []string, error) {
	region, name, err := splitCWLogsProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	desc, found, rerr := d.describeCWLogGroup(region, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"log group not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if desc.RetentionInDays > 0 {
		obs = append(obs, provider.Observation{Path: "retention.days",
			Value: fmt.Sprintf("%dh", desc.RetentionInDays*24), Derivation: "measured"})
	}
	if strings.TrimSpace(desc.KmsKeyId) != "" {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
			Value: true, Derivation: "measured"})
	}
	return obs, nil, nil
}

// updateCWLogs patches a log group IN PLACE for the mutable paths (D46):
// retention.days via PutRetentionPolicy, encryption.customerManagedKeys via
// AssociateKmsKey / DisassociateKmsKey. Ownership is re-checked (tags) BEFORE any
// mutation; unreadable -> unknown, vanished -> failed. An ambiguous outcome
// (transport / 5xx) is unknown WITH the providerId; a 4xx is failed.
func (d *Driver) updateCWLogs(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, name, err := splitCWLogsProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	plan, err := BuildCWLogs(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// pin the identity groundhold bound (carried in the pid), not a re-derived name.
	plan.LogGroupName = name

	// ownership re-check via the group's own ARN.
	desc, found, rerr := d.describeCWLogGroup(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed",
			Reason: "log group to update no longer exists — reconcile"}
	}
	tags, terr := d.cwlogsTags(region, desc.Arn)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "ownership tags gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "log group tags do not match — refusing to update a resource that is not ours"}
	}

	for _, path := range changes {
		switch path {
		case "retention.days":
			rbody, _ := json.Marshal(map[string]any{
				"logGroupName": name, "retentionInDays": plan.RetentionDays})
			st, resp, cerr := d.logsCall(region, "PutRetentionPolicy", string(rbody))
			if r := cwLogsPatchOutcome("set retention", providerID, st, resp, cerr); r != nil {
				return *r
			}
		case "encryption.customerManagedKeys":
			if plan.CMK {
				kbody, _ := json.Marshal(map[string]any{
					"logGroupName": name, "kmsKeyId": plan.KmsKeyArn})
				st, resp, cerr := d.logsCall(region, "AssociateKmsKey", string(kbody))
				if r := cwLogsPatchOutcome("associate CMK", providerID, st, resp, cerr); r != nil {
					return *r
				}
			} else {
				st, resp, cerr := d.logsCall(region, "DisassociateKmsKey",
					string(mustJSON(map[string]any{"logGroupName": name})))
				if r := cwLogsPatchOutcome("disassociate CMK", providerID, st, resp, cerr); r != nil {
					return *r
				}
			}
		default:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("cloudwatch logs in-place update does not honor %q — reconcile", path)}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// cwLogsPatchOutcome folds one patch call into the four-valued shape: nil = keep
// going (HTTP 200), non-nil = terminal. Ambiguous (transport / 5xx) is unknown WITH
// the providerId; a 4xx is failed.
func cwLogsPatchOutcome(what, providerID string, st int, resp []byte, err error) *provider.CreateResult {
	switch {
	case err != nil:
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("%s outcome unknown (may have landed): %v", what, err)}
	case st == http.StatusOK:
		return nil
	case st >= 500:
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("%s HTTP %d (server error — may have landed) — reconcile", what, st)}
	default:
		return &provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("%s HTTP %d (%s)", what, st, ecsErr(resp))}
	}
}

func mustJSON(m map[string]any) []byte {
	b, _ := json.Marshal(m)
	return b
}

// classifyCWLogsChange answers, per attribute, whether CloudWatch Logs can honor the
// transition IN PLACE (D46) — PURE provider knowledge, no network. retention.days is
// PutRetentionPolicy (mutable); CMK is Associate/DisassociateKmsKey (mutable — an
// updater is wired, so this is never a mutable-without-updater lie); the region is the
// group's fixed home (a change is a replacement).
func classifyCWLogsChange(path string) (string, string) {
	switch path {
	case "retention.days":
		return "mutable", "" // PutRetentionPolicy
	case "encryption.customerManagedKeys":
		return "mutable", "" // AssociateKmsKey / DisassociateKmsKey in place
	case "location.region":
		return "immutable", "a log group lives in one region — moving it is a replacement"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no CloudWatch Logs in-place mapping for " + path
	}
}

// deleteCWLogs is ownership-tag-gated (D47, stateful — a log group HOLDS logs, so
// destroying it loses history) and four-valued. A missing group is an idempotent
// success; a tag mismatch refuses (never delete a foreign group); an ambiguous
// outcome is unknown WITH the pid.
func (d *Driver) deleteCWLogs(capability, environment, providerID string) provider.CreateResult {
	region, name, err := splitCWLogsProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	desc, found, rerr := d.describeCWLogGroup(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	tags, terr := d.cwlogsTags(region, desc.Arn)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "ownership tags gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "log group tags do not match — refusing to delete a resource that is not ours (its logs are data)"}
	}
	body, _ := json.Marshal(map[string]any{"logGroupName": name})
	st, resp, err := d.logsCall(region, "DeleteLogGroup", string(body))
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if st == http.StatusOK || strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	return provider.CreateResult{Status: "failed",
		Reason: fmt.Sprintf("delete HTTP %d: %s", st, ecsErr(resp))}
}

// discoverCWLogs enumerates the region's log groups as capability.monitoring.logs,
// each reverse-mapped by the SAME observeCWLogs. DescribeLogGroups is region-scoped;
// discovery lists ALL groups (brownfield is honest about what exists — the AWS-native
// groups whose retention Acme wants to govern, e.g. VPC flow logs / EKS control
// plane), and observe maps each. Per-group isolation: one unmappable name never sinks
// the sweep.
func (d *Driver) discoverCWLogs(region string) ([]provider.Discovered, []string, error) {
	var out []provider.Discovered
	var diags []string
	var nextToken string
	for {
		req := map[string]any{}
		if nextToken != "" {
			req["nextToken"] = nextToken
		}
		body, _ := json.Marshal(req)
		st, resp, err := d.logsCall(region, "DescribeLogGroups", string(body))
		if err != nil {
			return nil, nil, fmt.Errorf("cwlogs DescribeLogGroups: %v", err)
		}
		if st != http.StatusOK {
			return nil, nil, fmt.Errorf("cwlogs DescribeLogGroups: HTTP %d (%s)", st, ecsErr(resp))
		}
		var r struct {
			LogGroups []cwLogGroupDesc `json:"logGroups"`
			NextToken string           `json:"nextToken"`
		}
		if json.Unmarshal(resp, &r) != nil {
			return nil, nil, readBody("cwlogs DescribeLogGroups", st)
		}
		for _, g := range r.LogGroups {
			if !logGroupOK.MatchString(g.LogGroupName) {
				diags = append(diags, g.LogGroupName+": name not representable as a providerId")
				continue
			}
			pid := cwLogsProviderID(region, g.LogGroupName)
			obs, odiags, oerr := d.observeCWLogs("", pid)
			if oerr != nil {
				diags = append(diags, g.LogGroupName+": "+oerr.Error())
				continue
			}
			for _, dg := range odiags {
				diags = append(diags, g.LogGroupName+": "+dg)
			}
			out = append(out, provider.Discovered{
				ProviderID:   pid,
				ResourceType: "capability.monitoring.logs",
				Observations: obs,
			})
		}
		if r.NextToken == "" {
			break
		}
		nextToken = r.NextToken
	}
	return out, diags, nil
}
