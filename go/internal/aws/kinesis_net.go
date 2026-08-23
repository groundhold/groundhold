// Kinesis network shell (D114): the SigV4-signed, JSON-protocol half of the AWS
// capability.streaming.pipe driver. CreateStream is polled to ACTIVE, then (if the
// candidate asks) retention is raised and CMK encryption is enabled by SEPARATE
// calls — a partial there is unknown/failed WITH the pid, never a silent success.
// The stream name is deterministic (D29). Ownership is TAGS (ListTagsForStream).
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

const kinesisTarget = "Kinesis_20131202"

func (d *Driver) kinesisBase(region string) string {
	if d.KinesisBaseURL != "" {
		return d.KinesisBaseURL
	}
	return "https://kinesis." + region + ".amazonaws.com"
}

func kinesisProviderID(region, account, stream string) string {
	return "kinesis:" + region + ":" + account + ":" + stream
}

func splitKinesisProviderID(providerID string) (region, account, stream string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "kinesis" {
		return "", "", "", fmt.Errorf("providerId %q is not kinesis:region:account:stream", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !account12.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId account %q is invalid", parts[2])
	}
	if !kinesisNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId stream %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) kinesisCall(region, action, body string) (int, []byte, error) {
	h := map[string]string{
		"Content-Type": "application/x-amz-json-1.1",
		"X-Amz-Target": kinesisTarget + "." + action,
	}
	return d.doSigned("POST", d.kinesisBase(region)+"/", "kinesis", region, h, []byte(body))
}

type kinesisSummary struct {
	StreamStatus         string `json:"StreamStatus"`
	StreamARN            string `json:"StreamARN"`
	RetentionPeriodHours int    `json:"RetentionPeriodHours"`
	EncryptionType       string `json:"EncryptionType"`
	KeyId                string `json:"KeyId"`
}

func (d *Driver) describeStream(region, stream string) (kinesisSummary, bool, error) {
	const op = "DescribeStreamSummary"
	st, resp, err := d.kinesisCall(region, "DescribeStreamSummary", jsonBody(map[string]any{"StreamName": stream}))
	if err != nil {
		return kinesisSummary{}, false, readTransport(op, err)
	}
	if strings.Contains(ecsErr(resp), "ResourceNotFoundException") {
		return kinesisSummary{}, false, nil
	}
	if st != http.StatusOK {
		return kinesisSummary{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var out struct {
		StreamDescriptionSummary kinesisSummary `json:"StreamDescriptionSummary"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return kinesisSummary{}, false, readBody(op, st)
	}
	return out.StreamDescriptionSummary, true, nil
}

func (d *Driver) kinesisTags(region, stream string) (map[string]string, error) {
	const op = "ListTagsForStream"
	st, resp, err := d.kinesisCall(region, "ListTagsForStream", jsonBody(map[string]any{"StreamName": stream}))
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, ecsErr(resp))
	}
	var out struct {
		Tags []struct {
			Key   string `json:"Key"`
			Value string `json:"Value"`
		} `json:"Tags"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range out.Tags {
		m[t.Key] = t.Value
	}
	return m, nil
}

func (d *Driver) createKinesis(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildKinesis(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := kinesisProviderID(region, account, plan.Stream)
	st, resp, err := d.kinesisCall(region, "CreateStream", jsonBody(plan.createBody()))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// creating — poll below
	case strings.Contains(ecsErr(resp), "ResourceInUseException"):
		tags, terr := d.kinesisTags(region, plan.Stream)
		if terr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing stream tags gave no answer — reconcile: " + terr.Error()}
		}
		if !groundholdTagsMatch(tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a stream with this name exists and is not ours (tags do not match)"}
		}
		// ours — fall through to poll + config
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	default:
		if r := provider.MutationResult(st, ecsErr(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d (%s)", st, ecsErr(resp))}
	}

	// poll to ACTIVE
	deadline := d.Now().Add(d.PollTimeout)
	for {
		s, found, rerr := d.describeStream(region, plan.Stream)
		if rerr == nil && found && s.StreamStatus == "ACTIVE" {
			break
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "stream still creating at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}

	// ownership tags (AddTagsToStream — CreateStream takes none).
	tst, tresp, terr := d.kinesisCall(region, "AddTagsToStream", jsonBody(map[string]any{
		"StreamName": plan.Stream,
		"Tags":       map[string]any{"groundhold-capability": sanitizeTag(capability), "groundhold-environment": sanitizeTag(environment)},
	}))
	if terr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("stream created but tagging outcome unknown: %v", terr)}
	}
	if tst >= 500 {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("stream created but tagging HTTP %d (server error) — reconcile", tst)}
	}
	if tst != http.StatusOK {
		if r := provider.MutationResult(tst, ecsErr(tresp), nil, pid, "tagging"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: pid, Status: "failed", Reason: fmt.Sprintf("stream created but tagging failed: HTTP %d (%s)", tst, ecsErr(tresp))}
	}

	// retention window (IncreaseStreamRetentionPeriod — default is 24h).
	if plan.RetentionHours > 24 {
		if r := d.kinesisConfigStep(region, pid, "IncreaseStreamRetentionPeriod", map[string]any{
			"StreamName": plan.Stream, "RetentionPeriodHours": plan.RetentionHours}, "retention"); r != nil {
			return *r
		}
	}
	// CMK encryption (StartStreamEncryption).
	if plan.CMEK {
		if r := d.kinesisConfigStep(region, pid, "StartStreamEncryption", map[string]any{
			"StreamName": plan.Stream, "EncryptionType": "KMS", "KeyId": plan.KmsKeyId}, "encryption"); r != nil {
			return *r
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// kinesisConfigStep issues a post-create config call; nil = ok, non-nil = a
// terminal result WITH the pid (a partial never loses the handle).
func (d *Driver) kinesisConfigStep(region, pid, action string, body map[string]any, what string) *provider.CreateResult {
	st, resp, err := d.kinesisCall(region, action, jsonBody(body))
	if err != nil {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("stream created but %s outcome unknown: %v", what, err)}
	}
	if st >= 500 {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("stream created but %s HTTP %d (server error) — reconcile", what, st)}
	}
	if st != http.StatusOK {
		if r := provider.MutationResult(st, ecsErr(resp), nil, pid, what); r != nil {
			return r
		}
		return &provider.CreateResult{ProviderID: pid, Status: "failed", Reason: fmt.Sprintf("stream created but %s failed: HTTP %d (%s)", what, st, ecsErr(resp))}
	}
	return nil
}

func (d *Driver) observeKinesis(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, stream, err := splitKinesisProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	s, found, rerr := d.describeStream(region, stream)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"stream not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// a Kinesis stream is always regionally/multi-AZ replicated.
		{Path: "availability.class", Value: "regional", Derivation: "platform-invariant"},
	}
	if s.RetentionPeriodHours > 0 {
		obs = append(obs, provider.Observation{Path: "retention.window",
			Value: fmt.Sprintf("%dh", s.RetentionPeriodHours), Derivation: "measured"})
	}
	// KMS encryption can use the AWS-MANAGED default, which DescribeStreamSummary
	// returns as alias/aws/kinesis — not a customer key, so exclude it (else a
	// managed-key stream falsely certifies BYOK on adoption).
	obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
		Value: s.EncryptionType == "KMS" && s.KeyId != "" && !isAWSManagedKMSKey(s.KeyId, "kinesis"), Derivation: "measured"})
	return obs, nil, nil
}

func (d *Driver) deleteKinesis(capability, environment, providerID string) provider.CreateResult {
	region, _, stream, err := splitKinesisProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	_, found, rerr := d.describeStream(region, stream)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	tags, terr := d.kinesisTags(region, stream)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "stream tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, e := d.kinesisCall(region, "DeleteStream", jsonBody(map[string]any{"StreamName": stream, "EnforceConsumerDeletion": true}))
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
		if r := provider.MutationResult(st, ecsErr(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d (%s)", st, ecsErr(resp))}
	}
	// ---- poll to absence (D968 class, D979) ----
	// DeleteStream is async: the stream enters DELETING, not gone. Reporting succeeded
	// here tombstones a data-bearing stream still live. Poll describeStream to a
	// confirmed absence as the create path polls to ACTIVE; unknown on timeout keeps
	// the handle.
	deadline := d.Now().Add(d.PollTimeout)
	for {
		if _, found, rerr := d.describeStream(region, stream); rerr == nil && !found {
			return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // confirmed gone
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "stream still deleting at poll timeout — reconcile via DescribeStreamSummary"}
		}
		time.Sleep(d.PollInterval)
	}
}

// classifyKinesisChange decides whether a drift on a Kinesis stream is reconciled in place or
// replaced. Before D1211 kinesis had NO ClassifyChange, so every drift fell to the AWS driver
// default of "immutable" = replacement. That verdict was being applied to retention.window —
// and replacing a stream drops the records buffered in it and breaks every consumer, to change
// a number AWS changes online. D1211: the retention window is Increase/DecreaseStreamRetention
// Period, so it is `mutable`; everything else stays "immutable" (honest replacement).
func classifyKinesisChange(path string) (string, string) {
	switch path {
	case "retention.window":
		return "mutable", "retention.window is changed in place via Increase/Decrease" +
			"StreamRetentionPeriod — never by replacing the stream (which drops its buffered records)"
	default:
		return "immutable", fmt.Sprintf(
			"Kinesis has no in-place update path for %q — reconciling a drift is a replacement", path)
	}
}

// updateKinesis changes the retention window in place (D1211): Increase or Decrease depending on
// the direction, chosen against the stream's CURRENT retention. Ownership is re-checked by tags
// first (never touch a stream that is not ours), and a gone stream is a clean failure distinct
// from a foreign one. Four-valued: an ambiguous call keeps the deterministic providerID.
func (d *Driver) updateKinesis(capability, environment, providerID string,
	attrs map[string]any, changes []string) provider.CreateResult {
	region, _, stream, err := splitKinesisProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	summary, found, rerr := d.describeStream(region, stream)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "stream no longer exists — cannot update"}
	}
	tags, terr := d.kinesisTags(region, stream)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "stream tags do not match — refusing to update a resource that is not ours"}
	}

	for _, path := range changes {
		switch path {
		case "retention.window":
			hours, herr := durationHours(attrs["retention.window"])
			if herr != nil {
				return provider.CreateResult{Status: "failed", Reason: "retention.window: " + herr.Error()}
			}
			if hours < 24 || hours > 8760 {
				return provider.CreateResult{Status: "failed",
					Reason: fmt.Sprintf("retention.window %dh is outside the Kinesis range (24h..8760h)", hours)}
			}
			// Increase and Decrease are distinct API calls; pick against the stream's current
			// window. Equal is a no-op — never issue a call AWS would reject as no change.
			action := ""
			switch {
			case hours > summary.RetentionPeriodHours:
				action = "IncreaseStreamRetentionPeriod"
			case hours < summary.RetentionPeriodHours:
				action = "DecreaseStreamRetentionPeriod"
			}
			if action == "" {
				continue
			}
			st, resp, cerr := d.kinesisCall(region, action, jsonBody(map[string]any{
				"StreamName": stream, "RetentionPeriodHours": hours}))
			switch {
			case cerr != nil:
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: fmt.Sprintf("%s outcome unknown (may have landed): %v", action, cerr)}
			case st == http.StatusOK:
				// Accepted, NOT applied. Increase/DecreaseStreamRetentionPeriod is async:
				// the stream enters UPDATING carrying the OLD window and only reaches the new
				// one on the way back to ACTIVE. Field validation (D1211) caught this driver
				// reporting succeeded during UPDATING at 24h while the target was 48h — a
				// false-green a converge would tombstone as applied. Poll to the applied
				// window before succeeding (D953 poll-to-applied, as the create path polls to
				// ACTIVE); unknown on timeout keeps the handle for reconcile.
				deadline := d.Now().Add(d.PollTimeout)
				for {
					cur, found, rerr := d.describeStream(region, stream)
					if rerr == nil && found && cur.StreamStatus == "ACTIVE" && cur.RetentionPeriodHours == hours {
						break // window applied
					}
					if d.Now().After(deadline) {
						return provider.CreateResult{ProviderID: providerID, Status: "unknown",
							Reason: fmt.Sprintf("%s accepted but stream not yet at %dh at poll "+
								"timeout — reconcile via DescribeStreamSummary", action, hours)}
					}
					time.Sleep(d.PollInterval)
				}
			case st >= 500:
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: fmt.Sprintf("%s HTTP %d (server error — may have landed) — reconcile", action, st)}
			default:
				if r := provider.MutationResult(st, ecsErr(resp), nil, providerID, action); r != nil {
					return *r
				}
				return provider.CreateResult{Status: "failed",
					Reason: fmt.Sprintf("%s HTTP %d: %s", action, st, ecsErr(resp))}
			}
		default:
			return provider.CreateResult{Status: "failed",
				Reason: "no kinesis in-place mapping for " + path}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
