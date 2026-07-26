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
		return nil, []string{"stream not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// a Kinesis stream is always regionally/multi-AZ replicated.
		{Path: "availability.class", Value: "regional", Derivation: "config-intent"},
	}
	if s.RetentionPeriodHours > 0 {
		obs = append(obs, provider.Observation{Path: "retention.window",
			Value: fmt.Sprintf("%dh", s.RetentionPeriodHours), Derivation: "measured"})
	}
	// KMS encryption can use the AWS-MANAGED default, which DescribeStreamSummary
	// returns as alias/aws/kinesis — not a customer key, so exclude it (else a
	// managed-key stream falsely certifies BYOK on adoption).
	if s.EncryptionType == "KMS" && s.KeyId != "" && !isAWSManagedKMSKey(s.KeyId, "kinesis") {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: true, Derivation: "measured"})
	}
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
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
