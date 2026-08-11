// SQS network shell (D95): the SigV4-signed half of the AWS messaging.queue
// driver. A queue is regional and its URL is deterministic from
// (region, account, name), so the handle is knowable BEFORE the create response
// — a lost/garbled outcome (D29) always carries the pid. Ownership is TAGS
// (applied at CreateQueue birth); a queue name is scoped to the account+region
// (no global namespace, so no D82 cross-account squat concern, unlike S3).
// Every attribute (retention, encryption, dedup, the public policy) is set at
// CreateQueue time, so the create sequence is short: CreateQueue (+attrs+tags)
// -> ownership re-check.
package aws

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

const sqsVersion = "2012-11-05"

func (d *Driver) sqsBase(region string) string {
	if d.SQSBaseURL != "" {
		return d.SQSBaseURL
	}
	return "https://sqs." + region + ".amazonaws.com"
}

// sqsARN assembles the queue ARN. v0 targets the standard "aws" partition.
func sqsARN(region, account, name string) string {
	return "arn:aws:sqs:" + region + ":" + account + ":" + name
}

// sqsQueueURL is the queue URL SQS assigns — deterministic from base+account+
// name, so it never needs to be parsed out of the (opaque) CreateQueue response.
func sqsQueueURL(base, account, name string) string {
	return base + "/" + account + "/" + name
}

func sqsProviderID(region, account, name string) string {
	return "sqs:" + region + ":" + account + ":" + name
}

// splitSQSProviderID validates every component before it is interpolated into a
// URL path (D73 boundary). The account rides in the id so observe/delete rebuild
// the URL with no STS call.
func splitSQSProviderID(providerID string) (region, account, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "sqs" {
		return "", "", "", fmt.Errorf("providerId %q is not sqs:region:account:name", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !account12.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId account %q is invalid", parts[2])
	}
	if !sqsNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId queue name %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

// sqsPost signs (region-scoped) and sends a Query-protocol POST.
func (d *Driver) sqsPost(region, body string) (int, []byte, error) {
	return d.doSigned("POST", d.sqsBase(region)+"/", "sqs", region,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(body))
}

// createSQS: CreateQueue (all attributes + ownership tags in one call), then an
// ownership re-check. A same-account queue with this name that is NOT ours
// (foreign tags) is refused; an untagged one is unknown (reconcile), never
// silently taken over (mirrors S3/SNS).
func (d *Driver) createSQS(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildSQSCreate(account, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	arn := sqsARN(region, account, plan.Name)
	pid := sqsProviderID(region, account, plan.Name)
	queueURL := sqsQueueURL(d.sqsBase(region), account, plan.Name)

	// ---- CreateQueue (+ attributes + ownership tags at birth). Tags apply only
	// on an actual creation, so an idempotent hit of a pre-existing queue leaves
	// its tags untouched — the ownership re-read below is what proves it is ours.
	form := map[string]string{
		"Action":      "CreateQueue",
		"Version":     sqsVersion,
		"QueueName":   plan.Name,
		"Tag.1.Key":   "groundhold-capability",
		"Tag.1.Value": sanitizeTag(capability),
		"Tag.2.Key":   "groundhold-environment",
		"Tag.2.Value": sanitizeTag(environment),
	}
	allAttrs := map[string]string{}
	for k, v := range plan.Attributes {
		allAttrs[k] = v
	}
	if plan.Public {
		allAttrs["Policy"] = sqsPublicPolicy(arn)
	}
	i := 1
	for _, k := range sortedStrKeys(allAttrs) {
		form[fmt.Sprintf("Attribute.%d.Name", i)] = k
		form[fmt.Sprintf("Attribute.%d.Value", i)] = allAttrs[k]
		i++
	}
	st, resp, err := d.sqsPost(region, encodeForm(form))
	if err != nil {
		// the URL is deterministic — carry the pid so reconcile keeps the handle
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown: %v", err)}
	}
	switch {
	case st == http.StatusOK:
		// created OR idempotent hit — the ownership re-check below decides
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create: HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	case st >= 400:
		// a same-name queue with DIFFERENT attributes returns QueueNameExists — a
		// genuine failure, not an idempotent hit (SQS is strict about this).
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create: HTTP %d (%s): %s", st, rdsErrCode(resp), mutDetail(resp))}
	default:
		// a 3xx is NOT a created queue — never fall through to the ownership check
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create: unexpected HTTP %d — reconcile", st)}
	}

	// ---- ownership re-check (proves the queue the name resolved to is ours) ----
	tags, found, terr := d.sqsListTags(region, queueURL)
	if terr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "queue created; ownership tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "queue vanished immediately after create — reconcile"}
	}
	switch {
	case tags["groundhold-capability"] == sanitizeTag(capability) &&
		tags["groundhold-environment"] == sanitizeTag(environment):
		// ours
	case tags["groundhold-capability"] == "":
		// CreateQueue did not tag it, so it PRE-EXISTED untagged — not provably
		// ours. Refuse to silently take it over (mirrors S3/SNS).
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "a same-account queue with this name exists but is UNTAGGED — " +
				"if it is a groundhold leftover, remove or adopt it explicitly; " +
				"refusing to silently take over an unowned queue"}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: "a queue with this name exists in our account tagged for a " +
				"different groundhold capability — refusing"}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// sqsListTags reads a queue's tag set. found=false + readable=true is an
// authoritative "queue does not exist" (NonExistentQueue); readable=false is a
// transport/HTTP/parse failure (never "no tags", never "not found").
func (d *Driver) sqsListTags(region, queueURL string) (tags map[string]string, found bool, err error) {
	const op = "ListQueueTags"
	st, resp, cerr := d.sqsPost(region, encodeForm(map[string]string{
		"Action": "ListQueueTags", "Version": sqsVersion, "QueueUrl": queueURL}))
	if cerr != nil {
		return nil, false, readTransport(op, cerr)
	}
	if st == http.StatusNotFound || strings.Contains(rdsErrCode(resp), "NonExistentQueue") {
		return nil, false, nil
	}
	if st != http.StatusOK {
		return nil, false, readHTTP(op, st, rdsErrCode(resp))
	}
	parsed, perr := parseSQSTags(resp)
	if perr != nil {
		return nil, false, readBody(op, st) // a garbled 200 is unreadable, never "empty tags"
	}
	return parsed, true, nil
}

func parseSQSTags(body []byte) (map[string]string, error) {
	var t struct {
		Tags []struct {
			Key   string `xml:"Key"`
			Value string `xml:"Value"`
		} `xml:"ListQueueTagsResult>Tag"`
	}
	if err := xml.Unmarshal(body, &t); err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, tag := range t.Tags {
		m[tag.Key] = tag.Value
	}
	return m, nil
}

func parseSQSAttributes(body []byte) (map[string]string, error) {
	var r struct {
		Entries []struct {
			Name  string `xml:"Name"`
			Value string `xml:"Value"`
		} `xml:"GetQueueAttributesResult>Attribute"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, e := range r.Entries {
		m[e.Name] = e.Value
	}
	return m, nil
}

// observeSQS reverse-maps a live queue.
func (d *Driver) observeSQS(capability, providerID string) ([]provider.Observation, []string, error) {
	region, account, name, err := splitSQSProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameAccount(account); err != nil {
		return nil, nil, err
	}
	queueURL := sqsQueueURL(d.sqsBase(region), account, name)
	st, resp, err := d.sqsPost(region, encodeForm(map[string]string{
		"Action": "GetQueueAttributes", "Version": sqsVersion, "QueueUrl": queueURL,
		"AttributeName.1": "All"}))
	if err != nil {
		return nil, nil, err
	}
	if st == http.StatusNotFound || strings.Contains(rdsErrCode(resp), "NonExistentQueue") {
		// F-LC3 (D521): a BOUND resource the API says is GONE. A diagnostic
		// alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"queue not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("GetQueueAttributes: HTTP %d", st)
	}
	qattrs, perr := parseSQSAttributes(resp)
	if perr != nil {
		return nil, nil, fmt.Errorf("GetQueueAttributes: unparseable attributes")
	}

	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
	}
	var diags []string
	obs = append(obs,
		provider.Observation{Path: "location.region", Value: region, Derivation: "measured"},
		provider.Observation{Path: "service.managed", Value: true, Derivation: "measured"},
	)

	// FIFO drives delivery.guarantee + ordering. A FIFO queue delivers in order
	// AND (with content-based dedup) provides exactly-once broker dedup; a
	// standard queue is at-least-once, unordered.
	fifo := qattrs["FifoQueue"] == "true" || strings.HasSuffix(name, ".fifo")
	obs = append(obs, provider.Observation{Path: "ordering.enabled",
		Value: fifo, Derivation: "measured"})
	guarantee := "at-least-once"
	if fifo && qattrs["ContentBasedDeduplication"] == "true" {
		guarantee = "exactly-once"
	}
	obs = append(obs, provider.Observation{Path: "delivery.guarantee",
		Value: guarantee, Derivation: "measured"})

	// reliability.deadLetter — D745. A RedrivePolicy attribute means a dead-letter
	// target is NAMED. It does not mean the target exists: delete the DLQ and the policy
	// stays, over-limit messages are dropped instead of captured, and this reported
	// `true` — a reliability control naming a queue that is not there. The policy
	// carries the ARN, so the target can be asked about.
	switch dl, target, readable := d.deadLetterTarget(region, qattrs["RedrivePolicy"]); {
	case !dl:
		obs = append(obs, provider.Observation{Path: "reliability.deadLetter",
			Value: false, Derivation: "measured"})
	case readable && target:
		obs = append(obs, provider.Observation{Path: "reliability.deadLetter",
			Value: true, Derivation: "measured"})
	case readable:
		obs = append(obs, provider.Observation{Path: "reliability.deadLetter",
			Value: false, Derivation: "measured"})
		diags = append(diags, "reliability.deadLetter=false: a redrive policy names a "+
			"dead-letter queue that does not exist — over-limit messages are dropped, "+
			"not captured")
	default:
		// The target could not be read. An unreadable target is not permission to
		// claim either answer (D725, D743).
		diags = append(diags, "reliability.deadLetter not observed: a redrive policy is "+
			"set but its dead-letter target could not be read")
	}

	// retention: MessageRetentionPeriod is seconds.
	if rp := qattrs["MessageRetentionPeriod"]; rp != "" {
		obs = append(obs, provider.Observation{Path: "retention.minimum",
			Value: rp + "s", Derivation: "measured"})
	}

	// encryption: SSE-SQS (SqsManagedSseEnabled) or SSE-KMS (KmsMasterKeyId).
	// Either present means atRest. But SSE-KMS can use the AWS-MANAGED default key,
	// which GetQueueAttributes returns as alias/aws/sqs — that is NOT a customer
	// key, so it must not yield customerManagedKeys=true (a false BYOK PASS on an
	// adopted queue). Only a non-default key id proves customer-managed.
	kms := qattrs["KmsMasterKeyId"]
	sseManaged := qattrs["SqsManagedSseEnabled"] == "true"
	obs = append(obs, provider.Observation{Path: "encryption.atRest",
		Value: kms != "" || sseManaged, Derivation: "measured"})
	obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
		Value: kms != "" && !isAWSManagedKMSKey(kms, "sqs"), Derivation: "measured"})

	// publicExposure: the queue resource Policy. No Policy at all means the
	// default owner-only policy (not public). A present-but-unparseable policy is
	// a diagnostic, never a default-safe false.
	policy := qattrs["Policy"]
	switch {
	case policy == "":
		obs = append(obs, provider.Observation{Path: "network.publicExposure",
			Value: false, Derivation: "measured"})
	default:
		public, ok := sqsPolicyPublic(policy)
		if !ok {
			diags = append(diags, "network.publicExposure not observed: queue Policy unparseable")
		} else {
			obs = append(obs, provider.Observation{Path: "network.publicExposure",
				Value: public, Derivation: "measured"})
		}
	}
	return obs, diags, nil
}

// sqsPolicyPublic reports whether a queue policy grants anonymous access. Public
// iff any Allow statement has a wildcard Principal and NO condition (a
// conditioned wildcard is not an unconditional public path). Reuses the SNS
// principal/wildcard parser (the policy JSON shape is identical).
func sqsPolicyPublic(policy string) (public, parseable bool) {
	var p struct {
		Statement []struct {
			Effect    string          `json:"Effect"`
			Principal json.RawMessage `json:"Principal"`
			Condition json.RawMessage `json:"Condition"`
		} `json:"Statement"`
	}
	if json.Unmarshal([]byte(policy), &p) != nil {
		return false, false
	}
	for _, s := range p.Statement {
		if s.Effect != "Allow" {
			continue
		}
		if cond := strings.TrimSpace(string(s.Condition)); cond != "" && cond != "null" && cond != "{}" {
			continue
		}
		if principalWildcard(s.Principal) {
			return true, true
		}
	}
	return false, true
}

// classifySQSChange (D46): PURE — can this capability.messaging.queue transition
// be honored in place? delivery.guarantee / ordering are the FIFO switch, whose
// ".fifo" name is create-time IMMUTABLE (a change is a replacement, D48), and a
// queue is regional (region immutable). Retention, the resource policy (public
// exposure) and the KMS/SSE key are all re-assertable via SetQueueAttributes, so
// they are mutable. Platform/projection properties are unsupported.
func classifySQSChange(path string, desired any, impl map[string]any) (string, string) {
	switch path {
	case "delivery.guarantee", "ordering.enabled":
		return "immutable", "FIFO vs standard is create-time only on SQS " +
			"(the queue name/type cannot be switched in place) — a replacement"
	case "location.region":
		return "immutable", "an SQS queue is regional; its region is fixed at creation — a change is a replacement"
	case "retention.minimum":
		return "mutable", ""
	case "reliability.deadLetter":
		// RedrivePolicy is re-assertable/clearable in place (SetQueueAttributes).
		return "mutable", ""
	case "network.publicExposure":
		return "mutable", ""
	case "encryption.atRest", "encryption.customerManagedKeys":
		return "mutable", ""
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no SQS in-place mapping for " + path
	}
}

// updateSQS: ownership (tags) re-check FIRST, then ONE SetQueueAttributes for
// ONLY the changed paths. The retention / encryption / public-policy values are
// reused from the SAME create builder (BuildSQSCreate) so an update and a create
// make identical choices; the immutable FIFO attributes the builder also
// produces are deliberately NOT sent (SQS would reject them). Turning encryption
// off explicitly clears both the managed-SSE flag and any KMS key.
func (d *Driver) updateSQS(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, account, name, err := splitSQSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameAccount(account); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	queueURL := sqsQueueURL(d.sqsBase(region), account, name)
	tags, found, terr := d.sqsListTags(region, queueURL)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed",
			Reason: "queue no longer exists — re-observe and re-plan"}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "queue tags do not match — refusing to patch a resource that is not ours"}
	}
	arn := sqsARN(region, account, name)
	plan, err := BuildSQSCreate("pv", environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	set := map[string]string{}
	for _, path := range changes {
		switch path {
		case "retention.minimum":
			set["MessageRetentionPeriod"] = plan.Attributes["MessageRetentionPeriod"]
		case "reliability.deadLetter":
			// desired true -> the builder produced a RedrivePolicy (operands present,
			// or it would have refused above); desired false -> clear it explicitly.
			set["RedrivePolicy"] = plan.Attributes["RedrivePolicy"]
		case "encryption.atRest", "encryption.customerManagedKeys":
			switch {
			case plan.Attributes["KmsMasterKeyId"] != "":
				set["KmsMasterKeyId"] = plan.Attributes["KmsMasterKeyId"]
			case plan.Attributes["SqsManagedSseEnabled"] == "true":
				set["SqsManagedSseEnabled"] = "true"
			default:
				// desired: no encryption — clear both mechanisms explicitly.
				set["SqsManagedSseEnabled"] = "false"
				set["KmsMasterKeyId"] = ""
			}
		case "network.publicExposure":
			if plan.Public {
				set["Policy"] = sqsPublicPolicy(arn)
			} else {
				set["Policy"] = "" // reset to the default owner-only policy
			}
		default:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("sqs path %s is not patchable in place", path)}
		}
	}
	form := map[string]string{
		"Action":   "SetQueueAttributes",
		"Version":  sqsVersion,
		"QueueUrl": queueURL,
	}
	i := 1
	for _, k := range sortedStrKeys(set) {
		form[fmt.Sprintf("Attribute.%d.Name", i)] = k
		form[fmt.Sprintf("Attribute.%d.Value", i)] = set[k]
		i++
	}
	st, resp, err := d.sqsPost(region, encodeForm(form))
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("patch outcome unknown — reconcile: %v", err)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("patch HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, providerID, "patch"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("patch failed: HTTP %d (%s)", st, rdsErrCode(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// deleteSQS: ownership (tags) pre-check, then DeleteQueue (idempotent — a
// NonExistentQueue is success). A queue that is not ours (foreign or untagged)
// is refused, never deleted.
func (d *Driver) deleteSQS(capability, environment, providerID string) provider.CreateResult {
	region, account, name, err := splitSQSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameAccount(account); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	queueURL := sqsQueueURL(d.sqsBase(region), account, name)
	tags, found, terr := d.sqsListTags(region, queueURL)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if tags["groundhold-capability"] != sanitizeTag(capability) ||
		tags["groundhold-environment"] != sanitizeTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "queue tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, err := d.sqsPost(region, encodeForm(map[string]string{
		"Action": "DeleteQueue", "Version": sqsVersion, "QueueUrl": queueURL}))
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if strings.Contains(rdsErrCode(resp), "NonExistentQueue") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete: HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("delete: HTTP %d (%s)", st, rdsErrCode(resp))}
	}
	// ---- poll to absence (D968 class, D982) ----
	// DeleteQueue is async: AWS documents up to 60s during which the queue (and its
	// in-flight messages) still answers. Reporting succeeded here tombstones a queue
	// still live. Poll sqsListTags to a confirmed NonExistentQueue; unknown on timeout
	// keeps the handle.
	deadline := d.Now().Add(d.PollTimeout)
	for {
		if _, found, rerr := d.sqsListTags(region, queueURL); rerr == nil && !found {
			return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // confirmed gone
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "queue still deleting at poll timeout — reconcile via ListQueues"}
		}
		time.Sleep(d.PollInterval)
	}
}

// deadLetterTarget answers whether a redrive policy names a dead-letter queue and
// whether that queue EXISTS (D745). Returns (policyPresent, targetExists, readable);
// readable=false means the target could not be asked about, which is not the same as
// absent.
func (d *Driver) deadLetterTarget(region, redrivePolicy string) (present, exists, readable bool) {
	if redrivePolicy == "" {
		return false, false, true
	}
	var pol struct {
		DeadLetterTargetArn string `json:"deadLetterTargetArn"`
	}
	if json.Unmarshal([]byte(redrivePolicy), &pol) != nil || pol.DeadLetterTargetArn == "" {
		return true, false, false
	}
	// arn:aws:sqs:<region>:<account>:<name>
	parts := strings.Split(pol.DeadLetterTargetArn, ":")
	if len(parts) < 6 {
		return true, false, false
	}
	url := sqsQueueURL(d.sqsBase(parts[3]), parts[4], parts[5])
	st, resp, err := d.sqsPost(parts[3], encodeForm(map[string]string{
		"Action": "GetQueueAttributes", "Version": sqsVersion, "QueueUrl": url,
		"AttributeName.1": "QueueArn"}))
	switch {
	case err != nil:
		return true, false, false
	case st == http.StatusNotFound || strings.Contains(rdsErrCode(resp), "NonExistentQueue"):
		return true, false, true // authoritatively gone
	case st != http.StatusOK:
		return true, false, false
	}
	return true, true, true
}
