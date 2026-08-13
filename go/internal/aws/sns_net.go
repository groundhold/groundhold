// SNS network shell (D94): the SigV4-signed half of the AWS messaging.topic
// driver. A topic is regional and its ARN is deterministic from
// (region, account, name), so the handle is knowable BEFORE the create response
// — a lost/garbled outcome (D29) always carries the pid. Ownership is TAGS
// (applied at CreateTopic birth); a topic name is scoped to the account+region
// (no global namespace, so no D82 cross-account squat concern, unlike S3).
// The create sequence: CreateTopic (+tags) -> ownership re-check ->
// SetTopicAttributes (KMS key) -> SetTopicAttributes (public policy).
package aws

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"groundhold/internal/provider"
)

const snsVersion = "2010-03-31"

func (d *Driver) snsBase(region string) string {
	if d.SNSBaseURL != "" {
		return d.SNSBaseURL
	}
	return "https://sns." + region + ".amazonaws.com"
}

// snsARN assembles the topic ARN. v0 targets the standard "aws" partition;
// gov/cn partitions carry different ARN partitions and are out of scope (their
// multi-segment regions do not pass regionOK either).
func snsARN(region, account, name string) string {
	return "arn:aws:sns:" + region + ":" + account + ":" + name
}

func snsProviderID(region, account, name string) string {
	return "sns:" + region + ":" + account + ":" + name
}

// splitSNSProviderID validates every component before it is interpolated into
// an ARN/path (D73 boundary). The account rides in the id so observe/delete can
// rebuild the ARN with no STS call (the read paths pin no account).
func splitSNSProviderID(providerID string) (region, account, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "sns" {
		return "", "", "", fmt.Errorf("providerId %q is not sns:region:account:name", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !account12.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId account %q is invalid", parts[2])
	}
	if !snsNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId topic name %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

// snsPost signs (region-scoped) and sends a Query-protocol POST.
func (d *Driver) snsPost(region, body string) (int, []byte, error) {
	return d.doSigned("POST", d.snsBase(region)+"/", "sns", region,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(body))
}

// createSNS: CreateTopic (+ownership tags), ownership re-check, then the
// optional attribute mutations (KMS key, public policy). A same-account topic
// with this name that is NOT ours (foreign tags) is refused; an untagged one is
// unknown (reconcile), never silently taken over.
func (d *Driver) createSNS(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildSNSCreate(account, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	arn := snsARN(region, account, plan.Name)
	pid := snsProviderID(region, account, plan.Name)

	// ---- CreateTopic (+ ownership tags at birth). SNS Tags apply only on an
	// actual creation, so an idempotent hit of a pre-existing topic leaves its
	// tags untouched — the ownership re-read below is what proves it is ours.
	create := encodeForm(map[string]string{
		"Action":              "CreateTopic",
		"Version":             snsVersion,
		"Name":                plan.Name,
		"Tags.member.1.Key":   "groundhold-capability",
		"Tags.member.1.Value": sanitizeTag(capability),
		"Tags.member.2.Key":   "groundhold-environment",
		"Tags.member.2.Value": sanitizeTag(environment),
	})
	st, resp, err := d.snsPost(region, create)
	if err != nil {
		// the ARN is deterministic — carry the pid so reconcile keeps the handle
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
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create: HTTP %d (%s): %s", st, rdsErrCode(resp), mutDetail(resp))}
	default:
		// a 3xx is NOT a created topic — never fall through to the config steps
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create: unexpected HTTP %d — reconcile", st)}
	}

	// ---- ownership re-check (proves the topic the name resolved to is ours) ----
	tags, found, rerr := d.snsListTags(region, arn)
	if rerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "topic created; ownership tag read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "topic vanished immediately after create — reconcile"}
	}
	switch {
	case tags["groundhold-capability"] == sanitizeTag(capability) &&
		tags["groundhold-environment"] == sanitizeTag(environment):
		// ours — proceed to re-assert config idempotently
	case tags["groundhold-capability"] == "":
		// CreateTopic did not tag it, so it PRE-EXISTED untagged — not provably
		// ours. Refuse to silently take it over (mirrors the S3 untagged case).
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "a same-account topic with this name exists but is UNTAGGED — " +
				"if it is a groundhold leftover, remove or adopt it explicitly; " +
				"refusing to silently take over an unowned topic"}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: "a topic with this name exists in our account tagged for a " +
				"different groundhold capability — refusing"}
	}

	// ---- encryption (KMS key: alias/aws/sns for the provider default, or a
	// customer key) ----
	if plan.KmsKeyID != "" {
		if r := d.snsSetAttr(region, arn, "KmsMasterKeyId", plan.KmsKeyID, pid, "encryption"); r != nil {
			return *r
		}
	}
	// ---- public publish policy (second exposure gate) ----
	if plan.Public {
		if r := d.snsSetAttr(region, arn, "Policy", snsPublicPolicy(arn), pid, "public policy"); r != nil {
			return *r
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// snsSetAttr runs one SetTopicAttributes; nil = ok, non-nil = a terminal result
// WITH the pid (the topic exists, so a partial is unknown/failed, never lost).
func (d *Driver) snsSetAttr(region, arn, name, value, pid, what string) *provider.CreateResult {
	body := encodeForm(map[string]string{
		"Action":         "SetTopicAttributes",
		"Version":        snsVersion,
		"TopicArn":       arn,
		"AttributeName":  name,
		"AttributeValue": value,
	})
	st, resp, err := d.snsPost(region, body)
	if err != nil {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("topic created; %s outcome unknown — reconcile", what)}
		return &r
	}
	if st >= 500 {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("topic created; %s HTTP %d (server error) — reconcile", what, st)}
		return &r
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, pid, what); r != nil {
			return r
		}
		r := provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("topic created but %s failed: HTTP %d (%s)", what, st, rdsErrCode(resp))}
		return &r
	}
	return nil
}

// snsListTags reads a topic's tag set. found=false + readable=true is an
// authoritative "topic does not exist" (NotFound); readable=false is a
// transport/HTTP/parse failure (never "no tags", never "not found").
func (d *Driver) snsListTags(region, arn string) (tags map[string]string, found bool, err error) {
	const op = "ListTagsForResource"
	body := encodeForm(map[string]string{
		"Action": "ListTagsForResource", "Version": snsVersion, "ResourceArn": arn})
	st, resp, cerr := d.snsPost(region, body)
	if cerr != nil {
		return nil, false, readTransport(op, cerr)
	}
	if st == http.StatusNotFound || strings.Contains(rdsErrCode(resp), "NotFound") {
		return nil, false, nil
	}
	if st != http.StatusOK {
		return nil, false, readHTTP(op, st, rdsErrCode(resp))
	}
	parsed, perr := parseSNSTags(resp)
	if perr != nil {
		return nil, false, readBody(op, st) // a garbled 200 is unreadable, never "empty tags"
	}
	return parsed, true, nil
}

func parseSNSTags(body []byte) (map[string]string, error) {
	var t struct {
		Tags []struct {
			Key   string `xml:"Key"`
			Value string `xml:"Value"`
		} `xml:"ListTagsForResourceResult>Tags>member"`
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

func parseSNSAttributes(body []byte) (map[string]string, error) {
	var r struct {
		Entries []struct {
			Key   string `xml:"key"`
			Value string `xml:"value"`
		} `xml:"GetTopicAttributesResult>Attributes>entry"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, e := range r.Entries {
		m[e.Key] = e.Value
	}
	return m, nil
}

// observeSNS reverse-maps a live topic.
func (d *Driver) observeSNS(capability, providerID string) ([]provider.Observation, []string, error) {
	region, account, name, err := splitSNSProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameAccount(account); err != nil {
		return nil, nil, err
	}
	arn := snsARN(region, account, name)
	st, resp, err := d.snsPost(region, encodeForm(map[string]string{
		"Action": "GetTopicAttributes", "Version": snsVersion, "TopicArn": arn}))
	if err != nil {
		return nil, nil, err
	}
	if st == http.StatusNotFound || strings.Contains(rdsErrCode(resp), "NotFound") {
		// F-LC3 (D521): a BOUND resource the API says is GONE. A diagnostic
		// alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"topic not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("GetTopicAttributes: HTTP %d", st)
	}
	tattrs, perr := parseSNSAttributes(resp)
	if perr != nil {
		return nil, nil, fmt.Errorf("GetTopicAttributes: unparseable attributes")
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
	// encryption: a KmsMasterKeyId is present iff the topic has SSE. The value
	// distinguishes the AWS-managed default (alias/aws/sns) from a customer key —
	// reliably, unlike RDS where the ARN is ambiguous.
	kms := tattrs["KmsMasterKeyId"]
	obs = append(obs, provider.Observation{Path: "encryption.atRest",
		Value: kms != "", Derivation: "measured"})
	obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
		Value: kms != "" && kms != snsAWSManagedKey, Derivation: "measured"})
	// publicExposure: the topic resource Policy. No Policy attribute at all means
	// the default owner-only policy (not public). A present-but-unparseable policy
	// is a diagnostic, never a default-safe false.
	policy := tattrs["Policy"]
	switch {
	case policy == "":
		obs = append(obs, provider.Observation{Path: "network.publicExposure",
			Value: false, Derivation: "measured"})
	default:
		public, ok := snsPolicyPublic(policy)
		if !ok {
			diags = append(diags, "network.publicExposure not observed: topic Policy unparseable")
		} else {
			obs = append(obs, provider.Observation{Path: "network.publicExposure",
				Value: public, Derivation: "measured"})
		}
	}
	// delivery.confirmedSubscribers (D1030): a topic with none is a dummy an alarm
	// fires into and no one hears. SNS reports the confirmed count on GetTopicAttributes,
	// so no extra call. A witness can PROVE ">= N confirmed" but NOT "reaches nobody":
	// a 0 read is confounded by a pending subscription (and SNS's SubscriptionsPending
	// counter LAGS a just-created one — field-observed 2026-08-13, it stayed 0 right
	// after Subscribe), a cross-account subscription, or a delivery path it does not
	// enumerate. So confirmed>0 is measured; 0 is UNKNOWN (emit nothing -> a hard gte-1
	// blocks as unknown, never a false violated). Counts CONFIRMED subscriptions, not
	// that a human reads them (the alert.notify D1027 non-claim).
	confRaw, hasConf := tattrs["SubscriptionsConfirmed"]
	confirmed, cerr := strconv.Atoi(confRaw)
	switch {
	case !hasConf || cerr != nil:
		diags = append(diags, "delivery.confirmedSubscribers not observed: SubscriptionsConfirmed missing/unparseable")
	case confirmed > 0:
		obs = append(obs, provider.Observation{Path: "delivery.confirmedSubscribers",
			Value: confirmed, Derivation: "measured"})
	default:
		diags = append(diags, "delivery.confirmedSubscribers unknown: 0 confirmed — a witness "+
			"cannot prove a topic reaches nobody (a pending, cross-account, or uncatalogued "+
			"subscription is not counted here)")
	}
	return obs, diags, nil
}

// snsPolicyPublic reports whether a topic policy grants anonymous publish. It is
// public iff any Allow statement has a wildcard Principal and NO condition (a
// conditioned wildcard is not an unconditional public path). Returns
// parseable=false on a malformed policy so the caller surfaces a diagnostic
// rather than a default-safe verdict.
func snsPolicyPublic(policy string) (public, parseable bool) {
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
			continue // a conditioned wildcard is not an unconditional public path
		}
		if principalWildcard(s.Principal) {
			return true, true
		}
	}
	return false, true
}

// principalWildcard matches "*" and {"AWS":"*"} / {"AWS":["*"]} — the forms an
// anonymous-publish grant takes.
func principalWildcard(raw json.RawMessage) bool {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == "*"
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	aws, ok := obj["AWS"]
	if !ok {
		return false
	}
	var as string
	if json.Unmarshal(aws, &as) == nil {
		return as == "*"
	}
	var arr []string
	if json.Unmarshal(aws, &arr) == nil {
		for _, v := range arr {
			if v == "*" {
				return true
			}
		}
	}
	return false
}

// classifySNSChange (D46): PURE — can this capability.messaging.topic transition
// be honored in place? A topic is REGIONAL and its name/ARN are fixed at birth,
// so location.region is a replacement; the resource policy (public exposure) and
// the KMS key (encryption) are re-assertable via SetTopicAttributes, so they are
// mutable. Platform/projection properties are unsupported.
func classifySNSChange(path string, desired any, impl map[string]any) (string, string) {
	switch path {
	case "location.region":
		return "immutable", "an SNS topic is regional; its region is fixed at creation — a change is a replacement"
	case "network.publicExposure":
		return "mutable", ""
	case "encryption.atRest", "encryption.customerManagedKeys":
		return "mutable", ""
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no SNS in-place mapping for " + path
	}
}

// updateSNS: ownership (tags) re-check FIRST, then SetTopicAttributes for ONLY
// the changed paths. The KMS key and the public-policy decision are reused from
// the SAME create builder (BuildSNSCreate) so an update and a create make the
// identical honesty/encryption choices; an empty KmsMasterKeyId disables SSE and
// an empty Policy resets to the default owner-only policy.
func (d *Driver) updateSNS(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, account, name, err := splitSNSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameAccount(account); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	arn := snsARN(region, account, name)
	tags, found, rerr := d.snsListTags(region, arn)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update tag read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed",
			Reason: "topic no longer exists — re-observe and re-plan"}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "topic tags do not match — refusing to patch a resource that is not ours"}
	}
	// desired plan (create-decision reuse) — the KMS key / public verdict.
	plan, err := BuildSNSCreate("pv", environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	setEncryption, setPolicy := false, false
	for _, path := range changes {
		switch path {
		case "encryption.atRest", "encryption.customerManagedKeys":
			setEncryption = true
		case "network.publicExposure":
			setPolicy = true
		default:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("sns path %s is not patchable in place", path)}
		}
	}
	if setEncryption {
		if r := d.snsUpdateAttr(region, arn, "KmsMasterKeyId", plan.KmsKeyID, providerID, "encryption"); r != nil {
			return *r
		}
	}
	if setPolicy {
		policy := ""
		if plan.Public {
			policy = snsPublicPolicy(arn)
		}
		if r := d.snsUpdateAttr(region, arn, "Policy", policy, providerID, "public policy"); r != nil {
			return *r
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// snsUpdateAttr runs one SetTopicAttributes for the update path; nil = ok,
// non-nil = a terminal result. err/5xx are unknown WITH the pid (may have
// landed — D29); a 4xx/3xx is failed.
func (d *Driver) snsUpdateAttr(region, arn, name, value, pid, what string) *provider.CreateResult {
	st, resp, err := d.snsPost(region, encodeForm(map[string]string{
		"Action":         "SetTopicAttributes",
		"Version":        snsVersion,
		"TopicArn":       arn,
		"AttributeName":  name,
		"AttributeValue": value,
	}))
	if err != nil {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("%s patch outcome unknown — reconcile", what)}
		return &r
	}
	if st >= 500 {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("%s patch HTTP %d (server error) — reconcile", what, st)}
		return &r
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, pid, what+" patch"); r != nil {
			return r
		}
		r := provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("%s patch failed: HTTP %d (%s)", what, st, rdsErrCode(resp))}
		return &r
	}
	return nil
}

// deleteSNS: ownership (tags) pre-check, then DeleteTopic (idempotent — a
// NotFound is success). A topic that is not ours (foreign or untagged) is
// refused, never deleted.
func (d *Driver) deleteSNS(capability, environment, providerID string) provider.CreateResult {
	region, account, name, err := splitSNSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameAccount(account); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	arn := snsARN(region, account, name)
	tags, found, rerr := d.snsListTags(region, arn)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete tag read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if tags["groundhold-capability"] != sanitizeTag(capability) ||
		tags["groundhold-environment"] != sanitizeTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "topic tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, err := d.snsPost(region, encodeForm(map[string]string{
		"Action": "DeleteTopic", "Version": snsVersion, "TopicArn": arn}))
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if strings.Contains(rdsErrCode(resp), "NotFound") {
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
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
