// Pub/Sub queue network shell (D95): the httptest-covered half of the GCP
// messaging.queue driver. The queue is a CONSTITUTIVE COMPOSITE — create is
// backing-topic PUT then subscription PUT (both synchronous, no LRO); the
// providerId (the subscription id, deterministic) is carried from the FIRST
// mutation so a partial is failed/unknown WITH the pid, never succeeded (D29).
// Public exposure is an allUsers roles/pubsub.subscriber IAM binding on the
// SUBSCRIPTION (the same version-3 read-modify-write-confirm honesty as the
// topic's publisher grant). Ownership is LABELS; retirement is REVERSE
// (subscription then the backing topic).
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func (d *Driver) subscriptionURL(project, name string) string {
	return d.pubsubBase() + "/projects/" + project + "/subscriptions/" + name
}

type subscriptionDoc struct {
	Name                      string            `json:"name"`
	Topic                     string            `json:"topic"`
	Labels                    map[string]string `json:"labels"`
	MessageRetentionDuration  string            `json:"messageRetentionDuration"`
	EnableExactlyOnceDelivery bool              `json:"enableExactlyOnceDelivery"`
	EnableMessageOrdering     bool              `json:"enableMessageOrdering"`
	DeadLetterPolicy          *struct {
		DeadLetterTopic     string `json:"deadLetterTopic"`
		MaxDeliveryAttempts int    `json:"maxDeliveryAttempts"`
	} `json:"deadLetterPolicy"`
}

// createPubSubQueue: backing topic PUT -> subscription PUT -> (if public) grant
// allUsers subscriber. The pid (subscription id) is deterministic, so it is
// carried from the topic PUT onward — a partial (topic landed, subscription did
// not) is failed/unknown WITH the pid, never succeeded.
func (d *Driver) createPubSubQueue(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildPubSubQueuePlan(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	name := plan.Name
	pid := pubsubProviderID(d.Project, name)

	// ---- 1. the constitutive backing TOPIC (residency/CMEK live here) ----
	topicURL := d.topicURL(d.Project, name)
	wantRegion, _ := attrs["location.region"].(string)
	wantKey, _ := impl["kms_key_name"].(string)
	if cmek, _ := attrs["encryption.customerManagedKeys"].(bool); !cmek {
		wantKey = ""
	}
	status, body, err := d.call("PUT", topicURL, plan.TopicBody)
	if err != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("backing topic create outcome unknown: %v", err)}
	}
	switch {
	case status == http.StatusConflict:
		ours, doc, found, rerr := d.pubsubGetTopic(name, capability, environment)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "backing topic name conflict, existing topic gave no answer — reconcile: " + rerr.Error()}
		}
		if !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "backing topic name conflict, but it was gone on the follow-up read — reconcile"}
		}
		if !ours {
			return provider.CreateResult{Status: "failed",
				Reason: "a topic with the backing name exists but is not ours (labels do not match)"}
		}
		if !regionsMatch(doc.MessageStoragePolicy.AllowedPersistenceRegions, wantRegion) {
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf(
				"existing backing topic storage regions %v do not match desired residency %q "+
					"and pubsub update is not wired — reconcile",
				doc.MessageStoragePolicy.AllowedPersistenceRegions, wantRegion)}
		}
		if doc.KmsKeyName != wantKey {
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf(
				"existing backing topic CMEK key %q does not match desired %q and pubsub "+
					"update is not wired — reconcile", doc.KmsKeyName, wantKey)}
		}
	case status >= 400:
		res := mutationResult("backing topic create", status, body)
		if res.Status == "unknown" {
			res.ProviderID = pid // 5xx may have landed — keep the deterministic handle
		}
		return res
	default:
		var b struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(body, &b) != nil || b.Name == "" {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "backing topic create response carried no topic — reconcile"}
		}
	}

	// ---- 2. the SUBSCRIPTION (the durable queue) ----
	subURL := d.subscriptionURL(d.Project, name)
	status, body, err = d.call("PUT", subURL, plan.SubBody)
	if err != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("subscription create outcome unknown: %v", err)}
	}
	switch {
	case status == http.StatusConflict:
		ours, doc, found, rerr := d.pubsubGetSubscription(name, capability, environment)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "subscription name conflict, existing subscription gave no answer — reconcile: " + rerr.Error()}
		}
		if !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "subscription name conflict, but it was gone on the follow-up read — reconcile"}
		}
		if !ours {
			return provider.CreateResult{Status: "failed",
				Reason: "a subscription with this name exists but is not ours (labels do not match)"}
		}
		if !subscriptionConfigMatches(doc, plan.SubBody) {
			return provider.CreateResult{Status: "failed", Reason: "existing subscription " +
				"config differs from desired and pubsub update is not wired — reconcile"}
		}
	case status >= 400:
		res := mutationResult("subscription create", status, body)
		// the pid is knowable and the backing topic exists — always keep the handle
		// so a partial never loses it (D29), even on a 4xx subscription failure.
		res.ProviderID = pid
		return res
	default:
		var b struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(body, &b) != nil || b.Name == "" {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "subscription create response carried no subscription — reconcile"}
		}
	}

	// ---- 3. public exposure: allUsers subscriber on the subscription ----
	if plan.Public {
		if unknown, err := d.setSubscriptionPublic(d.Project, name); err != nil {
			st := "failed"
			if unknown {
				st = "unknown"
			}
			return provider.CreateResult{ProviderID: pid, Status: st, Reason: err.Error()}
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// pubsubGetSubscription returns ownership, the live subscription document,
// existence, and why a read failed — a failed read is never "not ours", and a
// 404 is an authoritative absence.
func (d *Driver) pubsubGetSubscription(name, capability, environment string) (ours bool, doc subscriptionDoc, found bool, err error) {
	const op = "subscriptions.get"
	status, body, cerr := d.call("GET", d.subscriptionURL(d.Project, name), nil)
	if cerr != nil {
		return false, subscriptionDoc{}, false, readTransport(op, cerr)
	}
	if status == http.StatusNotFound {
		return false, subscriptionDoc{}, false, nil
	}
	if status != http.StatusOK {
		return false, subscriptionDoc{}, false, readHTTP(op, status, gcpErrCode(body))
	}
	if json.Unmarshal(body, &doc) != nil {
		return false, subscriptionDoc{}, false, readBody(op, status)
	}
	ours = doc.Labels["groundhold-capability"] == sanitizeLabel(capability) &&
		doc.Labels["groundhold-environment"] == sanitizeLabel(environment)
	return ours, doc, true, nil
}

// subscriptionConfigMatches reports whether a live subscription's durable config
// equals the desired body — a create-time property mismatch (retention, ordering,
// exactly-once) is a reconcile, not an idempotent hit (update is not wired).
func subscriptionConfigMatches(doc subscriptionDoc, want map[string]any) bool {
	wantExactly, _ := want["enableExactlyOnceDelivery"].(bool)
	if doc.EnableExactlyOnceDelivery != wantExactly {
		return false
	}
	wantOrdering, _ := want["enableMessageOrdering"].(bool)
	if doc.EnableMessageOrdering != wantOrdering {
		return false
	}
	// retention is only compared when the author pinned it (else Pub/Sub's default
	// applies and there is nothing to match against).
	if wantRet, ok := want["messageRetentionDuration"].(string); ok && wantRet != "" {
		if doc.MessageRetentionDuration != wantRet {
			return false
		}
	}
	// dead-letter policy is only compared when the author pinned it (else Pub/Sub's
	// default — no policy — applies and there is nothing to match against). deadLetter
	// is mutable, so a mismatch is a reconcile the update path can settle, never a
	// silent takeover.
	if wantDL, ok := want["deadLetterPolicy"].(map[string]any); ok {
		if doc.DeadLetterPolicy == nil {
			return false
		}
		wantTopic, _ := wantDL["deadLetterTopic"].(string)
		wantAtt, _ := wantDL["maxDeliveryAttempts"].(int)
		if doc.DeadLetterPolicy.DeadLetterTopic != wantTopic ||
			doc.DeadLetterPolicy.MaxDeliveryAttempts != wantAtt {
			return false
		}
	}
	return true
}

// setSubscriptionPublic grants allUsers roles/pubsub.subscriber via a version-3
// read-modify-write (etag preserved, append-only), then re-reads to confirm.
// Returns unknown=true only when the MUTATING setIamPolicy response was lost
// (D29: never "failed"). Reuses the shared getRunPolicyForWrite/readRunPolicy
// (generic on the resource base) + appendMember/hasMember/isDomainRestricted.
func (d *Driver) setSubscriptionPublic(project, name string) (unknown bool, err error) {
	base := d.subscriptionURL(project, name)
	bindings, etag, err := d.getRunPolicyForWrite(base)
	if err != nil {
		return false, fmt.Errorf("public exposure: %v", err) // reads are definitive
	}
	bindings = appendMember(bindings, "roles/pubsub.subscriber", "allUsers")

	status, body, cerr := d.call("POST", base+":setIamPolicy",
		map[string]any{"policy": map[string]any{
			"version": iamPolicyVersion, "bindings": bindings, "etag": etag}})
	if cerr != nil {
		return true, fmt.Errorf("public exposure: setIamPolicy outcome "+
			"unknown — reconcile via getIamPolicy: %v", cerr)
	}
	if status != http.StatusOK {
		if isDomainRestricted(body) {
			return false, fmt.Errorf("public exposure blocked by domain-"+
				"restricted-sharing (an org-policy decision, not a missing "+
				"permission): %s", mutDetail(body))
		}
		if status >= 500 {
			return true, fmt.Errorf("public exposure: setIamPolicy HTTP %d "+
				"(server error — the grant may have landed, reconcile): %s",
				status, mutDetail(body))
		}
		if provider.Classify(status, gcpErrCode(body), nil).Unknown() {
			// D237: a throttle (429) or live 403 does not prove the grant failed.
			return true, fmt.Errorf("public exposure: setIamPolicy HTTP %d "+
				"(transient/denied — the grant may have landed, reconcile): %s",
				status, mutDetail(body))
		}
		return false, fmt.Errorf("public exposure: setIamPolicy HTTP %d: %s",
			status, mutDetail(body))
	}
	pub, cerr := d.subscriptionPublic(project, name)
	switch {
	case pub:
		return false, nil
	case cerr != nil:
		return true, fmt.Errorf("public exposure: setIamPolicy returned 200 but "+
			"the binding could not be confirmed (%v) — reconcile", cerr)
	default:
		return false, fmt.Errorf("public exposure: allUsers subscriber binding " +
			"did not take (org policy or a conditional binding may interfere)")
	}
}

// subscriptionPublic reports whether the subscription grants anonymous consume
// (allUsers/allAuthenticatedUsers subscriber). Three-valued: unreadable is never
// "not public".
func (d *Driver) subscriptionPublic(project, name string) (public bool, err error) {
	bindings, perr := d.readRunPolicy(d.subscriptionURL(project, name))
	if perr != nil {
		return false, perr
	}
	for _, b := range bindings {
		role, _ := b["role"].(string)
		if role == "roles/pubsub.subscriber" &&
			(hasMember(b, "allUsers") || hasMember(b, "allAuthenticatedUsers")) {
			return true, nil
		}
	}
	return false, nil
}

// observePubSubQueue reverse-maps the composite: GET the subscription (the queue
// semantics) AND the constitutive backing topic (residency/CMEK). The residency
// mapping is the honesty crux (D94): a backing topic with NO storage policy is
// GLOBAL and carries no residency guarantee, so location.region is a diagnostic,
// never defaulted.
func (d *Driver) observePubSubQueue(capability, providerID string) ([]provider.Observation, []string, error) {
	project, name, err := splitPubSubProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	status, body, err := d.call("GET", d.subscriptionURL(project, name), nil)
	if err != nil {
		return nil, nil, err
	}
	if status == http.StatusNotFound {
		// F-LC3 (D521): a BOUND resource the API says is GONE. A diagnostic
		// alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"subscription not found — bound resource is gone (will re-create)"}, nil
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("subscriptions.get: HTTP %d", status)
	}
	var sub subscriptionDoc
	if err := json.Unmarshal(body, &sub); err != nil {
		return nil, nil, fmt.Errorf("subscriptions.get: unparseable subscription document")
	}

	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
	}
	var diags []string
	obs = append(obs,
		provider.Observation{Path: "service.managed", Value: true, Derivation: "measured"},
		provider.Observation{Path: "encryption.atRest", Value: true, Derivation: "platform-invariant"}, // always encrypts
	)

	// delivery.guarantee + ordering come from the SUBSCRIPTION.
	guarantee := "at-least-once"
	if sub.EnableExactlyOnceDelivery {
		guarantee = "exactly-once"
	}
	obs = append(obs,
		provider.Observation{Path: "delivery.guarantee", Value: guarantee, Derivation: "measured"},
		provider.Observation{Path: "ordering.enabled", Value: sub.EnableMessageOrdering, Derivation: "measured"},
	)
	if sub.MessageRetentionDuration != "" {
		obs = append(obs, provider.Observation{Path: "retention.minimum",
			Value: sub.MessageRetentionDuration, Derivation: "measured"})
	}

	// reliability.deadLetter: a deadLetterPolicy with a target topic means messages
	// unprocessed after N attempts go to a dead-letter topic (not lost). Absent =>
	// no policy (measured false), so a "deadLetter equals true" constraint reads
	// violated, never unknown (symmetric with the SQS RedrivePolicy mapping).
	obs = append(obs, provider.Observation{Path: "reliability.deadLetter",
		Value:      sub.DeadLetterPolicy != nil && sub.DeadLetterPolicy.DeadLetterTopic != "",
		Derivation: "measured"})

	// residency + CMEK come from the constitutive backing topic.
	const topicOp = "topics.get"
	tstatus, tbody, terr := d.call("GET", d.topicURL(project, name), nil)
	if terr != nil {
		diags = append(diags, "location.region/encryption.customerManagedKeys not observed "+
			"on the constitutive backing topic: "+readTransport(topicOp, terr).Error())
	} else if tstatus != http.StatusOK {
		diags = append(diags, "location.region/encryption.customerManagedKeys not observed "+
			"on the constitutive backing topic: "+readHTTP(topicOp, tstatus, gcpErrCode(tbody)).Error())
	} else {
		var topic topicDoc
		if json.Unmarshal(tbody, &topic) != nil {
			diags = append(diags, "location.region/encryption.customerManagedKeys not "+
				"observed: the backing topic document is unparseable")
		} else {
			// D1040/D1003: the backing topic was read and parsed, so an empty KmsKeyName
			// is a MEASURED false (Google-managed), not an absence — emit BOTH states.
			// The read-failed/unparseable branches above keep their diagnostic.
			obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
				Value: topic.KmsKeyName != "", Derivation: "measured"})
			switch regions := topic.MessageStoragePolicy.AllowedPersistenceRegions; len(regions) {
			case 0:
				diags = append(diags, "location.region not observed: the backing topic has no "+
					"messageStoragePolicy — it is GLOBAL and carries no residency guarantee "+
					"(a residency contract cannot be satisfied by a global topic)")
			case 1:
				obs = append(obs, provider.Observation{Path: "location.region",
					Value: regions[0], Derivation: "measured"})
			default:
				diags = append(diags, fmt.Sprintf("location.region not observed: the backing "+
					"topic messageStoragePolicy pins multiple regions (%v)", regions))
			}
		}
	}

	// publicExposure: an allUsers/allAuthenticatedUsers subscriber binding.
	pub, perr := d.subscriptionPublic(project, name)
	if perr != nil {
		diags = append(diags, "network.publicExposure not observed: "+perr.Error())
	} else {
		obs = append(obs, provider.Observation{Path: "network.publicExposure",
			Value: pub, Derivation: "measured"})
	}
	return obs, diags, nil
}

// deletePubSubQueue: REVERSE-order retirement (subscription then the constitutive
// backing topic), each ours-by-labels. The ownership pre-read on the subscription
// is the refusal gate; a foreign subscription is never deleted. 404 is idempotent
// success at every step.
func (d *Driver) deletePubSubQueue(capability, environment, providerID string) provider.CreateResult {
	project, name, err := splitPubSubProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}

	// ---- ownership pre-read + delete the SUBSCRIPTION ----
	status, body, err := d.call("GET", d.subscriptionURL(project, name), nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-delete subscription read failed: %v", err)}
	}
	switch {
	case status == http.StatusNotFound:
		// subscription already gone — fall through to retire the backing topic
	case status != http.StatusOK:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("pre-delete subscription read: HTTP %d", status)}
	default:
		var doc subscriptionDoc
		if json.Unmarshal(body, &doc) != nil {
			return provider.CreateResult{Status: "unknown",
				Reason: "pre-delete subscription read unparseable — refusing an ambiguous delete"}
		}
		if doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
			doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "subscription labels do not match — refusing to delete a resource that is not ours"}
		}
		dstatus, dbody, derr := d.call("DELETE", d.subscriptionURL(project, name), nil)
		if derr != nil {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("subscription delete outcome unknown: %v", derr)}
		}
		if dstatus != http.StatusNotFound && dstatus >= 400 {
			res := mutationResult("subscription delete", dstatus, dbody)
			if res.Status == "unknown" {
				res.ProviderID = providerID
			}
			return res
		}
	}

	// ---- retire the constitutive backing TOPIC (ours by labels) ----
	// deletePubSub does the topic ownership re-read + DELETE under the SAME name;
	// a partial (subscription gone, topic delete ambiguous) surfaces unknown WITH
	// the pid.
	return d.deletePubSub(capability, environment, providerID)
}

// updatePubSubQueue patches a subscription's mutable attributes in place (D130 update
// slice, symmetric with the SQS update). Only retention.minimum is wired in this slice
// — a subscriptions.patch of messageRetentionDuration with an updateMask. Ownership
// (labels) is re-checked immediately before the patch; ClassifyChange
// (classifyPubSubQueueChange) already gated the change set, so a non-retention path
// here is a bug — refused, never silently applied.
//
// HONEST LIMITATION: Pub/Sub UpdateSubscription offers NO optimistic-concurrency token
// (no etag/version/generation on a subscription), so unlike the Cloud SQL / GCS patches
// there is no CAS precondition — a concurrent retention change is last-write-wins. This
// is stated, not faked with a precondition the API does not have; the ownership re-read
// immediately before the write keeps the TOCTOU window minimal.
func (d *Driver) updatePubSubQueue(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	project, name, err := splitPubSubProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	sub := map[string]any{"name": fmt.Sprintf("projects/%s/subscriptions/%s", project, name)}
	var masks []string
	for _, path := range changes {
		switch path {
		case "retention.minimum":
			dur, derr := pubsubRetentionDuration(attrs[path])
			if derr != nil {
				return provider.CreateResult{Status: "failed", Reason: derr.Error()}
			}
			sub["messageRetentionDuration"] = dur
			masks = append(masks, "messageRetentionDuration")
		case "reliability.deadLetter":
			// desired true -> build the policy from the operands (refuses loudly if
			// absent, exactly as create does); desired false -> clear it. Clearing is
			// a patch to empty: the field stays absent from the body and the updateMask
			// entry is what tells Pub/Sub to reset it. deadLetterPolicy is patchable via
			// subscriptions.patch (mirrors the SQS RedrivePolicy set/clear).
			if want, _ := attrs[path].(bool); want {
				policy, perr := pubsubDeadLetterPolicy(impl)
				if perr != nil {
					return provider.CreateResult{Status: "failed", Reason: perr.Error()}
				}
				sub["deadLetterPolicy"] = policy
			}
			masks = append(masks, "deadLetterPolicy")
		default:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("path %s is not patchable in place on a Pub/Sub subscription (ClassifyChange should have refused it)", path)}
		}
	}
	// ownership re-check immediately before the mutate (narrow the TOCTOU window; the
	// API gives no CAS token to close it fully).
	ours, _, found, rerr := d.pubsubGetSubscription(name, capability, environment)
	if rerr != nil {
		return provider.CreateResult{Status: "unknown", Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "subscription no longer exists — cannot update"}
	}
	if !ours {
		return provider.CreateResult{Status: "failed",
			Reason: "subscription labels do not match — refusing to patch a resource that is not ours"}
	}
	mask := strings.Join(masks, ",")
	url := d.subscriptionURL(project, name) + "?updateMask=" + mask
	status, body, err := d.call("PATCH", url, map[string]any{"subscription": sub, "updateMask": mask})
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("patch outcome unknown: %v", err)}
	}
	if status >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("patch HTTP %d (server error — may have landed) — reconcile", status)}
	}
	if status >= 400 {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("patch HTTP %d: %s", status, mutDetail(body))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
