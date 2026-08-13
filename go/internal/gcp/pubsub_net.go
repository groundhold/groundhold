// Pub/Sub network shell + security (D94): the thin, httptest-covered half of the
// GCP messaging.topic driver. Topic create is a SYNCHRONOUS PUT (no LRO). Public
// publish is an allUsers roles/pubsub.publisher IAM binding — the same
// version-3 read-modify-write-confirm honesty as Cloud Run / GCS (etag CAS,
// append-only, domain-restricted-sharing surfaced by name, never "succeeded" for
// a partial grant). Ownership is LABELS; a topic name is scoped to the project
// (no global namespace, so no D82 cross-project squat concern here).
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func (d *Driver) pubsubBase() string {
	if d.PubSubBaseURL != "" {
		return d.PubSubBaseURL
	}
	return pubsubBaseURL
}

// pubsubProviderID is service-prefixed; topics are global, so no region — the
// residency region rides in the message-storage policy, never the identity.
func pubsubProviderID(project, name string) string {
	return "pubsub:" + project + ":" + name
}

// splitPubSubProviderID validates every component before path interpolation
// (D73). The accepted name charset is the safe subset the driver generates
// (alnum + . _ -), never the full Pub/Sub set (which permits %, +, ~ — risky in
// a URL path).
func splitPubSubProviderID(providerID string) (project, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "pubsub" {
		return "", "", fmt.Errorf("providerId %q is not pubsub:project:name", providerID)
	}
	if !gcpName.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId project %q is not a valid identifier", parts[1])
	}
	if !pubsubNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId topic name %q is not a valid topic name", parts[2])
	}
	return parts[1], parts[2], nil
}

func (d *Driver) topicURL(project, name string) string {
	return d.pubsubBase() + "/projects/" + project + "/topics/" + name
}

type topicDoc struct {
	Name                 string            `json:"name"`
	Labels               map[string]string `json:"labels"`
	KmsKeyName           string            `json:"kmsKeyName"`
	MessageStoragePolicy struct {
		AllowedPersistenceRegions []string `json:"allowedPersistenceRegions"`
	} `json:"messageStoragePolicy"`
}

// createPubSub: build -> PUT (synchronous) -> (if public) grant allUsers
// publisher. A same-name topic that is not ours (labels) is refused; one whose
// live residency/CMEK config differs is refused too (update is not wired).
func (d *Driver) createPubSub(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	req, err := BuildPubSubCreateRequest(d.Project, environment, capability,
		attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	name := TopicName(d.Project, environment, capability, generation)
	// the topic name is deterministic, so the providerId is knowable BEFORE the
	// PUT response — a lost/garbled outcome (D29) must carry it (handle never lost).
	pid := pubsubProviderID(d.Project, name)
	public, _ := attrs["network.publicExposure"].(bool)
	wantRegion, _ := attrs["location.region"].(string)
	wantKey, _ := impl["kms_key_name"].(string)
	if cmek, _ := attrs["encryption.customerManagedKeys"].(bool); !cmek {
		wantKey = ""
	}
	req.URL = d.topicURL(d.Project, name) // rebuild for the test base

	status, body, err := d.call(req.Method, req.URL, req.Body)
	if err != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown: %v", err)}
	}
	switch {
	case status == http.StatusConflict:
		// exists — continue ONLY if ours AND its live config matches (update is
		// not wired). Topic names are project-scoped, so this is our own prior
		// create, an idempotent retry, or a foreign topic in this project.
		ours, doc, found, rerr := d.pubsubGetTopic(name, capability, environment)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing topic gave no answer — reconcile: " + rerr.Error()}
		}
		if !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, but the conflicting topic was gone on the follow-up read — reconcile"}
		}
		if !ours {
			return provider.CreateResult{Status: "failed",
				Reason: "a topic with this name exists but is not ours (labels do not match)"}
		}
		if !regionsMatch(doc.MessageStoragePolicy.AllowedPersistenceRegions, wantRegion) {
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf(
				"existing topic storage regions %v do not match desired residency %q "+
					"and pubsub update is not wired — reconcile",
				doc.MessageStoragePolicy.AllowedPersistenceRegions, wantRegion)}
		}
		if doc.KmsKeyName != wantKey {
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf(
				"existing topic CMEK key %q does not match desired %q and pubsub "+
					"update is not wired — reconcile", doc.KmsKeyName, wantKey)}
		}
	case status >= 400:
		res := mutationResult("create", status, body)
		if res.Status == "unknown" {
			res.ProviderID = pid // 5xx may have landed — keep the deterministic handle
		}
		return res
	default:
		var b struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(body, &b) != nil || b.Name == "" {
			// a 2xx create MUST echo the topic resource; an empty/garbled body
			// means the mutation may have landed (D29) — never a false succeeded.
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "create response carried no topic — reconcile"}
		}
	}

	if public {
		if unknown, err := d.setTopicPublic(d.Project, name); err != nil {
			st := "failed"
			if unknown {
				st = "unknown"
			}
			return provider.CreateResult{ProviderID: pid, Status: st, Reason: err.Error()}
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// regionsMatch reports whether a topic's storage policy pins EXACTLY the desired
// residency region — a superset/subset is a residency mismatch, not a match.
func regionsMatch(got []string, want string) bool {
	return len(got) == 1 && got[0] == want
}

// pubsubGetTopic returns ownership, the live topic document, whether the topic
// exists, and why a read failed — a failed read is never "not ours", and a 404
// is an authoritative absence rather than a failure.
func (d *Driver) pubsubGetTopic(name, capability, environment string) (ours bool, doc topicDoc, found bool, err error) {
	const op = "topics.get"
	status, body, cerr := d.call("GET", d.topicURL(d.Project, name), nil)
	if cerr != nil {
		return false, topicDoc{}, false, readTransport(op, cerr)
	}
	if status == http.StatusNotFound {
		return false, topicDoc{}, false, nil
	}
	if status != http.StatusOK {
		return false, topicDoc{}, false, readHTTP(op, status, gcpErrCode(body))
	}
	if json.Unmarshal(body, &doc) != nil {
		return false, topicDoc{}, false, readBody(op, status)
	}
	ours = doc.Labels["groundhold-capability"] == sanitizeLabel(capability) &&
		doc.Labels["groundhold-environment"] == sanitizeLabel(environment)
	return ours, doc, true, nil
}

// setTopicPublic grants allUsers roles/pubsub.publisher via a version-3
// read-modify-write (etag preserved, append-only), then re-reads to confirm.
// Returns unknown=true only when the MUTATING setIamPolicy response was lost
// (D29: never "failed"). Reuses the shared getRunPolicyForWrite/readRunPolicy
// (generic on the resource base) + appendMember/hasMember/isDomainRestricted.
func (d *Driver) setTopicPublic(project, name string) (unknown bool, err error) {
	base := d.topicURL(project, name)
	bindings, etag, err := d.getRunPolicyForWrite(base)
	if err != nil {
		return false, fmt.Errorf("public exposure: %v", err) // reads are definitive
	}
	bindings = appendMember(bindings, "roles/pubsub.publisher", "allUsers")

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
	pub, cerr := d.confirmTopicPublic(project, name)
	switch {
	case pub:
		return false, nil
	case cerr != nil:
		return true, fmt.Errorf("public exposure: setIamPolicy returned 200 but "+
			"the binding could not be confirmed (%v) — reconcile", cerr)
	default:
		return false, fmt.Errorf("public exposure: allUsers publisher binding " +
			"did not take (org policy or a conditional binding may interfere)")
	}
}

func (d *Driver) confirmTopicPublic(project, name string) (public bool, err error) {
	bindings, perr := d.readRunPolicy(d.topicURL(project, name))
	if perr != nil {
		return false, perr
	}
	for _, b := range bindings {
		if b["role"] == "roles/pubsub.publisher" && hasMember(b, "allUsers") {
			return true, nil
		}
	}
	return false, nil
}

func (d *Driver) readTopicPublic(project, name string) (public bool, err error) {
	bindings, perr := d.readRunPolicy(d.topicURL(project, name))
	if perr != nil {
		return false, perr
	}
	for _, b := range bindings {
		role, _ := b["role"].(string)
		if role == "roles/pubsub.publisher" &&
			(hasMember(b, "allUsers") || hasMember(b, "allAuthenticatedUsers")) {
			return true, nil
		}
	}
	return false, nil
}

// observePubSub reverse-maps a live topic. The residency mapping is the honesty
// crux: a topic with NO message-storage policy is GLOBAL and carries no
// residency guarantee, so location.region is NOT observed (a diagnostic), never
// defaulted — a global topic must never look like it satisfies a residency
// contract.
func (d *Driver) observePubSub(capability, providerID string) ([]provider.Observation, []string, error) {
	project, name, err := splitPubSubProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	status, body, err := d.call("GET", d.topicURL(project, name), nil)
	if err != nil {
		return nil, nil, err
	}
	// F-LC3 (D519): a 404 here is a READABLE absence, not a failure to read.
	// Folded into the generic error it made the binding block forever on
	// unknown instead of re-creating; the contract reserves a marker for it.
	if status == http.StatusNotFound {
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"bound resource is gone (will re-create)"}, nil
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("topics.get: HTTP %d", status)
	}
	var doc topicDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, nil, fmt.Errorf("topics.get: unparseable topic document")
	}

	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
	}
	var diags []string
	obs = append(obs,
		provider.Observation{Path: "encryption.atRest", Value: true, Derivation: "platform-invariant"}, // always encrypts
		provider.Observation{Path: "service.managed", Value: true, Derivation: "measured"},
	)
	// customerManagedKeys: present iff the topic carries a CMEK, read from the topic
	// GET. Absent means the Google-managed default — a MEASURED false, not an absence
	// (D1040/D1003): emit the bool for BOTH states so a `customerManagedKeys: true`
	// candidate cannot be adopted over a Google-managed topic.
	obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
		Value: doc.KmsKeyName != "", Derivation: "measured"})
	// residency: the honesty crux.
	switch regions := doc.MessageStoragePolicy.AllowedPersistenceRegions; len(regions) {
	case 0:
		diags = append(diags, "location.region not observed: the topic has no "+
			"messageStoragePolicy — it is GLOBAL and carries no residency guarantee "+
			"(a residency contract cannot be satisfied by a global topic)")
	case 1:
		obs = append(obs, provider.Observation{Path: "location.region",
			Value: regions[0], Derivation: "measured"})
	default:
		diags = append(diags, fmt.Sprintf("location.region not observed: the "+
			"messageStoragePolicy pins multiple regions (%v) — cannot map to a "+
			"single residency region", regions))
	}
	// publicExposure: an allUsers/allAuthenticatedUsers publisher binding. An
	// unreadable IAM policy emits a diagnostic and NOTHING (never default-safe).
	pub, perr := d.readTopicPublic(project, name)
	if perr != nil {
		diags = append(diags, "network.publicExposure not observed: "+perr.Error())
	} else {
		obs = append(obs, provider.Observation{Path: "network.publicExposure",
			Value: pub, Derivation: "measured"})
	}
	return obs, diags, nil
}

// deletePubSub: ownership (labels) pre-read, then DELETE. 404 is idempotent
// success. Pub/Sub topics carry no etag/generation, so there is no delete-time
// CAS (a small TOCTOU window the ownership pre-read narrows but cannot close).
func (d *Driver) deletePubSub(capability, environment, providerID string) provider.CreateResult {
	project, name, err := splitPubSubProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	status, body, err := d.call("GET", d.topicURL(project, name), nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-delete read failed: %v", err)}
	}
	if status == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if status != http.StatusOK {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("pre-delete read: HTTP %d", status)}
	}
	var doc topicDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: "pre-delete read unparseable — refusing an ambiguous delete"}
	}
	if doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
		doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "topic labels do not match — refusing to delete a resource that is not ours"}
	}
	status, respBody, err := d.call("DELETE", d.topicURL(project, name), nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if status == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent race
	}
	if status >= 400 {
		res := mutationResult("delete", status, respBody)
		if res.Status == "unknown" {
			res.ProviderID = providerID
		}
		return res
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// setTopicPrivate revokes the allUsers roles/pubsub.publisher binding via the same
// version-3 read-modify-write setTopicPublic uses (etag preserved as the CAS), then
// re-reads to confirm the topic is no longer public. unknown=true only when the
// MUTATING setIamPolicy response was lost (D29), never "failed".
func (d *Driver) setTopicPrivate(project, name string) (unknown bool, err error) {
	base := d.topicURL(project, name)
	bindings, etag, err := d.getRunPolicyForWrite(base)
	if err != nil {
		return false, fmt.Errorf("remove public exposure: %v", err)
	}
	bindings = removeMember(bindings, "roles/pubsub.publisher", "allUsers")
	status, body, cerr := d.call("POST", base+":setIamPolicy",
		map[string]any{"policy": map[string]any{
			"version": iamPolicyVersion, "bindings": bindings, "etag": etag}})
	if cerr != nil {
		return true, fmt.Errorf("remove public exposure: setIamPolicy outcome unknown — reconcile: %v", cerr)
	}
	if status >= 500 {
		return true, fmt.Errorf("remove public exposure: setIamPolicy HTTP %d (server error — may have landed) — reconcile: %s", status, mutDetail(body))
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("remove public exposure: setIamPolicy HTTP %d: %s", status, mutDetail(body))
	}
	pub, cerr := d.confirmTopicPublic(project, name)
	switch {
	case cerr != nil:
		return true, fmt.Errorf("remove public exposure: setIamPolicy returned 200 but the policy could not be confirmed (%v) — reconcile", cerr)
	case pub:
		return false, fmt.Errorf("remove public exposure: the allUsers publisher binding is still present after the write")
	default:
		return false, nil
	}
}

// updatePubSub patches a topic's mutable attributes in place (D129 update slice,
// symmetric with the SNS update). Only network.publicExposure is wired in this slice —
// a grant or revoke of the allUsers publisher binding (the etag is the CAS). Ownership
// (labels) is re-checked first; ClassifyChange (classifyPubSubChange) already gated the
// change set, so a non-exposure path here is a bug — refused, never silently applied.
func (d *Driver) updatePubSub(capability, environment, providerID string,
	attrs map[string]any, changes []string) provider.CreateResult {
	project, name, err := splitPubSubProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	ours, _, found, rerr := d.pubsubGetTopic(name, capability, environment)
	if rerr != nil {
		return provider.CreateResult{Status: "unknown", Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "topic no longer exists — cannot update"}
	}
	if !ours {
		return provider.CreateResult{Status: "failed",
			Reason: "topic labels do not match — refusing to patch a resource that is not ours"}
	}
	for _, path := range changes {
		if path != "network.publicExposure" {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("path %s is not patchable in place on Pub/Sub (ClassifyChange should have refused it)", path)}
		}
		desired, _ := attrs[path].(bool)
		var unknown bool
		if desired {
			unknown, err = d.setTopicPublic(project, name)
		} else {
			unknown, err = d.setTopicPrivate(project, name)
		}
		if err != nil {
			st := "failed"
			if unknown {
				st = "unknown"
			}
			return provider.CreateResult{ProviderID: providerID, Status: st, Reason: err.Error()}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
