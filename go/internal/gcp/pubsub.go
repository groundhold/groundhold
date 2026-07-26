// Pub/Sub request building (D94): the semantic core of the GCP messaging.topic
// driver — the SAME capability.messaging.topic vocabulary AWS SNS fulfils (the
// provider-agnostic thesis, D85). A topic is created with a SYNCHRONOUS PUT
// (no LRO, unlike Cloud Run/SQL). A topic holds nothing the author owns
// (subscribers own their copies), so the mapping is thin: labels (ownership),
// a customer KMS key, a message-storage policy for residency, and IAM for the
// public-publish gate (a network-shell concern).
//
// THE critical honesty point: Pub/Sub is GLOBAL by default. location.region
// maps to messageStoragePolicy.allowedPersistenceRegions, NOT the API host. A
// residency contract "satisfied" by a global topic (no storage policy) would be
// a compliance lie — so create ALWAYS pins the storage policy, and observe
// refuses to report a region for a topic that has no storage policy.
package gcp

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const pubsubBaseURL = "https://pubsub.googleapis.com/v1"

// pubsubNameOK bounds a topic name for the providerId parser (D73): the safe
// subset the driver generates (a leading letter, then alnum + . _ -), never the
// full Pub/Sub charset (which permits %, +, ~ — risky in a URL path).
var pubsubNameOK = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{2,254}$`)

// TopicName is the deterministic Pub/Sub topic name (the idempotency mechanism —
// topics.create/PUT dedupes on the name). Pub/Sub names are 3-255 chars, start
// with a letter, and may NOT start with "goog"; resourceName already guarantees
// a leading letter, so only the reserved prefix needs guarding.
func TopicName(project, environment, capability string, generation int) string {
	name := resourceName(project, environment, capability, generation, 255)
	if strings.HasPrefix(name, "goog") {
		name = "t" + name
	}
	return name
}

// BuildPubSubCreateRequest maps capability.messaging.topic attributes + the impl
// block to a topics PUT. Every error is a refusal apply surfaces in preflight,
// before any mutation — never a silently dropped attribute.
func BuildPubSubCreateRequest(project, environment, capability string,
	attrs, impl map[string]any, generation int) (Request, error) {

	if generation < 1 {
		generation = 1
	}
	name := TopicName(project, environment, capability, generation)
	body := map[string]any{
		"labels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
	}
	region := ""
	cmek := false

	paths := make([]string, 0, len(attrs))
	for p := range attrs {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			region, _ = raw.(string)
		case "encryption.atRest":
			// Pub/Sub always encrypts at rest — true is satisfied by construction,
			// false cannot be honored (there is no unencrypted mode).
			if raw != true {
				return Request{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored by Pub/Sub " +
						"(messages are always encrypted at rest)")
			}
		case "encryption.customerManagedKeys":
			cmek, _ = raw.(bool)
		case "network.publicExposure":
			// public exposure is an IAM grant (allUsers publisher) the network
			// shell applies after create — nothing in the topic body. Only the
			// type is validated here (a non-bool would be a malformed candidate).
			if _, ok := raw.(bool); !ok {
				return Request{}, fmt.Errorf("network.publicExposure must be a boolean")
			}
		case "service.managed":
			if raw != true {
				return Request{}, fmt.Errorf("service.managed=false cannot be honored by Pub/Sub")
			}
		default:
			return Request{}, fmt.Errorf(
				"attribute %s has no Pub/Sub mapping — refusing rather than "+
					"silently dropping it", path)
		}
	}

	if cmek {
		key, _ := impl["kms_key_name"].(string)
		if key == "" {
			return Request{}, fmt.Errorf(
				"encryption.customerManagedKeys requires implementation.kms_key_name " +
					"(a Cloud KMS key resource) — the Google-managed default does not satisfy it")
		}
		body["kmsKeyName"] = key
	}

	if region == "" {
		return Request{}, fmt.Errorf("pubsub requires location.region (the message storage region)")
	}
	// region is interpolated into the message-storage policy body, not a path,
	// but bound its charset anyway (defence in depth, D73).
	if !gcpName.MatchString(region) {
		return Request{}, fmt.Errorf(
			"location.region %q is not a valid GCP region identifier", region)
	}
	// THE residency honesty point: a global topic does not satisfy a residency
	// contract, so the storage policy is ALWAYS pinned to the declared region.
	body["messageStoragePolicy"] = map[string]any{
		"allowedPersistenceRegions": []any{region},
	}

	url := fmt.Sprintf("%s/projects/%s/topics/%s", pubsubBaseURL, project, name)
	return Request{Method: "PUT", URL: url, Body: body}, nil
}
