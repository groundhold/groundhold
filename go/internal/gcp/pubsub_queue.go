// Pub/Sub queue request building (D95): the semantic core of the GCP
// messaging.queue driver — the SAME capability.messaging.queue vocabulary AWS
// SQS fulfils (the provider-agnostic thesis, D85). A Pub/Sub "queue" has no
// single native resource: it is a CONSTITUTIVE COMPOSITE (the ECS precedent,
// D86/D94) of a SUBSCRIPTION (the durable backlog the author owns) plus a
// backing TOPIC (the publish address the subscription pulls from). The two are
// created/observed/retired ATOMICALLY under ONE binding — the subscription id
// IS the providerId, the topic is created in the same sequence under the SAME
// deterministic name (topics and subscriptions are separate namespaces, so the
// name may be shared) and is retired on delete. The author never names or varies
// the topic.
//
// THE residency honesty point is inherited from the topic (D94): Pub/Sub is
// GLOBAL by default, so location.region maps to the BACKING topic's
// messageStoragePolicy.allowedPersistenceRegions, NOT the API host — create
// ALWAYS pins it, observe refuses to report a region for a global backing topic.
package gcp

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"groundhold/internal/scalars"
)

// pubsubDLTopicOK bounds a dead-letter TOPIC operand (D26/D73). A dead-letter
// target is a separate Pub/Sub topic referenced by its FULL resource name
// (projects/<project>/topics/<topic>) — the shape the subscription's
// deadLetterPolicy.deadLetterTopic requires (mirrors the SQS DLQ ARN gate).
var pubsubDLTopicOK = regexp.MustCompile(
	`^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/topics/[A-Za-z][A-Za-z0-9_.~+%-]{2,254}$`)

// QueueName is the deterministic name shared by the subscription AND its
// constitutive backing topic (separate Pub/Sub namespaces, so one name serves
// both — the single handle that keeps the composite under ONE binding). The
// capability salts the hash, so a queue and a topic in the same project never
// collide.
func QueueName(project, environment, capability string, generation int) string {
	name := resourceName(project, environment, capability, generation, 255)
	if strings.HasPrefix(name, "goog") {
		name = "q" + name
	}
	return name
}

// PubSubQueuePlan is the ordered create sequence: the backing topic FIRST (its
// residency/CMEK is the crux), then the subscription that references it.
type PubSubQueuePlan struct {
	Name      string
	TopicBody map[string]any
	SubBody   map[string]any
	Public    bool
}

// BuildPubSubQueuePlan maps capability.messaging.queue attributes + the impl
// block to the topic body and the subscription body. Every error is a refusal
// apply surfaces in preflight, before any mutation — never a silently dropped
// attribute, never a clamp.
func BuildPubSubQueuePlan(project, environment, capability string,
	attrs, impl map[string]any, generation int) (PubSubQueuePlan, error) {

	if generation < 1 {
		generation = 1
	}
	name := QueueName(project, environment, capability, generation)
	labels := map[string]any{
		"groundhold-capability":  sanitizeLabel(capability),
		"groundhold-environment": sanitizeLabel(environment),
	}
	topicBody := map[string]any{"labels": labels}
	subBody := map[string]any{
		// the subscription references the backing topic by RESOURCE NAME (never a
		// URL) — stable regardless of the API host, so the composite stays bound.
		"topic":  fmt.Sprintf("projects/%s/topics/%s", project, name),
		"labels": labels,
	}

	region := ""
	cmek := false
	public := false
	deadLetter := false

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
				return PubSubQueuePlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored by Pub/Sub " +
						"(messages are always encrypted at rest)")
			}
		case "encryption.customerManagedKeys":
			cmek, _ = raw.(bool)
		case "network.publicExposure":
			// public exposure is an IAM grant (allUsers subscriber) the shell
			// applies to the SUBSCRIPTION after create — nothing in either body.
			b, ok := raw.(bool)
			if !ok {
				return PubSubQueuePlan{}, fmt.Errorf("network.publicExposure must be a boolean")
			}
			public = b
		case "delivery.guarantee":
			g, _ := raw.(string)
			switch g {
			case "exactly-once":
				// the SUBSCRIPTION's broker guarantee — necessary, not sufficient
				// for exactly-once PROCESSING (needs producer dedup + correct ack).
				subBody["enableExactlyOnceDelivery"] = true
			case "at-least-once", "":
				// the Pub/Sub baseline
			default:
				return PubSubQueuePlan{}, fmt.Errorf("delivery.guarantee %q is not a valid value", g)
			}
		case "ordering.enabled":
			if b, _ := raw.(bool); b {
				subBody["enableMessageOrdering"] = true
			}
		case "reliability.deadLetter":
			// posture bool: only true is meaningful (false = no dead-letter policy,
			// Pub/Sub's default — nothing on the subscription body).
			deadLetter, _ = raw.(bool)
		case "retention.minimum":
			s, err := scalars.Parse(raw)
			if err != nil || s.Kind != scalars.Duration {
				return PubSubQueuePlan{}, fmt.Errorf("retention.minimum is not a duration")
			}
			ms, ok := s.Value.(float64)
			if !ok {
				return PubSubQueuePlan{}, fmt.Errorf("retention.minimum is not a duration")
			}
			secs := ms / 1000
			if secs != float64(int64(secs)) {
				return PubSubQueuePlan{}, fmt.Errorf(
					"retention.minimum must be a whole number of seconds, got %v", secs)
			}
			// Pub/Sub subscription messageRetentionDuration envelope: 10m .. 31d.
			// Outside -> REFUSE loudly (vocab: never clamp a data-loss floor).
			if secs < 600 || secs > 2678400 {
				return PubSubQueuePlan{}, fmt.Errorf(
					"retention.minimum %ds is outside the Pub/Sub envelope (600s..2678400s) — "+
						"refusing rather than clamping", int64(secs))
			}
			subBody["messageRetentionDuration"] = fmt.Sprintf("%ds", int64(secs))
		case "service.managed":
			if raw != true {
				return PubSubQueuePlan{}, fmt.Errorf("service.managed=false cannot be honored by Pub/Sub")
			}
		default:
			return PubSubQueuePlan{}, fmt.Errorf(
				"attribute %s has no Pub/Sub mapping — refusing rather than "+
					"silently dropping it", path)
		}
	}

	if cmek {
		key, _ := impl["kms_key_name"].(string)
		if key == "" {
			return PubSubQueuePlan{}, fmt.Errorf(
				"encryption.customerManagedKeys requires implementation.kms_key_name " +
					"(a Cloud KMS key resource) — the Google-managed default does not satisfy it")
		}
		// CMEK is a property of the BACKING topic (where messages are stored).
		topicBody["kmsKeyName"] = key
	}

	if region == "" {
		return PubSubQueuePlan{}, fmt.Errorf("pubsub queue requires location.region (the message storage region)")
	}
	if !gcpName.MatchString(region) {
		return PubSubQueuePlan{}, fmt.Errorf(
			"location.region %q is not a valid GCP region identifier", region)
	}
	// THE residency honesty point: a global backing topic does not satisfy a
	// residency contract, so the storage policy is ALWAYS pinned to the region.
	topicBody["messageStoragePolicy"] = map[string]any{
		"allowedPersistenceRegions": []any{region},
	}

	// Dead-letter posture (reliability.deadLetter): the semantic is "messages
	// unprocessed after N delivery attempts go to a dead-letter TOPIC, not lost";
	// the target topic + attempt threshold are impl operands (D26). deadLetter=true
	// PRESUPPOSES both — refuse loudly on a missing operand rather than create a
	// subscription that silently forwards nothing to a dead-letter topic.
	if deadLetter {
		policy, err := pubsubDeadLetterPolicy(impl)
		if err != nil {
			return PubSubQueuePlan{}, err
		}
		subBody["deadLetterPolicy"] = policy
	}

	return PubSubQueuePlan{Name: name, TopicBody: topicBody, SubBody: subBody, Public: public}, nil
}

// pubsubDeadLetterPolicy maps the reliability.deadLetter operands (impl block, D26)
// to a Pub/Sub subscription deadLetterPolicy: the dead-letter TOPIC (a separate
// Pub/Sub topic that catches messages unprocessed after maxDeliveryAttempts) plus
// the attempt threshold. Both are required — deadLetter=true presupposes them.
// Shared by the create builder and the update path (symmetric with the SQS
// RedrivePolicy). maxDeliveryAttempts is Pub/Sub's own 5..100 envelope — refuse
// outside it rather than clamp a data-loss threshold.
func pubsubDeadLetterPolicy(impl map[string]any) (map[string]any, error) {
	topic, _ := impl["dead_letter_topic"].(string)
	if topic == "" {
		return nil, fmt.Errorf(
			"reliability.deadLetter=true requires implementation.dead_letter_topic " +
				"(the resource name projects/<project>/topics/<topic> of a separate " +
				"Pub/Sub topic to catch messages unprocessed after maxDeliveryAttempts)")
	}
	if !pubsubDLTopicOK.MatchString(topic) {
		return nil, fmt.Errorf(
			"implementation.dead_letter_topic %q is not a valid Pub/Sub topic resource "+
				"name (projects/<project>/topics/<topic>)", topic)
	}
	attempts, ok := pubsubIntOperand(impl["max_delivery_attempts"])
	if !ok {
		return nil, fmt.Errorf(
			"reliability.deadLetter=true requires implementation.max_delivery_attempts " +
				"(a whole number of delivery attempts before a message is forwarded to " +
				"the dead-letter topic)")
	}
	if attempts < 5 || attempts > 100 {
		return nil, fmt.Errorf(
			"implementation.max_delivery_attempts %d is outside the Pub/Sub envelope (5..100)", attempts)
	}
	return map[string]any{"deadLetterTopic": topic, "maxDeliveryAttempts": attempts}, nil
}

// pubsubIntOperand pulls a whole-number operand from the free-form impl block
// (D26), which may arrive as int / int64 / float64 depending on the loader.
func pubsubIntOperand(raw any) (int, bool) {
	switch v := raw.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		if v != float64(int64(v)) {
			return 0, false
		}
		return int(v), true
	}
	return 0, false
}

// pubsubRetentionDuration parses a retention.minimum duration scalar into the Pub/Sub
// messageRetentionDuration form ("<n>s"), enforcing the same 600s..2678400s envelope
// the create path does — never clamping a data-loss floor. Shared by the update path.
func pubsubRetentionDuration(raw any) (string, error) {
	sc, err := scalars.Parse(raw)
	if err != nil || sc.Kind != scalars.Duration {
		return "", fmt.Errorf("retention.minimum is not a duration")
	}
	ms, ok := sc.Value.(float64)
	if !ok {
		return "", fmt.Errorf("retention.minimum is not a duration")
	}
	secs := ms / 1000
	if secs != float64(int64(secs)) {
		return "", fmt.Errorf("retention.minimum must be a whole number of seconds, got %v", secs)
	}
	if secs < 600 || secs > 2678400 {
		return "", fmt.Errorf(
			"retention.minimum %ds is outside the Pub/Sub envelope (600s..2678400s) — refusing rather than clamping", int64(secs))
	}
	return fmt.Sprintf("%ds", int64(secs)), nil
}
