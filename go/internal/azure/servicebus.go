// Azure Service Bus request building (D99): the Azure half of the messaging domain
// (D94/D95), making messaging symmetric across all three clouds. Two capabilities,
// two constitutive composites: a namespace + a queue (messaging.queue), or a
// namespace + a topic (messaging.topic) — the namespace is the constitutive
// substrate (like the storage account / ACA environment), created/tagged/retired
// with the binding. Standard SKU (topics + sessions + dedup need Standard+).
//
// Honest mappings: retention.minimum -> defaultMessageTimeToLive (the unconsumed-
// message survival window, exactly as SQS MessageRetentionPeriod / Pub-Sub
// messageRetentionDuration); delivery.guarantee=exactly-once -> requiresDuplicate
// Detection (broker dedup window — necessary, not sufficient, like SQS FIFO);
// ordering.enabled -> requiresSession (ordered within a session key). CMK is
// namespace-level and Premium-only -> REFUSED on the Standard baseline.
//
// reliability.deadLetter (fala 2, parity with SQS RedrivePolicy / Pub-Sub
// deadLetterPolicy) diverges HONESTLY on Azure: a Service Bus queue does NOT get a
// SEPARATE dead-letter queue the way SQS/Pub-Sub do — every queue has a BUILT-IN
// sub-queue ($DeadLetterQueue) that ALWAYS exists. So there is no dead-letter TARGET
// to name (no ARN / topic operand). What is governable is WHEN a message is
// dead-lettered: properties.maxDeliveryCount (attempts before a message moves to the
// built-in DLQ) and properties.deadLetteringOnMessageExpiration (TTL-expired messages
// go to the DLQ instead of vanishing). reliability.deadLetter=true therefore means
// "dead-lettering is configured intentionally": we require impl.max_delivery_count (a
// whole number, 1..2000 Azure envelope) and set deadLetteringOnMessageExpiration=true.
package azure

import (
	"fmt"
	"sort"
)

const serviceBusAPIVersion = "2022-10-01-preview"

type ServiceBusPlan struct {
	Namespace   string
	Entity      string // queue or topic name
	IsTopic     bool
	Region      string
	Environment string
	Capability  string
	Public      bool
	TTLDays     int64 // retention.minimum (queue only)
	Dedup       bool  // delivery.guarantee=exactly-once (queue only)
	Session     bool  // ordering.enabled (queue only)
	DeadLetter  bool  // reliability.deadLetter (queue only): dead-lettering configured intentionally
	MaxDelivery int   // properties.maxDeliveryCount (queue only, set iff DeadLetter)
}

func serviceBusNamespace(environment, capability string, generation int) string {
	return azResourceName("pv-sb", environment, capability, generation)
}

// BuildServiceBusQueue maps capability.messaging.queue to a Service Bus plan.
func BuildServiceBusQueue(environment, capability string,
	attrs, impl map[string]any, generation int) (ServiceBusPlan, error) {
	p := ServiceBusPlan{Environment: environment, Capability: capability,
		Namespace: serviceBusNamespace(environment, capability, generation),
		Entity:    azResourceName("q", environment, capability, generation)}
	for _, path := range sortedAttrKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "delivery.guarantee":
			switch raw {
			case "at-least-once":
				p.Dedup = false
			case "exactly-once":
				p.Dedup = true // broker duplicate detection (necessary, not sufficient)
			default:
				return ServiceBusPlan{}, fmt.Errorf("delivery.guarantee %v has no Service Bus mapping", raw)
			}
		case "ordering.enabled":
			p.Session, _ = raw.(bool) // requiresSession: ordered within a session
		case "reliability.deadLetter":
			// posture bool: only true is meaningful (false = Azure's default
			// dead-lettering — the built-in DLQ still exists, we just do not raise
			// deadLetteringOnMessageExpiration nor pin a custom maxDeliveryCount).
			p.DeadLetter, _ = raw.(bool)
		case "retention.minimum":
			d, err := durationDays(raw)
			if err != nil {
				return ServiceBusPlan{}, fmt.Errorf("retention.minimum: %v", err)
			}
			p.TTLDays = d
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "encryption.atRest":
			if raw != true {
				return ServiceBusPlan{}, fmt.Errorf("encryption.atRest=false cannot be honored (Service Bus is always encrypted)")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				return ServiceBusPlan{}, fmt.Errorf(
					"encryption.customerManagedKeys is not honored on the Standard Service Bus " +
						"baseline: CMK is a namespace-level Premium-only feature (a different SKU + a " +
						"managed identity) — refusing rather than silently downgrading to platform keys")
			}
		case "service.managed":
			if raw != true {
				return ServiceBusPlan{}, fmt.Errorf("service.managed=false cannot be honored by Service Bus")
			}
		default:
			return ServiceBusPlan{}, fmt.Errorf(
				"attribute %s has no Service Bus queue mapping — refusing rather than silently dropping it", path)
		}
	}
	if p.Region == "" {
		return ServiceBusPlan{}, fmt.Errorf("azure service bus requires location.region")
	}
	// Dead-letter posture (reliability.deadLetter): unlike SQS/Pub-Sub there is NO
	// separate dead-letter target to name — the queue's built-in $DeadLetterQueue is
	// always present. The operand is the retry threshold (maxDeliveryCount) that
	// decides WHEN a message is dead-lettered; deadLetter=true presupposes it. Refuse
	// loudly on a missing/out-of-envelope operand rather than pin an arbitrary count.
	if p.DeadLetter {
		mdc, ok := sbIntOperand(impl["max_delivery_count"])
		if !ok {
			return ServiceBusPlan{}, fmt.Errorf(
				"reliability.deadLetter=true requires implementation.max_delivery_count " +
					"(a whole number of delivery attempts before a message moves to the " +
					"queue's built-in dead-letter sub-queue; Azure has no separate DLQ target)")
		}
		if mdc < 1 || mdc > 2000 {
			return ServiceBusPlan{}, fmt.Errorf(
				"implementation.max_delivery_count %d is outside the Service Bus envelope (1..2000)", mdc)
		}
		p.MaxDelivery = mdc
	}
	return p, nil
}

// sbIntOperand pulls a whole-number operand from the free-form impl block (D26),
// which may arrive as int / int64 / float64 depending on the loader.
func sbIntOperand(raw any) (int, bool) {
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

// classifyServiceBusQueueChange (D46): which capability.messaging.queue transitions
// can a Service Bus queue honor IN PLACE? reliability.deadLetter (maxDeliveryCount +
// deadLetteringOnMessageExpiration) and retention.minimum (defaultMessageTimeToLive)
// are patchable on the queue entity via a queues PUT (create-or-update). The
// create-time delivery/ordering type (requiresDuplicateDetection/requiresSession) is
// immutable — a change is a replacement. Region is the namespace's (create-time).
// Public exposure is a NAMESPACE property this queue-entity updater does not touch —
// honest "unsupported" rather than a silent claim. Platform/projection props have
// nothing to patch. Symmetric with classifyPubSubQueueChange / classifySQSChange.
func classifyServiceBusQueueChange(path string) (string, string) {
	switch path {
	case "reliability.deadLetter", "retention.minimum":
		return "mutable", "in-place via a Service Bus queues PUT (maxDeliveryCount / deadLetteringOnMessageExpiration / defaultMessageTimeToLive)"
	case "delivery.guarantee", "ordering.enabled":
		return "immutable", "requiresDuplicateDetection/requiresSession are create-time only on a Service Bus queue — a change is a replacement"
	case "location.region":
		return "immutable", "region is the namespace's create-time location — a change is a replacement"
	case "network.publicExposure":
		return "unsupported", "publicNetworkAccess is a namespace-level property the queue-entity updater does not patch in this slice"
	case "encryption.customerManagedKeys":
		return "unsupported", "CMK is a namespace-level Premium-only feature — refused at build, not patchable here"
	case "encryption.atRest", "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Service Bus queue in-place mapping for " + path
	}
}

// BuildServiceBusTopic maps capability.messaging.topic to a Service Bus plan.
func BuildServiceBusTopic(environment, capability string,
	attrs, impl map[string]any, generation int) (ServiceBusPlan, error) {
	p := ServiceBusPlan{Environment: environment, Capability: capability, IsTopic: true,
		Namespace: serviceBusNamespace(environment, capability, generation),
		Entity:    azResourceName("t", environment, capability, generation)}
	for _, path := range sortedAttrKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "encryption.atRest":
			if raw != true {
				return ServiceBusPlan{}, fmt.Errorf("encryption.atRest=false cannot be honored (Service Bus is always encrypted)")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				return ServiceBusPlan{}, fmt.Errorf(
					"encryption.customerManagedKeys is not honored on the Standard Service Bus " +
						"baseline: CMK is a namespace-level Premium-only feature — refused")
			}
		case "service.managed":
			if raw != true {
				return ServiceBusPlan{}, fmt.Errorf("service.managed=false cannot be honored by Service Bus")
			}
		default:
			return ServiceBusPlan{}, fmt.Errorf(
				"attribute %s has no Service Bus topic mapping — refusing rather than silently dropping it", path)
		}
	}
	if p.Region == "" {
		return ServiceBusPlan{}, fmt.Errorf("azure service bus requires location.region")
	}
	return p, nil
}

func sortedAttrKeys(attrs map[string]any) []string {
	out := make([]string, 0, len(attrs))
	for k := range attrs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
