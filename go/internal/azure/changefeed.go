// Azure Event Grid change-event feed request building (capability.observability.
// changefeed): the Azure observability.changefeed driver. An Event Grid event
// subscription at SUBSCRIPTION scope (Microsoft.EventGrid/eventSubscriptions on
// /subscriptions/{id}) delivers the Azure subscription's resource-change events to
// a StorageQueue the operator drains — groundhold PROVISIONS the feed so `react` can
// consume changes real-time instead of polling. The queue (feed.target) is
// pre-existing substrate the feed REFERENCES; the feed never owns its lifecycle
// (the capability's D26 operand boundary).
//
// The event subscription is a proxy resource: no tags, no location, no sku — so
// ownership is the DETERMINISTIC content-addressed name (the azcustomrole pattern),
// not a tag. v0.1 captures broadly (no coverage/event-type filters — that grammar
// is deliberately absent from the vocab, filter in `react`).
package azure

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const changeFeedAPIVersion = "2025-02-15"

// A StorageQueue destination stores the STORAGE ACCOUNT resource id + a queue name
// separately, but a contract declares ONE verifiable string. feed.target is the
// full storage-queue resource id; the driver splits it on this literal into the
// (accountId, queueName) the ARM body needs, and observe re-composes it — an exact
// round-trip so a reverse-mapped feed.target equals what was declared.
const queuePathSep = "/queueServices/default/queues/"

var (
	// A storage account resource id, bounded before it enters the request body.
	storageAccountIDOK = regexp.MustCompile(
		`^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9._()-]{1,90}/providers/Microsoft\.Storage/storageAccounts/[a-z0-9]{3,24}$`)
	// A storage queue name: 3-63 chars, lowercase alphanumeric and hyphens,
	// starting and ending alphanumeric.
	queueNameOK = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
)

type ChangeFeedPlan struct {
	Name             string // the event-subscription name (deterministic identity)
	Environment      string
	Capability       string
	StorageAccountID string // destination.properties.resourceId
	QueueName        string // destination.properties.queueName
	FeedTarget       string // the canonical feed.target (full queue resource id)
}

func changeFeedName(environment, capability string, generation int) string {
	return azResourceName("pv-cf", environment, capability, generation)
}

// composeFeedTarget is the inverse of parsing: (accountId, queueName) -> the
// canonical feed.target string, so observe re-derives exactly what create consumed.
func composeFeedTarget(storageAccountID, queueName string) string {
	return storageAccountID + queuePathSep + queueName
}

// parseFeedTarget splits a feed.target into its storage account id + queue name,
// validating both. A malformed target is a refusal (refuse-before-mutate), never a
// silently dropped or half-built destination.
func parseFeedTarget(target string) (storageAccountID, queueName string, err error) {
	i := strings.Index(target, queuePathSep)
	if i < 0 {
		return "", "", fmt.Errorf(
			"feed.target %q is not a storage-queue resource id "+
				"(expected <storageAccountId>%s<queueName>)", target, queuePathSep)
	}
	storageAccountID = target[:i]
	queueName = target[i+len(queuePathSep):]
	if !storageAccountIDOK.MatchString(storageAccountID) {
		return "", "", fmt.Errorf(
			"feed.target storage account %q is not a Microsoft.Storage/storageAccounts resource id", storageAccountID)
	}
	if !queueNameOK.MatchString(queueName) {
		return "", "", fmt.Errorf(
			"feed.target queue name %q is not a valid Azure storage queue name (3-63 lowercase alphanumeric/hyphen)", queueName)
	}
	return storageAccountID, queueName, nil
}

// BuildChangeFeed maps capability.observability.changefeed attributes to an Event
// Grid event-subscription plan. Every error is a refusal apply surfaces in
// preflight — no attribute is silently dropped (D43).
func BuildChangeFeed(environment, capability string,
	attrs, impl map[string]any, generation int) (ChangeFeedPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := ChangeFeedPlan{
		Environment: environment, Capability: capability,
		Name: changeFeedName(environment, capability, generation),
	}

	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	var haveTarget bool
	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "feed.target":
			target, _ := raw.(string)
			if target == "" {
				return ChangeFeedPlan{}, fmt.Errorf("feed.target must be a non-empty string")
			}
			sa, q, err := parseFeedTarget(target)
			if err != nil {
				return ChangeFeedPlan{}, err
			}
			p.StorageAccountID, p.QueueName, p.FeedTarget = sa, q, composeFeedTarget(sa, q)
			haveTarget = true
		case "service.managed":
			if raw != true {
				return ChangeFeedPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored: Event Grid is a managed change feed, " +
						"not a self-operated log tailer")
			}
		default:
			return ChangeFeedPlan{}, fmt.Errorf(
				"attribute %s has no Azure Event Grid changefeed mapping — refusing rather than "+
					"silently dropping it (capability.observability.changefeed v0.1 is feed.target + service.managed only)", path)
		}
	}
	if !haveTarget {
		return ChangeFeedPlan{}, fmt.Errorf(
			"azure changefeed requires feed.target (the storage-queue resource id events are delivered to)")
	}
	return p, nil
}
