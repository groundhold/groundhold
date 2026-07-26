// GCP Cloud Asset Inventory change-feed request building (D141/D142): the
// semantic core of the GCP capability.observability.changefeed driver — the
// OPT-IN path from the polling crawl to real-time posture. A feed captures
// infrastructure MUTATIONS and delivers asset-change notifications to a Pub/Sub
// topic (the feed.target), so `groundhold react` (or any consumer) drains the
// topic and reacts instead of polling.
//
// THE core semantic is feed.target — WHERE the changes go. A Cloud Asset feed
// forwards events; it references an existing Pub/Sub topic, it does NOT own the
// topic's lifecycle (D26 — a separate capability/operand provisions the topic).
// v0.1 is minimal: feed.target + service.managed, nothing else. The feed
// captures broadly (assetTypes ".*", contentType RESOURCE) and leaves coverage
// filtering to `react` (the cloud grammars differ; the capability governs only
// that changes ARE captured and delivered somewhere consumable).
package gcp

import (
	"fmt"
	"regexp"
)

const assetFeedBaseURL = "https://cloudasset.googleapis.com/v1"

// feedIDOK bounds a Cloud Asset feed id for the providerId parser (D73): a
// leading letter, then letters/digits/underscore/hyphen — the safe subset
// resourceName generates and the feeds API accepts.
var feedIDOK = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,99}$`)

// assetFeedTopicOK bounds feed.target — a fully-qualified Pub/Sub topic path
// "projects/<project>/topics/<topic>". The topic rides in the request BODY (not
// a URL path), but a malformed target is a malformed contract: refuse it in
// preflight rather than let the API reject it after the lease.
var assetFeedTopicOK = regexp.MustCompile(
	`^projects/([a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,20})/topics/[A-Za-z][A-Za-z0-9._~%+-]{2,254}$`)

// AssetFeedID is the deterministic feed id (the idempotency mechanism — feeds
// are content-addressed by (project, feedId), so a lost create re-creates the
// same id). Feed ids are <=100 chars, start with a letter.
func AssetFeedID(project, environment, capability string, generation int) string {
	return resourceName(project, environment, capability, generation, 100)
}

// AssetFeedPlan is the attribute-derived shape a create assembles.
type AssetFeedPlan struct {
	FeedID string
	Target string // the Pub/Sub topic: projects/<p>/topics/<t>
}

// BuildAssetFeed maps capability.observability.changefeed attributes + impl to a
// plan. Every error is a preflight refusal, never a silently dropped attribute.
func BuildAssetFeed(project, environment, capability string,
	attrs, impl map[string]any, generation int) (AssetFeedPlan, error) {

	if generation < 1 {
		generation = 1
	}
	if !projectOK.MatchString(project) {
		return AssetFeedPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	p := AssetFeedPlan{FeedID: AssetFeedID(project, environment, capability, generation)}

	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "feed.target":
			p.Target, _ = raw.(string)
			if !assetFeedTopicOK.MatchString(p.Target) {
				return AssetFeedPlan{}, fmt.Errorf(
					"feed.target %q is not a fully-qualified Pub/Sub topic "+
						"(want projects/<project>/topics/<topic>)", p.Target)
			}
		case "service.managed":
			if raw != true {
				return AssetFeedPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored by Cloud Asset Inventory " +
						"(a Cloud Asset feed is a managed change feed)")
			}
		default:
			return AssetFeedPlan{}, fmt.Errorf(
				"attribute %s has no Cloud Asset feed mapping — refusing rather than "+
					"silently dropping it", path)
		}
	}

	if p.Target == "" {
		return AssetFeedPlan{}, fmt.Errorf(
			"changefeed requires feed.target (the Pub/Sub topic change events land in)")
	}
	return p, nil
}

// createBody is the CreateFeed request body: POST v1/{parent=projects/*}/feeds.
// The feed captures broadly (all asset types, RESOURCE content) and forwards to
// the target topic; feed.name MUST be empty in a create (the API assigns it).
func (p AssetFeedPlan) createBody() map[string]any {
	return map[string]any{
		"feedId": p.FeedID,
		"feed": map[string]any{
			"feedOutputConfig": map[string]any{
				"pubsubDestination": map[string]any{"topic": p.Target},
			},
			"assetTypes":  []any{".*"},
			"contentType": "RESOURCE",
		},
	}
}
