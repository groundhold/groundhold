// GCP Cloud Asset Inventory change-feed network shell (D141/D142): the
// bearer-signed half of the capability.observability.changefeed driver. A feed
// is content-addressed by (project, feedId) — the feedId is deterministic, so
// the providerId is knowable BEFORE the create response (a lost create is
// unknown, reconcile by the same id). observe reverse-maps the feed's Pub/Sub
// topic back to feed.target.
//
// Ownership honesty: a Cloud Asset feed carries NO labels or description field,
// so ownership is asserted by the deterministic feedId namespace
// (content-addressing) — the create 409 path additionally verifies the existing
// feed's target TOPIC matches ours before continuing, so a feed that exists at
// our id but points elsewhere is refused, never silently adopted.
//
// Endpoints (cloudasset.googleapis.com/v1):
//
//	CreateFeed  POST   {parent=projects/*}/feeds   body {feedId, feed}
//	GetFeed     GET    {name=projects/*/feeds/*}
//	DeleteFeed  DELETE {name=projects/*/feeds/*}
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func (d *Driver) assetFeedBase() string {
	if d.AssetFeedBaseURL != "" {
		return d.AssetFeedBaseURL
	}
	return assetFeedBaseURL
}

func assetFeedProviderID(project, feedID string) string {
	return "assetfeed:" + project + ":" + feedID
}

func splitAssetFeedProviderID(providerID string) (project, feedID string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "assetfeed" {
		return "", "", fmt.Errorf("providerId %q is not assetfeed:project:feedId", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !feedIDOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId feedId %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

type assetFeedDoc struct {
	Name             string `json:"name"`
	FeedOutputConfig struct {
		PubsubDestination struct {
			Topic string `json:"topic"`
		} `json:"pubsubDestination"`
	} `json:"feedOutputConfig"`
}

func (doc assetFeedDoc) topic() string { return doc.FeedOutputConfig.PubsubDestination.Topic }

// assetFeedName builds the {name} the Cloud Asset feeds.get and feeds.delete
// endpoints demand. Unlike feeds.create — whose {parent} accepts the project ID —
// get and delete REJECT a project ID in the name ("Feed name must be in the format
// of projects|folders|organizations/<number>/feeds/<feed_identifier>") and require
// the project NUMBER. project is the providerId's project, which sameProject has
// already pinned to d.Project, so its number is ourProjectNumber().
//
// Field 2026-08-10: get/delete built the name with the ID, so both 400'd forever —
// a retire's pre-delete read never answered, the delete never fired, and the feed
// was orphaned while resume reported "pending" indefinitely (worse than nothing).
func (d *Driver) assetFeedName(feedID string) (string, error) {
	num, err := d.ourProjectNumber()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/projects/%s/feeds/%s", d.assetFeedBase(), num, feedID), nil
}

func (d *Driver) getAssetFeed(project, feedID string) (assetFeedDoc, bool, error) {
	const op = "assetFeed.get"
	url, err := d.assetFeedName(feedID)
	if err != nil {
		return assetFeedDoc{}, false, readTransport(op, err)
	}
	st, body, err := d.call("GET", url, nil)
	if err != nil {
		return assetFeedDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return assetFeedDoc{}, false, nil
	}
	if st != http.StatusOK {
		return assetFeedDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc assetFeedDoc
	if json.Unmarshal(body, &doc) != nil {
		return assetFeedDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createAssetFeed(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAssetFeed(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := assetFeedProviderID(d.Project, plan.FeedID)
	url := fmt.Sprintf("%s/projects/%s/feeds", d.assetFeedBase(), d.Project)
	st, body, e := d.call("POST", url, plan.createBody())
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", e)}
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st == http.StatusConflict:
		doc, found, rerr := d.getAssetFeed(d.Project, plan.FeedID)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "feedId conflict, existing feed gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || doc.topic() != plan.Target {
			return provider.CreateResult{Status: "failed",
				Reason: "a feed with this id exists and points at a different topic — not ours"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // idempotent
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
	}
}

func (d *Driver) observeAssetFeed(capability, providerID string) ([]provider.Observation, []string, error) {
	project, feedID, err := splitAssetFeedProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getAssetFeed(project, feedID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"change feed not found — bound resource is gone (will re-create)"}, nil
	}
	if doc.topic() == "" {
		return []provider.Observation{
			// D802: the feed EXISTS — it simply has no destination. Clearing the absence
			// marker says so; the attributes stay unobserved and the diagnostic explains
			// why. An empty return would have read as "gone".
			{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		}, []string{"change feed has no Pub/Sub destination — nothing anyone can drain"}, nil
	}
	return []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "feed.target", Value: doc.topic(), Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}, nil, nil
}

func (d *Driver) deleteAssetFeed(capability, environment, providerID string) provider.CreateResult {
	project, feedID, err := splitAssetFeedProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// Ownership is content-addressed: the feedId lives in groundhold's deterministic
	// namespace (feeds carry no labels). Confirm existence, then delete the pinned
	// id — removing the feed only stops future delivery (stateful:false; already
	// delivered events stay in the target topic).
	// OWNERSHIP (D451): the comment above already reasons that the id "lives in
	// groundhold's deterministic namespace (feeds carry no labels)" — it never checked
	// that the id is one we would produce.
	if !nameLooksOursGCP(feedID, capability, environment, "", "-", nameOK, 8) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("asset feed %q is not named by groundhold for %s/%s — "+
				"refusing to delete a feed this contract does not own", feedID, capability, environment)}
	}
	_, found, rerr := d.getAssetFeed(project, feedID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	url, err := d.assetFeedName(feedID)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "delete could not resolve the feed name — reconcile: " + err.Error()}
	}
	st, body, e := d.call("DELETE", url, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
