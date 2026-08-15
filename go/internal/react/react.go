// Package react is the event-driven ingress (candidate D143): the opt-in path from
// the polling crawl (D141) to real-time posture (D142). A single cloud change event
// — delivered by the cloud's OWN bus (EventBridge/Pub-Sub/Event Grid), never a
// groundhold daemon — is mapped to (provider, scope) COORDINATES ONLY: no byte of the
// payload becomes a fact. groundhold then re-lists just that scope (read-only,
// authenticated) and SPLICES the fresh listing into the last full crawl, so a new
// shadow resource surfaces in seconds without a full re-crawl. The event is a HINT,
// never evidence, and never the source of truth — the periodic crawl remains the
// completeness backstop; every spliced document is superseded by the next full
// sweep. Arrival is non-deterministic; the reaction is deterministic given the
// (envelope, base-context, --at), and sits outside the verifier.
package react

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"groundhold/internal/crawl"
	"groundhold/internal/discover"
)

// Event is the mapped coordinate of a change: which provider+scope to re-read.
type Event struct {
	Kind     string `json:"kind"`
	Provider string `json:"provider"`
	Scope    string `json:"scope"`
	Hint     string `json:"hint,omitempty"` // the triggering change (diagnostic only)
}

// ParseEvent maps ONE change-event envelope to coordinates. It handles the groundhold
// test-event kind and the AWS EventBridge envelope. It reads only the routing
// fields — the payload's data never enters any document, so a forged or replayed
// event can at worst trigger one paced, read-only re-list of an already-paired
// scope.
// ErrNothingToReactTo marks a WELL-FORMED frame that carries no resource coordinate
// — a watch BOOKMARK or ERROR. D591: these used to return the same error as a
// document nothing could parse, so a stream consumer routing on the outcome could not
// tell "a routine frame, nothing to do" from "I could not understand this event and
// dropped it". The second means the real-time path is losing changes, which is the
// failure react exists to prevent; they must not read alike.
var ErrNothingToReactTo = errors.New("frame carries no resource coordinate")

func ParseEvent(raw []byte) (Event, error) {
	var e Event
	if json.Unmarshal(raw, &e) == nil && e.Kind == "groundhold/test-event/v0" {
		if e.Provider == "" || e.Scope == "" {
			return Event{}, fmt.Errorf("groundhold/test-event/v0 requires provider and scope")
		}
		return e, nil
	}
	// AWS EventBridge: {"source":"aws.s3"|"aws.cloudtrail",...,"detail":{"awsRegion","eventName"}}
	var eb struct {
		Source string `json:"source"`
		Detail struct {
			AWSRegion string `json:"awsRegion"`
			EventName string `json:"eventName"`
		} `json:"detail"`
	}
	if json.Unmarshal(raw, &eb) == nil && strings.HasPrefix(eb.Source, "aws.") && eb.Detail.AWSRegion != "" {
		return Event{Kind: "aws.eventbridge", Provider: "aws", Scope: eb.Detail.AWSRegion, Hint: eb.Detail.EventName}, nil
	}
	// Kubernetes native-watch: {"type":"ADDED|MODIFIED|DELETED","object":{"kind",
	// "metadata":{"namespace","name"}}}. k8s' watch is a STANDING stream — no feed to
	// provision (spec/drivers.md §3), so this is the app-layer's real-time source. The
	// event carries only routing coordinates: scope = the object's namespace (a
	// cluster-scoped object has none, so it re-lists cluster-wide). A DELETE is honest
	// too — the freshened namespace listing simply no longer contains the object. Watch
	// BOOKMARK/ERROR frames carry no resource coordinate and are ignored loudly.
	var wk struct {
		Type   string `json:"type"`
		Object struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Namespace string `json:"namespace"`
				Name      string `json:"name"`
			} `json:"metadata"`
		} `json:"object"`
	}
	if json.Unmarshal(raw, &wk) == nil && wk.Object.Kind != "" &&
		(wk.Type == "ADDED" || wk.Type == "MODIFIED" || wk.Type == "DELETED") {
		return Event{
			Kind:     "k8s.watch",
			Provider: "k8s",
			Scope:    wk.Object.Metadata.Namespace,
			Hint:     wk.Type + " " + wk.Object.Kind + "/" + wk.Object.Metadata.Name,
		}, nil
	}
	// A watch frame we DO recognise as watch-shaped, carrying no resource to re-list
	// (BOOKMARK, ERROR), is nothing to react to — not a parse failure (D591).
	// Only the frame types that carry no resource BY DEFINITION are benign. An
	// ADDED/MODIFIED/DELETED without an object is malformed, not routine, and calling
	// it benign would drop a real change as if it were a bookmark.
	if wk.Type == "BOOKMARK" || wk.Type == "ERROR" {
		return Event{}, fmt.Errorf("%w: watch %s frame", ErrNothingToReactTo, wk.Type)
	}
	return Event{}, fmt.Errorf("unrecognised event envelope (expected groundhold/test-event/v0, an AWS EventBridge event, or a Kubernetes watch event)")
}

// FreshScope builds the re-listed scope's context from a discovery result, stamping
// each resource at `stamp`. Crucially the scope's completeness is READ from the re-list,
// never assumed: a driver that truncated its listing (a page went unread) returns partial
// results with NO error, and a hardcoded "complete" here would launder that into an
// affirmative complete claim — spliced OVER a prior honest incomplete and letting posture
// exit 0 over a scope where a shadow may sit on the unread page. react is the unattended
// stream path where exit 0 reads "all clear"; the count must stay a lower bound (D803/D873).
func FreshScope(scope, listedAt, stamp string, res *discover.Result) crawl.ScopeContext {
	sc := crawl.ScopeContext{Scope: scope, Status: "complete", ListedAt: listedAt,
		Resources: []crawl.Resource{}}
	if res.Incomplete {
		sc.Status = "incomplete"
		sc.Reason = res.IncompleteReason
	}
	for _, r := range res.Discovery.Resources {
		sc.Resources = append(sc.Resources, crawl.Resource{
			ProviderID: r.ProviderID, ResourceType: r.ResourceType,
			Observations: r.Observations, ObservedAt: stamp})
	}
	return sc
}

// Splice replaces the (provider, scope) block of base with a freshly re-listed scope
// and recomputes the content hash. Other scopes keep the last full crawl's content
// (each scope is a self-contained content block). base may be nil — a first event
// with no prior crawl yields a document with just this scope. The result is honest:
// every scope carries a real listing; per-resource ObservedAt (identity-excluded)
// distinguishes the freshened scope from the sweep's.
func Splice(base *crawl.Document, provider, scope, at string, fresh crawl.ScopeContext) (*crawl.Document, error) {
	doc := &crawl.Document{At: at}
	replaced := false
	if base != nil {
		doc.Crawl = base.Crawl
		for _, p := range base.Providers {
			np := crawl.ProviderContext{Provider: p.Provider, Diagnostics: p.Diagnostics}
			if p.Provider == provider {
				for _, s := range p.Scopes {
					if s.Scope == scope {
						np.Scopes = append(np.Scopes, fresh)
						replaced = true
					} else {
						np.Scopes = append(np.Scopes, s)
					}
				}
			} else {
				np.Scopes = append(np.Scopes, p.Scopes...)
			}
			doc.Providers = append(doc.Providers, np)
		}
	}
	if !replaced {
		// the provider/scope was not in the base crawl — add it
		var pc *crawl.ProviderContext
		for i := range doc.Providers {
			if doc.Providers[i].Provider == provider {
				pc = &doc.Providers[i]
			}
		}
		if pc == nil {
			doc.Providers = append(doc.Providers, crawl.ProviderContext{Provider: provider})
			pc = &doc.Providers[len(doc.Providers)-1]
		}
		pc.Scopes = append(pc.Scopes, fresh)
	}
	h, err := crawl.ContentHash(doc)
	if err != nil {
		return nil, err
	}
	doc.ContextHash = h
	return doc, nil
}
