package crawl

import (
	"testing"
	"time"

	"groundhold/internal/pace"
)

// D592. Measured on the live cluster. A base crawl listed `kube-system` at 20:16 and
// recorded 14 resources. A fifteenth was then created there. `react` re-listed only
// `default` — the event's scope — spliced it into the base, and produced a document
// stamped `at: 20:20` carrying:
//
//	default      status=complete   8 resources   (listed at 20:20)
//	kube-system  status=complete  14 resources   (listed at 20:16)
//
// The document therefore states that AS OF 20:20 the kube-system scope COMPLETELY
// contained fourteen resources. It contained fifteen. Nothing in the document says
// when either scope was listed, so a splice silently re-dates every scope it did not
// touch.
//
// This is not cosmetic. `status: complete` is what `shadowLowerBound` rests on: it is
// the claim that a shadow count is a real lower bound rather than a number. Posture
// reads these scopes and classifies resources as managed or shadow from them, so a
// scope whose listing has aged is presented with exactly the authority of one just
// read. The whole point of the completeness field is to stop a count meaning less
// than it looks — and the freshness of that completeness was unrecorded.
//
// A scope now carries when it was listed. That is the minimum honest fix: it does not
// decide what posture should DO about a stale scope (a semantics change), it stops
// the document from claiming a currency it does not have.
func TestCrawlStampsEachScopeItLists(t *testing.T) {
	// Through Run, not a struct literal. The first version of this test built a
	// ScopeContext by hand and set the field itself — proving the field exists and
	// nothing about whether the crawl fills it. The mutation meter removed the
	// stamping and the test still passed, which is D564's shape in the test written
	// to close D592.
	clk, now := fixedClock(time.Unix(1000, 0))
	sched := pace.New(pace.DefaultPolicy(), clk)
	const at = "2026-07-31T20:16:00Z"
	doc, err := Run(reg(conn("aws", "preprod")), okFetch(resource("aws:db-1")),
		nil, sched, pace.DefaultPolicy().Budget, at, now)
	if err != nil {
		t.Fatal(err)
	}
	scopes := 0
	for _, p := range doc.Providers {
		for _, s := range p.Scopes {
			scopes++
			if s.ListedAt != at {
				t.Errorf("scope %q was listed by this run and carries listedAt=%q — a "+
					"splice would then re-date it to whenever it next runs", s.Scope, s.ListedAt)
			}
		}
	}
	if scopes == 0 {
		t.Fatal("the crawl produced no scopes — this test would pass on anything")
	}
}

// The timing must NOT reach the hashed model. The identity model's own comment says
// it covers content "WITHOUT any timing (observedAt, crawl stats, at)" — and for a
// good reason: a hash that moves every time you crawl cannot answer "is this the same
// world?", which is the only question it is for.
func TestListedAtStaysOutOfTheContextHash(t *testing.T) {
	mk := func(listed string) string {
		d := &Document{At: "2026-07-31T20:20:00Z", Providers: []ProviderContext{{
			Provider: "k8s",
			Scopes: []ScopeContext{{Scope: "default", Status: "complete",
				ListedAt: listed, Resources: []Resource{{ProviderID: "a", ResourceType: "t"}}}},
		}}}
		h, err := ContentHash(d)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	if mk("2026-07-31T20:16:00Z") != mk("2026-07-31T20:20:00Z") {
		t.Error("the context hash moved when only the listing TIME changed — a hash " +
			"that differs on every crawl cannot tell whether the world differs")
	}
}
