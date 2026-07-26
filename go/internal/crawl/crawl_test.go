package crawl

import (
	"strings"
	"testing"
	"time"

	"groundhold/internal/discover"
	"groundhold/internal/pace"
	"groundhold/internal/pair"
)

func fixedClock(t time.Time) (pace.Clock, func() time.Time) {
	cur := t
	clk := pace.Clock{
		Now:    func() time.Time { return cur },
		Sleep:  func(d time.Duration) { cur = cur.Add(d) },
		Jitter: func() float64 { return 0.5 },
	}
	return clk, func() time.Time { return cur }
}

func reg(conns ...pair.Connection) *pair.Registry { return &pair.Registry{Pairings: conns} }

func conn(provider, scope string) pair.Connection {
	return pair.Connection{Provider: provider, Scope: scope,
		Credential: pair.CredentialRef{Kind: "aws-profile", Name: "x"}}
}

func okFetch(res ...discover.Resource) Fetcher {
	return func(pair.Connection, string) Fetched {
		return Fetched{Resources: res, Pace: pace.Result{Outcome: pace.OK}}
	}
}

func resource(id string) discover.Resource {
	return discover.Resource{ProviderID: id, ResourceType: "capability.database.relational",
		Observations: []discover.Observation{{Path: "service.managed", Value: true, Derivation: "measured"}}}
}

func TestCrawlHappyPath(t *testing.T) {
	clk, now := fixedClock(time.Unix(1000, 0))
	sched := pace.New(pace.DefaultPolicy(), clk)
	doc, err := Run(reg(conn("aws", "preprod")), okFetch(resource("aws:db-1"), resource("aws:db-2")),
		nil, sched, pace.DefaultPolicy().Budget, "2026-07-17T00:00:00Z", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Providers) != 1 || len(doc.Providers[0].Scopes) != 1 {
		t.Fatalf("shape: %+v", doc.Providers)
	}
	sc := doc.Providers[0].Scopes[0]
	if sc.Status != "complete" || len(sc.Resources) != 2 {
		t.Fatalf("scope: %+v", sc)
	}
	if sc.Resources[0].ObservedAt == "" {
		t.Fatal("each resource must carry its actual fetch time")
	}
	if doc.Crawl.RequestsMade != 1 || doc.ContextHash == "" {
		t.Fatalf("crawl stats/hash: %+v", doc.Crawl)
	}
}

func TestCrawlBackoffThenComplete(t *testing.T) {
	clk, now := fixedClock(time.Unix(0, 0))
	sched := pace.New(pace.DefaultPolicy(), clk)
	n := 0
	fetch := func(pair.Connection, string) Fetched {
		n++
		if n == 1 {
			return Fetched{Pace: pace.Result{Outcome: pace.Throttled, RetryAfter: 3 * time.Second}}
		}
		return Fetched{Resources: []discover.Resource{resource("aws:db")}, Pace: pace.Result{Outcome: pace.OK}}
	}
	doc, err := Run(reg(conn("aws", "preprod")), fetch, nil, sched, pace.DefaultPolicy().Budget,
		"2026-07-17T00:00:00Z", now)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Providers[0].Scopes[0].Status != "complete" {
		t.Fatalf("must complete after backoff: %+v", doc.Providers[0].Scopes[0])
	}
	if doc.Crawl.Throttled != 1 || doc.Crawl.Backoffs != 1 {
		t.Fatalf("gentleness honesty block wrong: %+v", doc.Crawl)
	}
}

func TestCrawlBudgetStopsAndIsVisible(t *testing.T) {
	pol := pace.DefaultPolicy()
	pol.Budget = 1
	clk, now := fixedClock(time.Unix(0, 0))
	sched := pace.New(pol, clk)
	doc, err := Run(reg(conn("aws", "a"), conn("gcp", "b")), okFetch(resource("r")),
		nil, sched, pol.Budget, "2026-07-17T00:00:00Z", now)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Crawl.StoppedEarly != "budget" {
		t.Fatalf("a budget stop must be visible, got %q", doc.Crawl.StoppedEarly)
	}
	// the second provider's scope must be recorded incomplete, never silently dropped
	var sawIncomplete bool
	for _, p := range doc.Providers {
		for _, s := range p.Scopes {
			if s.Status == "incomplete" && strings.Contains(s.Reason, "budget") {
				sawIncomplete = true
			}
		}
	}
	if !sawIncomplete {
		t.Fatalf("budget-cut scope must be recorded incomplete with a reason: %+v", doc.Providers)
	}
}

func TestCrawlBreakerMarksIncomplete(t *testing.T) {
	clk, now := fixedClock(time.Unix(0, 0))
	sched := pace.New(pace.DefaultPolicy(), clk)
	fetch := func(pair.Connection, string) Fetched {
		return Fetched{Pace: pace.Result{Outcome: pace.ServerError}}
	}
	doc, err := Run(reg(conn("aws", "preprod")), fetch, nil, sched, pace.DefaultPolicy().Budget,
		"2026-07-17T00:00:00Z", now)
	if err != nil {
		t.Fatal(err)
	}
	sc := doc.Providers[0].Scopes[0]
	if sc.Status != "incomplete" || !strings.Contains(sc.Reason, "breaker") {
		t.Fatalf("a broken provider's scope must be incomplete with the breaker reason: %+v", sc)
	}
	if doc.Crawl.StoppedEarly != "breaker" {
		t.Fatalf("breaker stop must be visible: %+v", doc.Crawl)
	}
}

// TestContentHashExcludesTiming proves identity is content-only: the same discovered
// content crawled at two different wall-clock times (different observedAt) hashes
// identically — gentleness timing never enters the fingerprint.
func TestContentHashExcludesTiming(t *testing.T) {
	run := func(base time.Time) *Document {
		clk, now := fixedClock(base)
		sched := pace.New(pace.DefaultPolicy(), clk)
		d, err := Run(reg(conn("aws", "preprod")), okFetch(resource("aws:db")),
			nil, sched, pace.DefaultPolicy().Budget, "2026-07-17T00:00:00Z", now)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	a := run(time.Unix(1000, 0))
	b := run(time.Unix(9999, 0))
	if a.Providers[0].Scopes[0].Resources[0].ObservedAt == b.Providers[0].Scopes[0].Resources[0].ObservedAt {
		t.Fatal("precondition: the two runs must stamp different observedAt")
	}
	if a.ContextHash != b.ContextHash {
		t.Fatalf("content hash must be timing-independent:\n a %s\n b %s", a.ContextHash, b.ContextHash)
	}
}

// enumScopes returns an enumerator that fans a no-scope pairing out to the given
// scopes (one paced request), all OK.
func enumScopes(scopes ...string) Enumerator {
	return func(pair.Connection) EnumResult {
		return EnumResult{Scopes: scopes, Pace: pace.Result{Outcome: pace.OK}}
	}
}

func TestCrawlEnumeratesScopesWhenNoneDeclared(t *testing.T) {
	clk, now := fixedClock(time.Unix(0, 0))
	sched := pace.New(pace.DefaultPolicy(), clk)
	// a pairing with an EMPTY scope fans out via the enumerator to two scopes
	doc, err := Run(reg(conn("gcp", "")), okFetch(resource("gcp:db")),
		enumScopes("proj-a", "proj-b"), sched, pace.DefaultPolicy().Budget,
		"2026-07-17T00:00:00Z", now)
	if err != nil {
		t.Fatal(err)
	}
	scopes := doc.Providers[0].Scopes
	if len(scopes) != 2 || scopes[0].Scope != "proj-a" || scopes[1].Scope != "proj-b" {
		t.Fatalf("enumeration must fan out to the listed scopes: %+v", scopes)
	}
	// one enumeration request + two fetches
	if doc.Crawl.RequestsMade != 3 {
		t.Fatalf("requests = %d, want 3 (1 enumerate + 2 fetch)", doc.Crawl.RequestsMade)
	}
}

func TestCrawlDeclaredScopeSkipsEnumeration(t *testing.T) {
	clk, now := fixedClock(time.Unix(0, 0))
	sched := pace.New(pace.DefaultPolicy(), clk)
	called := false
	enum := func(pair.Connection) EnumResult {
		called = true
		return EnumResult{Scopes: []string{"x"}, Pace: pace.Result{Outcome: pace.OK}}
	}
	doc, err := Run(reg(conn("gcp", "explicit")), okFetch(resource("gcp:db")),
		enum, sched, pace.DefaultPolicy().Budget, "2026-07-17T00:00:00Z", now)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("a pairing with an explicit scope must NOT enumerate")
	}
	if len(doc.Providers[0].Scopes) != 1 || doc.Providers[0].Scopes[0].Scope != "explicit" {
		t.Fatalf("declared scope must be crawled verbatim: %+v", doc.Providers[0].Scopes)
	}
}

func TestCrawlEnumerationFailureIsVisible(t *testing.T) {
	clk, now := fixedClock(time.Unix(0, 0))
	sched := pace.New(pace.DefaultPolicy(), clk)
	// enumeration keeps failing -> the breaker trips -> the provider is abandoned,
	// recorded as a visible incomplete marker, never a silently empty provider
	enum := func(pair.Connection) EnumResult {
		return EnumResult{Pace: pace.Result{Outcome: pace.ServerError}}
	}
	doc, err := Run(reg(conn("gcp", "")), okFetch(resource("gcp:db")),
		enum, sched, pace.DefaultPolicy().Budget, "2026-07-17T00:00:00Z", now)
	if err != nil {
		t.Fatal(err)
	}
	sc := doc.Providers[0].Scopes
	if len(sc) != 1 || sc[0].Status != "incomplete" || !strings.Contains(sc[0].Reason, "enumeration failed") {
		t.Fatalf("a failed enumeration must surface a visible incomplete marker: %+v", sc)
	}
}

// TestContentHashIsOrderIndependent pins the determinism the crawl identity rests
// on: enumerators (subscriptions.list, DescribeRegions) and fetchers return
// provider-API order, which is not contractually stable. Two documents with the
// SAME content in DIFFERENT array orders — scopes, resources within a scope,
// observations within a resource — must hash identically, or a re-crawl of
// unchanged infrastructure would report a phantom change (invariant #1).
func TestContentHashIsOrderIndependent(t *testing.T) {
	obs := func(p string) discover.Observation {
		return discover.Observation{Path: p, Value: "v-" + p, Derivation: "measured"}
	}
	res := func(id string, paths ...string) Resource {
		r := Resource{ProviderID: id, ResourceType: "capability.database.relational"}
		for _, p := range paths {
			r.Observations = append(r.Observations, obs(p))
		}
		return r
	}

	awsFwd := ProviderContext{
		Provider: "aws",
		Scopes: []ScopeContext{
			{Scope: "eu-central-1", Status: "complete", Resources: []Resource{
				res("aws:db-a", "availability.class", "service.managed"),
				res("aws:db-b", "encryption.atRest"),
			}},
			{Scope: "eu-west-1", Status: "complete", Resources: []Resource{
				res("aws:db-c", "backup.retention"),
			}},
		},
	}
	gcpFwd := ProviderContext{
		Provider: "gcp",
		Scopes: []ScopeContext{
			{Scope: "europe-west1", Status: "complete", Resources: []Resource{
				res("gcp:sql-x", "service.managed"),
			}},
		},
	}
	forward := &Document{Providers: []ProviderContext{awsFwd, gcpFwd}}

	// Same content, every array reversed: PROVIDER order (react.Splice appends a
	// new provider at the tail, unsorted), scope order, resource order within the
	// first scope, and observation order within db-a.
	reversed := &Document{Providers: []ProviderContext{
		gcpFwd,
		{
			Provider: "aws",
			Scopes: []ScopeContext{
				{Scope: "eu-west-1", Status: "complete", Resources: []Resource{
					res("aws:db-c", "backup.retention"),
				}},
				{Scope: "eu-central-1", Status: "complete", Resources: []Resource{
					res("aws:db-b", "encryption.atRest"),
					res("aws:db-a", "service.managed", "availability.class"),
				}},
			},
		},
	}}

	hf, err := ContentHash(forward)
	if err != nil {
		t.Fatalf("hash forward: %v", err)
	}
	hr, err := ContentHash(reversed)
	if err != nil {
		t.Fatalf("hash reversed: %v", err)
	}
	if hf != hr {
		t.Errorf("content hash must not depend on array order:\n forward  %s\n reversed %s", hf, hr)
	}

	// Negative control: a genuinely different value MUST change the hash — the
	// sort must not be flattening content away.
	changed := &Document{Providers: []ProviderContext{{
		Provider: "aws",
		Scopes: []ScopeContext{
			{Scope: "eu-central-1", Status: "complete", Resources: []Resource{
				{ProviderID: "aws:db-a", ResourceType: "capability.database.relational",
					Observations: []discover.Observation{{Path: "availability.class", Value: "DIFFERENT", Derivation: "measured"}}},
			}},
		},
	}}}
	hc, err := ContentHash(changed)
	if err != nil {
		t.Fatalf("hash changed: %v", err)
	}
	if hc == hf {
		t.Errorf("a different observation value must change the hash")
	}
}

// Two observations sharing a PATH but differing in value/derivation must feed the
// ContextHash in a stable order regardless of the order the crawler returned them
// — Path alone is not a total order, so sort-by-path-alone left equal paths in
// enumeration order and hashed that. Mirrors discover's #159 guard.
func TestContentHashIsOrderIndependentForDuplicatePaths(t *testing.T) {
	doc := func(obs ...discover.Observation) *Document {
		return &Document{Providers: []ProviderContext{{
			Provider: "aws",
			Scopes: []ScopeContext{{Scope: "eu-central-1", Status: "complete",
				Resources: []Resource{{ProviderID: "aws:db-a",
					ResourceType: "capability.database.relational", Observations: obs}}}},
		}}}
	}
	a := doc(
		discover.Observation{Path: "tag.owner", Value: "x", Derivation: "measured"},
		discover.Observation{Path: "tag.owner", Value: "y", Derivation: "config-intent"},
		discover.Observation{Path: "service.managed", Value: true, Derivation: "measured"},
	)
	// same three, enumerated in a different order.
	b := doc(
		discover.Observation{Path: "service.managed", Value: true, Derivation: "measured"},
		discover.Observation{Path: "tag.owner", Value: "y", Derivation: "config-intent"},
		discover.Observation{Path: "tag.owner", Value: "x", Derivation: "measured"},
	)
	ha, err := ContentHash(a)
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}
	hb, err := ContentHash(b)
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	if ha != hb {
		t.Errorf("context hash depends on enumeration order for duplicate paths:\n a %s\n b %s", ha, hb)
	}
}
