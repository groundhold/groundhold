package react

import (
	"testing"

	"groundhold/internal/crawl"
)

func TestParseEventTestKind(t *testing.T) {
	e, err := ParseEvent([]byte(`{"kind":"groundhold/test-event/v0","provider":"fake","scope":"demo","hint":"created"}`))
	if err != nil || e.Provider != "fake" || e.Scope != "demo" || e.Hint != "created" {
		t.Fatalf("test-event parse: %+v err %v", e, err)
	}
	if _, err := ParseEvent([]byte(`{"kind":"groundhold/test-event/v0","scope":"demo"}`)); err == nil {
		t.Fatal("a test-event with no provider must refuse")
	}
}

func TestParseEventBridge(t *testing.T) {
	e, err := ParseEvent([]byte(`{"source":"aws.s3","detail":{"awsRegion":"eu-west-1","eventName":"CreateBucket"}}`))
	if err != nil || e.Provider != "aws" || e.Scope != "eu-west-1" || e.Hint != "CreateBucket" {
		t.Fatalf("eventbridge parse: %+v err %v", e, err)
	}
	if _, err := ParseEvent([]byte(`{"unrelated":true}`)); err == nil {
		t.Fatal("an unrecognised envelope must refuse")
	}
}

func TestParseEventK8sWatch(t *testing.T) {
	// a namespaced object -> scope is its namespace, provider k8s
	e, err := ParseEvent([]byte(`{"type":"ADDED","object":{"kind":"NetworkPolicy","metadata":{"namespace":"payments","name":"np"}}}`))
	if err != nil || e.Provider != "k8s" || e.Scope != "payments" || e.Kind != "k8s.watch" {
		t.Fatalf("k8s watch parse: %+v err %v", e, err)
	}
	if e.Hint != "ADDED NetworkPolicy/np" {
		t.Fatalf("hint = %q", e.Hint)
	}
	// a DELETE routes the same coordinates — the freshened namespace re-list reflects the absence
	if e, err := ParseEvent([]byte(`{"type":"DELETED","object":{"kind":"Role","metadata":{"namespace":"team","name":"r"}}}`)); err != nil || e.Scope != "team" {
		t.Fatalf("k8s delete parse: %+v err %v", e, err)
	}
	// a cluster-scoped object carries no namespace -> scope "" (cluster-wide re-list)
	if e, err := ParseEvent([]byte(`{"type":"MODIFIED","object":{"kind":"ClusterRole","metadata":{"name":"admin"}}}`)); err != nil || e.Provider != "k8s" || e.Scope != "" {
		t.Fatalf("cluster-scoped watch parse: %+v err %v", e, err)
	}
	// BOOKMARK/ERROR frames carry no resource coordinate -> loudly unrecognised
	if _, err := ParseEvent([]byte(`{"type":"BOOKMARK","object":{"kind":"NetworkPolicy","metadata":{}}}`)); err == nil {
		t.Fatal("a BOOKMARK watch frame must not be a routable event")
	}
}

func baseDoc() *crawl.Document {
	return &crawl.Document{At: "t0", Providers: []crawl.ProviderContext{{
		Provider: "aws",
		Scopes: []crawl.ScopeContext{
			{Scope: "eu-west-1", Status: "complete", Resources: []crawl.Resource{{ProviderID: "s3:old"}}},
			{Scope: "us-east-1", Status: "complete", Resources: []crawl.Resource{{ProviderID: "s3:other"}}},
		}}}}
}

func hasResource(sc crawl.ScopeContext, id string) bool {
	for _, r := range sc.Resources {
		if r.ProviderID == id {
			return true
		}
	}
	return false
}

func TestSpliceReplacesScopeLeavingOthers(t *testing.T) {
	fresh := crawl.ScopeContext{Scope: "eu-west-1", Status: "complete",
		Resources: []crawl.Resource{{ProviderID: "s3:old"}, {ProviderID: "s3:new-bucket"}}}
	doc, err := Splice(baseDoc(), "aws", "eu-west-1", "t1", fresh)
	if err != nil {
		t.Fatal(err)
	}
	var eu, us crawl.ScopeContext
	for _, s := range doc.Providers[0].Scopes {
		if s.Scope == "eu-west-1" {
			eu = s
		}
		if s.Scope == "us-east-1" {
			us = s
		}
	}
	if !hasResource(eu, "s3:new-bucket") {
		t.Fatal("the freshly listed scope must carry the new resource")
	}
	if !hasResource(us, "s3:other") || len(us.Resources) != 1 {
		t.Fatal("the untouched scope must keep the last crawl's content verbatim")
	}
	if doc.ContextHash == "" || doc.At != "t1" {
		t.Fatalf("spliced doc must carry a fresh hash + at: %+v", doc.At)
	}
}

func TestSpliceAddsAScopeAbsentFromBase(t *testing.T) {
	fresh := crawl.ScopeContext{Scope: "eu-west-1", Status: "complete",
		Resources: []crawl.Resource{{ProviderID: "s3:new"}}}
	// nil base: a first event with no prior crawl
	doc, err := Splice(nil, "aws", "eu-west-1", "t1", fresh)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Providers) != 1 || len(doc.Providers[0].Scopes) != 1 ||
		!hasResource(doc.Providers[0].Scopes[0], "s3:new") {
		t.Fatalf("a first-event splice must produce the single scope: %+v", doc.Providers)
	}
}

// TestSpliceHashIsContentOnly proves the same spliced CONTENT hashes identically at
// two different times — event timing never enters identity.
func TestSpliceHashIsContentOnly(t *testing.T) {
	fresh := crawl.ScopeContext{Scope: "eu-west-1", Status: "complete",
		Resources: []crawl.Resource{{ProviderID: "s3:x"}}}
	a, _ := Splice(baseDoc(), "aws", "eu-west-1", "t1", fresh)
	b, _ := Splice(baseDoc(), "aws", "eu-west-1", "t9999", fresh)
	if a.ContextHash != b.ContextHash {
		t.Fatalf("same content must hash identically:\n a %s\n b %s", a.ContextHash, b.ContextHash)
	}
}
