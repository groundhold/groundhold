package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func assetFeedAttrs() map[string]any {
	return map[string]any{
		"feed.target":     "projects/acme-prod/topics/infra-changes",
		"service.managed": true,
	}
}

func TestBuildAssetFeedHonors(t *testing.T) {
	p, err := BuildAssetFeed("acme-prod", "prod", "changefeed", assetFeedAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Target != "projects/acme-prod/topics/infra-changes" {
		t.Fatalf("plan = %+v", p)
	}
	if p.FeedID != AssetFeedID("acme-prod", "prod", "changefeed", 1) {
		t.Fatalf("feedId not deterministic: %q", p.FeedID)
	}
	body := p.createBody()
	if body["feedId"] != p.FeedID {
		t.Fatalf("body feedId = %v", body["feedId"])
	}
	feed := body["feed"].(map[string]any)
	if feed["contentType"] != "RESOURCE" {
		t.Fatalf("contentType = %v", feed["contentType"])
	}
	topic := feed["feedOutputConfig"].(map[string]any)["pubsubDestination"].(map[string]any)["topic"]
	if topic != "projects/acme-prod/topics/infra-changes" {
		t.Fatalf("pubsub topic = %v", topic)
	}
}

func TestBuildAssetFeedRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"bad-target":     {"feed.target": "infra-changes"}, // not a topic path
		"empty-target":   {"feed.target": ""},              // missing core semantic
		"wrong-resource": {"feed.target": "projects/p/subscriptions/s"},
		"unmanaged":      {"service.managed": false},
		"unknown-attr":   {"feed.coverage": "all"},
	}
	for name, extra := range cases {
		a := assetFeedAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildAssetFeed("acme-prod", "prod", "changefeed", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// feed.target is mandatory
	a := assetFeedAttrs()
	delete(a, "feed.target")
	if _, err := BuildAssetFeed("acme-prod", "prod", "changefeed", a, nil, 1); err == nil {
		t.Errorf("missing feed.target must refuse")
	}
}

// assetFeedServer is a fake cloudasset endpoint serving CreateFeed/GetFeed/
// DeleteFeed. topic is the Pub/Sub destination a GET reports back.
func assetFeedServer(t *testing.T, topic string) (*httptest.Server, *[]string) {
	t.Helper()
	var sawAuth []string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			sawAuth = append(sawAuth, r.Header.Get("Authorization"))
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/feeds"):
				var got map[string]any
				raw, _ := io.ReadAll(r.Body)
				if json.Unmarshal(raw, &got) != nil || got["feedId"] == nil {
					w.WriteHeader(400)
					return
				}
				feed := got["feed"].(map[string]any)
				sentTopic := feed["feedOutputConfig"].(map[string]any)["pubsubDestination"].(map[string]any)["topic"]
				_, _ = w.Write([]byte(`{"name":"projects/12345/feeds/` +
					got["feedId"].(string) + `","feedOutputConfig":{"pubsubDestination":{"topic":"` +
					sentTopic.(string) + `"}}}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"name":"projects/12345/feeds/x",` +
					`"feedOutputConfig":{"pubsubDestination":{"topic":"` + topic + `"}}}`))
			case r.Method == "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
	return srv, &sawAuth
}

func assetFeedDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.AssetFeedBaseURL = srv.URL
	return d
}

func TestCreateObserveDeleteAssetFeed(t *testing.T) {
	target := "projects/acme-prod/topics/infra-changes"
	srv, sawAuth := assetFeedServer(t, target)
	defer srv.Close()
	d := assetFeedDriver(t, srv)

	res := d.createAssetFeed("changefeed", "prod", assetFeedAttrs(), nil, 1)
	wantPID := "assetfeed:acme-prod:" + AssetFeedID("acme-prod", "prod", "changefeed", 1)
	if res.Status != "succeeded" || res.ProviderID != wantPID {
		t.Fatalf("create: %+v (want pid %q)", res, wantPID)
	}
	// the request carried a bearer token
	if len(*sawAuth) == 0 || (*sawAuth)[0] != "Bearer test-token" {
		t.Fatalf("missing/incorrect bearer: %v", *sawAuth)
	}

	obs, diags, err := d.observeAssetFeed("changefeed", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
		if o.Derivation != "measured" {
			t.Fatalf("observation %s derivation = %q, want measured", o.Path, o.Derivation)
		}
	}
	if got["feed.target"] != target || got["service.managed"] != true {
		t.Fatalf("observe: %+v diags=%v", got, diags)
	}

	if del := d.deleteAssetFeed("changefeed", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// A feed that already exists at our deterministic id but forwards to a DIFFERENT
// topic is not ours — the create 409 path refuses, never silently adopts it.
func TestCreateAssetFeedConflictForeignTopicRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "POST":
				w.WriteHeader(http.StatusConflict)
			case "GET":
				_, _ = w.Write([]byte(`{"feedOutputConfig":{"pubsubDestination":` +
					`{"topic":"projects/acme-prod/topics/someone-elses"}}}`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := assetFeedDriver(t, srv)
	res := d.createAssetFeed("changefeed", "prod", assetFeedAttrs(), nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign-topic conflict must refuse, got %+v", res)
	}
}

// A conflict on a feed that already forwards to OUR target is an idempotent success.
func TestCreateAssetFeedConflictSameTopicIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "POST":
				w.WriteHeader(http.StatusConflict)
			case "GET":
				_, _ = w.Write([]byte(`{"feedOutputConfig":{"pubsubDestination":` +
					`{"topic":"projects/acme-prod/topics/infra-changes"}}}`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := assetFeedDriver(t, srv)
	res := d.createAssetFeed("changefeed", "prod", assetFeedAttrs(), nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("same-topic conflict must be idempotent success, got %+v", res)
	}
}

func TestObserveAssetFeedNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer srv.Close()
	d := assetFeedDriver(t, srv)
	pid := "assetfeed:acme-prod:" + AssetFeedID("acme-prod", "prod", "changefeed", 1)
	obs, diags, err := d.observeAssetFeed("changefeed", pid)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 0 || len(diags) == 0 {
		t.Fatalf("a missing feed observes nothing with a diagnostic, got obs=%v diags=%v", obs, diags)
	}
}
