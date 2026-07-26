package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// a storage-queue resource id under testSub — the feed.target a contract declares.
const testQueueTarget = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/pvstore01/queueServices/default/queues/changes"

func changeFeedAttrs() map[string]any {
	return map[string]any{
		"feed.target":     testQueueTarget,
		"service.managed": true,
	}
}

func TestBuildChangeFeedHonors(t *testing.T) {
	p, err := BuildChangeFeed("prod", "feed", changeFeedAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.QueueName != "changes" {
		t.Fatalf("queue = %q", p.QueueName)
	}
	if p.StorageAccountID != "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/pvstore01" {
		t.Fatalf("account = %q", p.StorageAccountID)
	}
	if p.FeedTarget != testQueueTarget {
		t.Fatalf("feed.target round-trip = %q", p.FeedTarget)
	}
	if !strings.HasPrefix(p.Name, "pv-cf-") {
		t.Fatalf("name = %q", p.Name)
	}
}

func TestBuildChangeFeedRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"missing-target":     {"service.managed": true},
		"empty-target":       {"feed.target": "", "service.managed": true},
		"managed-false":      {"feed.target": testQueueTarget, "service.managed": false},
		"unknown-attr":       {"feed.target": testQueueTarget, "coverage.filter": "all"},
		"target-not-a-queue": {"feed.target": "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/pvstore01"},
		"target-bad-account": {"feed.target": "not-a-resource-id" + queuePathSep + "changes"},
		"target-bad-queue":   {"feed.target": "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/pvstore01" + queuePathSep + "Bad_Queue"},
	}
	for name, attrs := range cases {
		if _, err := BuildChangeFeed("prod", "feed", attrs, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

// changeFeedArmFake serves the event-subscription PUT/GET/DELETE and asserts the
// bearer header + the StorageQueue destination body on the PUT.
func changeFeedArmFake(t *testing.T, wantAccount, wantQueue string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
				t.Errorf("missing/wrong bearer: %q", got)
			}
			if !strings.Contains(r.URL.Path, "/providers/Microsoft.EventGrid/eventSubscriptions/") {
				t.Errorf("unexpected path %q", r.URL.Path)
			}
			switch r.Method {
			case "PUT":
				var body struct {
					Properties struct {
						Destination struct {
							EndpointType string `json:"endpointType"`
							Properties   struct {
								ResourceID string `json:"resourceId"`
								QueueName  string `json:"queueName"`
							} `json:"properties"`
						} `json:"destination"`
					} `json:"properties"`
				}
				raw, _ := io.ReadAll(r.Body)
				if err := json.Unmarshal(raw, &body); err != nil {
					t.Fatalf("bad PUT body: %v", err)
				}
				d := body.Properties.Destination
				if d.EndpointType != "StorageQueue" ||
					d.Properties.ResourceID != wantAccount || d.Properties.QueueName != wantQueue {
					t.Errorf("PUT destination = %+v (want acct=%q queue=%q)", d, wantAccount, wantQueue)
				}
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Creating"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded",` +
					`"destination":{"endpointType":"StorageQueue","properties":{` +
					`"resourceId":"` + wantAccount + `","queueName":"` + wantQueue + `"}}}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestCreateObserveDeleteChangeFeed(t *testing.T) {
	wantAccount := "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/pvstore01"
	srv := changeFeedArmFake(t, wantAccount, "changes")
	defer srv.Close()
	d := vnetTestDriver(t, srv)

	res := d.createChangeFeed("prod", "feed", changeFeedAttrs(), nil, 1)
	if res.Status != "succeeded" || res.ProviderID == "" {
		t.Fatalf("create: %+v", res)
	}
	if !strings.HasPrefix(res.ProviderID, "eventgrid:"+testSub+":pv-cf-") {
		t.Fatalf("providerId = %q", res.ProviderID)
	}

	obs, diags, err := d.observeChangeFeed("feed", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diags: %v", diags)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["feed.target"] != testQueueTarget {
		t.Fatalf("observe feed.target = %v (want %q)", got["feed.target"], testQueueTarget)
	}
	if got["service.managed"] != true {
		t.Fatalf("observe service.managed = %v", got["service.managed"])
	}

	if del := d.deleteChangeFeed("feed", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// A non-StorageQueue destination yields no feed.target observation, only a diagnostic.
func TestObserveChangeFeedNonQueueDestination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded",` +
				`"destination":{"endpointType":"WebHook"}}}`))
		}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	pid := changeFeedProviderID(testSub, changeFeedName("prod", "feed", 1))
	obs, diags, err := d.observeChangeFeed("feed", pid)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "feed.target" {
			t.Fatalf("feed.target must not be observed for a non-queue destination: %v", o.Value)
		}
	}
	if len(diags) == 0 || !strings.Contains(diags[0], "not StorageQueue") {
		t.Fatalf("expected a not-StorageQueue diagnostic, got %v", diags)
	}
}

func TestDeleteChangeFeedForeignSubscriptionRefused(t *testing.T) {
	srv := changeFeedArmFake(t, "", "")
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	foreign := changeFeedProviderID("00000000-0000-0000-0000-0000000000ff", changeFeedName("prod", "feed", 1))
	res := d.deleteChangeFeed("feed", "prod", foreign)
	if res.Status != "failed" || !strings.Contains(res.Reason, "across subscriptions") {
		t.Fatalf("foreign subscription must refuse delete, got %+v", res)
	}
}
