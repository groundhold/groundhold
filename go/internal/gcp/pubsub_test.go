package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func pubsubAttrs() map[string]any {
	return map[string]any{
		"location.region":        "europe-west1",
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"service.managed":        true,
	}
}

// A residency contract is honored ONLY via messageStoragePolicy — the create
// body ALWAYS pins it (a global topic would be a compliance lie).
func TestBuildPubSubResidencyAlwaysPinned(t *testing.T) {
	req, err := BuildPubSubCreateRequest("acme-prod", "prod", "events", pubsubAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "PUT" {
		t.Fatalf("topics.create must be a PUT, got %s", req.Method)
	}
	msp, ok := req.Body["messageStoragePolicy"].(map[string]any)
	if !ok {
		t.Fatal("residency must be pinned via messageStoragePolicy — a global topic is a lie")
	}
	regions, _ := msp["allowedPersistenceRegions"].([]any)
	if len(regions) != 1 || regions[0] != "europe-west1" {
		t.Fatalf("storage policy must pin exactly the region, got %v", regions)
	}
	labels, _ := req.Body["labels"].(map[string]any)
	if labels["groundhold-capability"] != "events" {
		t.Fatalf("ownership label missing: %v", labels)
	}
}

func TestBuildPubSubCMEK(t *testing.T) {
	a := pubsubAttrs()
	a["encryption.customerManagedKeys"] = true
	impl := map[string]any{"kms_key_name": "projects/p/locations/eu/keyRings/r/cryptoKeys/k"}
	req, err := BuildPubSubCreateRequest("acme-prod", "prod", "events", a, impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if req.Body["kmsKeyName"] != impl["kms_key_name"] {
		t.Fatalf("CMEK must set kmsKeyName, got %v", req.Body["kmsKeyName"])
	}
}

func TestBuildPubSubRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate func(map[string]any)
		impl   map[string]any
	}{
		"atRest false":     {func(a map[string]any) { a["encryption.atRest"] = false }, nil},
		"cmek without key": {func(a map[string]any) { a["encryption.customerManagedKeys"] = true }, nil},
		"unmanaged":        {func(a map[string]any) { a["service.managed"] = false }, nil},
		"no region":        {func(a map[string]any) { delete(a, "location.region") }, nil},
		"unknown attr":     {func(a map[string]any) { a["retention.minimum"] = "1h" }, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := pubsubAttrs()
			c.mutate(a)
			if _, err := BuildPubSubCreateRequest("acme-prod", "prod", "events", a, c.impl, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}

func TestSplitPubSubProviderID(t *testing.T) {
	if _, _, err := splitPubSubProviderID("pubsub:acme-prod:events-x"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	for _, bad := range []string{
		"pubsub:acme-prod", "gcs:acme-prod:events", "pubsub:acme-prod:bad/name",
	} {
		if _, _, err := splitPubSubProviderID(bad); err == nil {
			t.Errorf("accepted malformed pubsub id %q", bad)
		}
	}
}

// pubsubServer routes the Pub/Sub v1 JSON API. IAM is stateful: getIamPolicy
// returns an allUsers publisher binding only after a setIamPolicy, so a public
// create's read-modify-write-confirm runs end to end.
func pubsubServer(t *testing.T, topicJSON string, setIamStatus, deleteStatus int) *httptest.Server {
	t.Helper()
	granted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case strings.HasSuffix(p, ":getIamPolicy") && r.Method == "GET":
				if granted {
					_, _ = w.Write([]byte(`{"etag":"e1","version":3,"bindings":[` +
						`{"role":"roles/pubsub.publisher","members":["allUsers"]}]}`))
				} else {
					_, _ = w.Write([]byte(`{"etag":"e1","version":3,"bindings":[]}`))
				}
			case strings.HasSuffix(p, ":setIamPolicy") && r.Method == "POST":
				if setIamStatus != 0 && setIamStatus != 200 {
					w.WriteHeader(setIamStatus)
					return
				}
				granted = true
				_, _ = w.Write([]byte(`{"etag":"e2"}`))
			case r.Method == "PUT":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/the-topic"}`))
			case r.Method == "DELETE":
				if deleteStatus != 0 && deleteStatus != 200 {
					w.WriteHeader(deleteStatus)
					return
				}
				_, _ = w.Write([]byte(`{}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(topicJSON))
			default:
				w.WriteHeader(500)
			}
		}))
}

func pubsubDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.PubSubBaseURL = srv.URL
	return d
}

func TestCreatePubSubPublicGrantsPublisher(t *testing.T) {
	srv := pubsubServer(t, "", 0, 0)
	defer srv.Close()
	d := pubsubDriver(t, srv)
	a := pubsubAttrs()
	a["network.publicExposure"] = true
	res := d.createPubSub("events", "prod", a, nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "pubsub:acme-prod:") {
		t.Fatalf("got %+v, want succeeded + pubsub-prefixed id", res)
	}
}

func ownedTopic(regions string) string {
	return `{"name":"projects/acme-prod/topics/the-topic",` +
		`"labels":{"groundhold-capability":"events","groundhold-environment":"prod"},` +
		`"messageStoragePolicy":{"allowedPersistenceRegions":[` + regions + `]}}`
}

func TestDeletePubSubOurs(t *testing.T) {
	srv := pubsubServer(t, ownedTopic(`"europe-west1"`), 0, 0)
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.deletePubSub("events", "prod", "pubsub:acme-prod:the-topic")
	if res.Status != "succeeded" {
		t.Fatalf("delete of an owned topic must succeed, got %+v", res)
	}
}

func TestDeletePubSubForeignRefused(t *testing.T) {
	foreign := `{"name":"projects/acme-prod/topics/the-topic",` +
		`"labels":{"groundhold-capability":"other"}}`
	srv := pubsubServer(t, foreign, 0, 0)
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.deletePubSub("events", "prod", "pubsub:acme-prod:the-topic")
	if res.Status != "failed" {
		t.Fatalf("delete of a foreign topic must be refused, got %+v", res)
	}
}

// THE residency honesty test: a topic WITH a storage policy observes its region;
// a GLOBAL topic (no storage policy) does NOT observe a region — a diagnostic,
// never a default (a global topic must never look like it satisfies residency).
func TestObservePubSubResidencyHonesty(t *testing.T) {
	t.Run("pinned", func(t *testing.T) {
		srv := pubsubServer(t, ownedTopic(`"europe-west1"`), 0, 0)
		defer srv.Close()
		d := pubsubDriver(t, srv)
		obs, diags, err := d.observePubSub("events", "pubsub:acme-prod:the-topic")
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]any{}
		for _, o := range obs {
			got[o.Path] = o.Value
		}
		if got["location.region"] != "europe-west1" {
			t.Fatalf("a region-pinned topic must observe its region, got %v (diags %v)", got["location.region"], diags)
		}
	})
	t.Run("global", func(t *testing.T) {
		global := `{"name":"projects/acme-prod/topics/the-topic","labels":{}}`
		srv := pubsubServer(t, global, 0, 0)
		defer srv.Close()
		d := pubsubDriver(t, srv)
		obs, diags, err := d.observePubSub("events", "pubsub:acme-prod:the-topic")
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range obs {
			if o.Path == "location.region" {
				t.Fatalf("a GLOBAL topic must NOT observe a region — that is a residency lie: %+v", o)
			}
		}
		found := false
		for _, dg := range diags {
			if strings.Contains(dg, "GLOBAL") {
				found = true
			}
		}
		if !found {
			t.Fatalf("a global topic must emit a residency diagnostic, got %v", diags)
		}
	})
}

// Weapon 2 (D87): the metamorphic write/read round-trip. A stateful fake records
// what the PUT WRITES (kmsKeyName, messageStoragePolicy) and the setIamPolicy,
// and reflects them on topics.get / getIamPolicy; observePubSub must reverse-map
// the SAME semantic attributes create was given.
func metamorphicPubSubServer(t *testing.T) *httptest.Server {
	t.Helper()
	var kms string
	var regions []string
	granted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case strings.HasSuffix(p, ":getIamPolicy") && r.Method == "GET":
				if granted {
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[` +
						`{"role":"roles/pubsub.publisher","members":["allUsers"]}]}`))
				} else {
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[]}`))
				}
			case strings.HasSuffix(p, ":setIamPolicy") && r.Method == "POST":
				granted = true
				_, _ = w.Write([]byte(`{"etag":"e2"}`))
			case r.Method == "PUT":
				raw, _ := io.ReadAll(r.Body)
				var b topicDoc
				_ = json.Unmarshal(raw, &b)
				kms = b.KmsKeyName
				regions = b.MessageStoragePolicy.AllowedPersistenceRegions
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/x"}`))
			case r.Method == "GET":
				doc := map[string]any{
					"name":       "projects/acme-prod/topics/x",
					"labels":     map[string]any{"groundhold-capability": "events", "groundhold-environment": "prod"},
					"kmsKeyName": kms,
					"messageStoragePolicy": map[string]any{
						"allowedPersistenceRegions": regions},
				}
				_ = json.NewEncoder(w).Encode(doc)
			default:
				w.WriteHeader(500)
			}
		}))
}

func TestMetamorphicPubSubRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		public bool
		cmek   bool
	}{
		{"private-google-key", false, false},
		{"public-cmek", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicPubSubServer(t)
			defer srv.Close()
			d := pubsubDriver(t, srv)
			attrs := map[string]any{
				"location.region":        "europe-west1",
				"network.publicExposure": c.public,
				"encryption.atRest":      true,
				"service.managed":        true,
			}
			var impl map[string]any
			if c.cmek {
				attrs["encryption.customerManagedKeys"] = true
				impl = map[string]any{"kms_key_name": "projects/p/locations/eu/keyRings/r/cryptoKeys/k"}
			}
			res := d.createPubSub("events", "prod", attrs, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create failed: %+v", res)
			}
			obs, _, err := d.observePubSub("events", res.ProviderID)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["location.region"] != "europe-west1" {
				t.Errorf("residency round-trip broke: %v", got["location.region"])
			}
			if got["network.publicExposure"] != c.public {
				t.Errorf("public round-trip broke: wrote %v observed %v", c.public, got["network.publicExposure"])
			}
			_, hasCMEK := got["encryption.customerManagedKeys"]
			if hasCMEK != c.cmek {
				t.Errorf("cmek presence round-trip broke: want %v observed %v", c.cmek, hasCMEK)
			}
		})
	}
}
