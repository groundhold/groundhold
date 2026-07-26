package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file extends pubsub_test.go / pubsub_update_test.go, which pin the
// happy create/observe/delete/update loop and the residency honesty branch.
// These tests pin the remaining branches: regionsMatch (0% before this
// file), transport/5xx/conflict-mismatch branches of createPubSub, the D237
// transient routing on setTopicPublic/setTopicPrivate, pubsubGetTopic's error
// branches, observePubSub's multi-region diagnostic + transport error, and
// deletePubSub/updatePubSub's remaining branches.

// --- regionsMatch --------------------------------------------------------

func TestRegionsMatch(t *testing.T) {
	cases := []struct {
		got  []string
		want string
		ok   bool
	}{
		{[]string{"europe-west1"}, "europe-west1", true},
		{[]string{"europe-west1"}, "europe-west4", false},
		{[]string{"europe-west1", "europe-west4"}, "europe-west1", false}, // superset is not a match
		{nil, "europe-west1", false},
		{[]string{}, "", false},
	}
	for _, c := range cases {
		if got := regionsMatch(c.got, c.want); got != c.ok {
			t.Errorf("regionsMatch(%v, %q) = %v, want %v", c.got, c.want, got, c.ok)
		}
	}
}

// --- createPubSub transport/5xx/conflict branches --------------------------

func TestCreatePubSubTransportErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d := pubsubDriver(t, srv)
	srv.Close()
	res := d.createPubSub("events", "prod", pubsubAttrs(), nil, 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a lost create must be unknown WITH the deterministic pid, got %+v", res)
	}
}

func TestCreatePubSub5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.createPubSub("events", "prod", pubsubAttrs(), nil, 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a 503 create must be unknown WITH the pid, got %+v", res)
	}
}

func TestCreatePubSubEmptyBodyIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.createPubSub("events", "prod", pubsubAttrs(), nil, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "carried no topic") {
		t.Fatalf("an empty create response must be unknown, got %+v", res)
	}
}

func pubsubConflictServer(t *testing.T, topicStatus int, topicJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT":
			w.WriteHeader(http.StatusConflict)
		case r.Method == "GET":
			if topicStatus != 0 && topicStatus != 200 {
				w.WriteHeader(topicStatus)
				return
			}
			_, _ = w.Write([]byte(topicJSON))
		default:
			w.WriteHeader(500)
		}
	}))
}

func TestCreatePubSubConflictReadUnreadable(t *testing.T) {
	srv := pubsubConflictServer(t, http.StatusForbidden, "")
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.createPubSub("events", "prod", pubsubAttrs(), nil, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("an unreadable follow-up must be unknown, got %+v", res)
	}
}

func TestCreatePubSubConflictGoneOnFollowup(t *testing.T) {
	srv := pubsubConflictServer(t, http.StatusNotFound, "")
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.createPubSub("events", "prod", pubsubAttrs(), nil, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gone on the follow-up read") {
		t.Fatalf("a vanished conflicting topic must be unknown, got %+v", res)
	}
}

func TestCreatePubSubConflictNotOurs(t *testing.T) {
	srv := pubsubConflictServer(t, 200, `{"name":"projects/acme-prod/topics/the-topic","labels":{"groundhold-capability":"other"}}`)
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.createPubSub("events", "prod", pubsubAttrs(), nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign-labeled conflict must be failed, got %+v", res)
	}
}

func TestCreatePubSubConflictResidencyMismatch(t *testing.T) {
	topic := ownedTopic(`"europe-west4"`) // wants europe-west1
	srv := pubsubConflictServer(t, 200, topic)
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.createPubSub("events", "prod", pubsubAttrs(), nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "storage regions") {
		t.Fatalf("a residency mismatch must be failed, got %+v", res)
	}
}

func TestCreatePubSubConflictCMEKMismatch(t *testing.T) {
	topic := `{"name":"projects/acme-prod/topics/the-topic",` +
		`"labels":{"groundhold-capability":"events","groundhold-environment":"prod"},` +
		`"kmsKeyName":"projects/p/locations/eu/keyRings/r/cryptoKeys/other",` +
		`"messageStoragePolicy":{"allowedPersistenceRegions":["europe-west1"]}}`
	srv := pubsubConflictServer(t, 200, topic)
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.createPubSub("events", "prod", pubsubAttrs(), nil, 1) // no CMEK requested
	if res.Status != "failed" || !strings.Contains(res.Reason, "CMEK key") {
		t.Fatalf("a CMEK mismatch must be failed, got %+v", res)
	}
}

func TestCreatePubSubConflictIdempotentMatch(t *testing.T) {
	srv := pubsubConflictServer(t, 200, ownedTopic(`"europe-west1"`))
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.createPubSub("events", "prod", pubsubAttrs(), nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("a matching conflict (idempotent) must succeed, got %+v", res)
	}
}

// --- D237 transient routing on setTopicPublic / setTopicPrivate ------------

func TestSetTopicPublicTransientIsUnknown(t *testing.T) {
	srv := pubsubServer(t, "", 429, 0)
	defer srv.Close()
	d := pubsubDriver(t, srv)
	a := pubsubAttrs()
	a["network.publicExposure"] = true
	res := d.createPubSub("events", "prod", a, nil, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "transient/denied") {
		t.Fatalf("a 429 on setIamPolicy must be unknown, got %+v", res)
	}
}

func TestSetTopicPublic5xxIsUnknown(t *testing.T) {
	srv := pubsubServer(t, "", 500, 0)
	defer srv.Close()
	d := pubsubDriver(t, srv)
	a := pubsubAttrs()
	a["network.publicExposure"] = true
	res := d.createPubSub("events", "prod", a, nil, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "server error") {
		t.Fatalf("a 500 on setIamPolicy must be unknown, got %+v", res)
	}
}

func TestSetTopicPublicDRSFailed(t *testing.T) {
	// pubsubServer's setIamPolicy 400 path writes no body, so a dedicated server
	// is needed here for isDomainRestricted to have a message to match.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"e1","bindings":[]}`))
		case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":{"message":"domain restricted sharing forbids allUsers"}}`))
		case r.Method == "PUT":
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/the-topic"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := pubsubDriver(t, srv)
	a := pubsubAttrs()
	a["network.publicExposure"] = true
	res := d.createPubSub("events", "prod", a, nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "domain-restricted-sharing") {
		t.Fatalf("DRS must be a terminal failed, got %+v", res)
	}
}

func TestSetTopicPublicConfirmFailsAfterGrant(t *testing.T) {
	// setIamPolicy returns 200 but the confirm read never shows the binding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"e1","bindings":[]}`)) // never reflects the grant
		case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"e2"}`))
		case r.Method == "PUT":
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/topics/the-topic"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := pubsubDriver(t, srv)
	a := pubsubAttrs()
	a["network.publicExposure"] = true
	res := d.createPubSub("events", "prod", a, nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "did not take") {
		t.Fatalf("an unconfirmed grant must be a terminal failed, got %+v", res)
	}
}

func TestSetTopicPrivateStillPublicAfterRevoke(t *testing.T) {
	// setIamPolicy 200s but the confirm read STILL shows allUsers.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"e1","bindings":[{"role":"roles/pubsub.publisher","members":["allUsers"]}]}`))
		case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"e2"}`))
		case r.Method == "GET":
			_, _ = w.Write([]byte(ourTopicJSON("events")))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.Update("pubsub-topic", "events", "prod", "pubsub:acme-prod:pv-events-abcd1234",
		map[string]any{"network.publicExposure": false}, nil, []string{"network.publicExposure"}, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "still present") {
		t.Fatalf("a binding that survives revoke must be a terminal failed, got %+v", res)
	}
}

func TestSetTopicPrivateTransientIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"e1","bindings":[{"role":"roles/pubsub.publisher","members":["allUsers"]}]}`))
		case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
			w.WriteHeader(http.StatusServiceUnavailable)
		case r.Method == "GET":
			_, _ = w.Write([]byte(ourTopicJSON("events")))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.Update("pubsub-topic", "events", "prod", "pubsub:acme-prod:pv-events-abcd1234",
		map[string]any{"network.publicExposure": false}, nil, []string{"network.publicExposure"}, "k")
	if res.Status != "unknown" {
		t.Fatalf("a 503 on the revoke must be unknown, got %+v", res)
	}
}

// --- pubsubGetTopic error branches ------------------------------------

func TestPubsubGetTopicErrorBranches(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := pubsubDriver(t, srv)
		srv.Close()
		if _, _, _, err := d.pubsubGetTopic("x", "events", "prod"); err == nil {
			t.Fatal("expected a transport error")
		}
	})
	t.Run("unparseable body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()
		d := pubsubDriver(t, srv)
		if _, _, _, err := d.pubsubGetTopic("x", "events", "prod"); err == nil {
			t.Fatal("expected a body-parse error")
		}
	})
}

// --- observePubSub branches -------------------------------------------

func TestObservePubSubTransportErrorIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d := pubsubDriver(t, srv)
	srv.Close()
	if _, _, err := d.observePubSub("events", "pubsub:acme-prod:the-topic"); err == nil {
		t.Fatal("expected a transport error")
	}
}

func TestObservePubSubMultiRegionDiagnostic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"e1","bindings":[]}`))
		default:
			_, _ = w.Write([]byte(ownedTopic(`"europe-west1","europe-west4"`)))
		}
	}))
	defer srv.Close()
	d := pubsubDriver(t, srv)
	obs, diags, err := d.observePubSub("events", "pubsub:acme-prod:the-topic")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "location.region" {
			t.Fatalf("a multi-region storage policy must not observe a single region: %+v", o)
		}
	}
	found := false
	for _, dg := range diags {
		if strings.Contains(dg, "multiple regions") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a multi-region storage policy must diagnose, got %v", diags)
	}
}

func TestObservePubSubPublicReadErrorDiagnoses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			w.WriteHeader(http.StatusForbidden)
		default:
			_, _ = w.Write([]byte(ownedTopic(`"europe-west1"`)))
		}
	}))
	defer srv.Close()
	d := pubsubDriver(t, srv)
	obs, diags, err := d.observePubSub("events", "pubsub:acme-prod:the-topic")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "network.publicExposure" {
			t.Fatalf("an unreadable IAM policy must not fabricate publicExposure: %+v", o)
		}
	}
	found := false
	for _, dg := range diags {
		if strings.Contains(dg, "network.publicExposure not observed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a publicExposure diagnostic, got %v", diags)
	}
}

// --- deletePubSub branches ---------------------------------------------

func TestDeletePubSubTransportErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d := pubsubDriver(t, srv)
	srv.Close()
	res := d.deletePubSub("events", "prod", "pubsub:acme-prod:the-topic")
	if res.Status != "unknown" {
		t.Fatalf("a lost pre-delete read must be unknown, got %+v", res)
	}
}

func TestDeletePubSubPreDeleteReadNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.deletePubSub("events", "prod", "pubsub:acme-prod:the-topic")
	if res.Status != "failed" {
		t.Fatalf("a definitive non-200 pre-delete read must be failed, got %+v", res)
	}
}

func TestDeletePubSubUnparseableBodyRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.deletePubSub("events", "prod", "pubsub:acme-prod:the-topic")
	if res.Status != "unknown" || !strings.Contains(res.Reason, "unparseable") {
		t.Fatalf("an unparseable pre-delete read must refuse ambiguously, got %+v", res)
	}
}

func TestDeletePubSub5xxIsUnknown(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			_, _ = w.Write([]byte(ownedTopic(`"europe-west1"`)))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.deletePubSub("events", "prod", "pubsub:acme-prod:the-topic")
	if res.Status != "unknown" {
		t.Fatalf("a 503 on delete must be unknown, got %+v", res)
	}
}

// --- updatePubSub unsupported/not-found/foreign branches -----------------

func TestUpdatePubSubUnsupportedPathRefuses(t *testing.T) {
	srv := pubsubServer(t, ourTopicJSON("events"), 0, 0)
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.Update("pubsub-topic", "events", "prod", "pubsub:acme-prod:pv-events-abcd1234",
		map[string]any{"location.region": "us"}, nil, []string{"location.region"}, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not patchable in place") {
		t.Fatalf("an unsupported path must refuse, got %+v", res)
	}
}

func TestUpdatePubSubNotFoundRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := pubsubDriver(t, srv)
	res := d.Update("pubsub-topic", "events", "prod", "pubsub:acme-prod:pv-events-abcd1234",
		map[string]any{"network.publicExposure": true}, nil, []string{"network.publicExposure"}, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "no longer exists") {
		t.Fatalf("a vanished topic must refuse the update, got %+v", res)
	}
}

func TestUpdatePubSubPreUpdateReadTransportErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d := pubsubDriver(t, srv)
	srv.Close()
	res := d.Update("pubsub-topic", "events", "prod", "pubsub:acme-prod:pv-events-abcd1234",
		map[string]any{"network.publicExposure": true}, nil, []string{"network.publicExposure"}, "k")
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("a lost pre-update read must be unknown, got %+v", res)
	}
}
