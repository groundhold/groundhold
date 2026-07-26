package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file extends update_test.go (Cloud SQL BuildUpdateRequest/Update golden
// + refusal paths) and the per-service classify tests scattered across
// gcs_update_test.go/pubsub_update_test.go/pubsub_queue_update_test.go/
// secret_update_test.go/loadbalancer_test.go/clouddnsrecord_test.go, none of
// which exercise the REMAINING branches of the ClassifyChange dispatch table
// (update.go:20) or classifyCloudSQLChange/classifyAssetFeedChange directly
// (both 0% before this file), or the Cloud SQL Update/Delete error branches
// beyond the golden happy path and the two existing refusal tests.

// ─── ClassifyChange dispatch: every remaining service token ────────────────

func TestClassifyChangeDispatchRemainingServices(t *testing.T) {
	d := NewDriver("acme-prod")
	cases := []struct {
		service, path string
		desired       any
		want          string
	}{
		{"cloudsql", "recovery.rpo", "5m", "mutable"},
		{"cloudsql", "location.region", "eu", "immutable"},
		{"assetfeed", "feed.target", "t", "unsupported"},
		{"billingbudget", "budget.limit", 100, "mutable"},
		{"logbucket", "retention.days", 30, "mutable"},
		{"auditlogs", "delivery.assured", true, "mutable"},
		{"scc", "detection.enabled", true, "mutable"},
		{"vertexai", "model.provider", "x", "immutable"},
		{"artifactregistry", "location.region", "eu", "immutable"},
		{"gke", "cluster.version", "1.30", "mutable"},
		{"gke-addon", "addon.name", "x", "immutable"},
		{"gke-workloadidentity", "workload.namespace", "ns", "immutable"},
		{"backupplan", "schedule.frequency", "daily", "mutable"},
	}
	for _, c := range cases {
		got, reason := d.ClassifyChange(c.service, c.path, nil, c.desired, nil)
		if got != c.want {
			t.Errorf("%s/%s: got %q (%s), want %q", c.service, c.path, got, reason, c.want)
		}
	}
}

// TestClassifyChangeUnwiredServiceIsImmutable: D215 — a service with no
// explicit ClassifyChange case has no in-place update path, so a drift is
// honestly a REPLACEMENT (consent-gated when stateful), never a silent freeze.
func TestClassifyChangeUnwiredServiceIsImmutable(t *testing.T) {
	d := NewDriver("acme-prod")
	got, reason := d.ClassifyChange("cloudrun", "image", "v1", "v2", nil)
	if got != "immutable" {
		t.Fatalf("an unwired service must classify immutable (replacement), got %q", got)
	}
	if !strings.Contains(reason, "no in-place update path") {
		t.Fatalf("reason must say why: %q", reason)
	}
}

// ─── classifyCloudSQLChange direct (0% before this file) ────────────────────

func TestClassifyCloudSQLChangeBranches(t *testing.T) {
	d := NewDriver("acme-prod")

	cases := []struct {
		name    string
		path    string
		desired any
		impl    map[string]any
		want    string
	}{
		{"region is create-time only", "location.region", "eu", nil, "immutable"},
		{"engine/version is a migration", "engine.protocol", "16", nil, "immutable"},
		{"multi-regional availability has no GCP equivalent", "availability.class", "multi-regional", nil, "unsupported"},
		{"zonal/regional availability restarts the instance", "availability.class", "regional", nil, "caveated"},
		{"recovery.rpo is a clean patch", "recovery.rpo", "5m", nil, "mutable"},
		{"platform property is not patchable", "service.managed", true, nil, "unsupported"},
		{"unknown path has no mapping", "no.such.path", "x", nil, "unsupported"},
	}
	for _, c := range cases {
		got, _ := d.ClassifyChange("cloudsql", c.path, nil, c.desired, c.impl)
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}

	// removing public exposure with no privateNetwork operand is unsupported —
	// a private IP cannot be attached without a prepared link.
	got, reason := d.ClassifyChange("cloudsql", "network.publicExposure", true, false, nil)
	if got != "unsupported" || !strings.Contains(reason, "privateNetwork") {
		t.Fatalf("removing exposure with no prepared link must be unsupported, got %q (%s)", got, reason)
	}
	// removing public exposure WITH a privateNetwork operand is caveated
	// (irreversible once attached), not unsupported.
	impl := map[string]any{"network": map[string]any{"privateNetwork": "projects/p/global/networks/n"}}
	got, reason = d.ClassifyChange("cloudsql", "network.publicExposure", true, false, impl)
	if got != "caveated" || !strings.Contains(reason, "cannot be removed") {
		t.Fatalf("removing exposure with a prepared link must be caveated, got %q (%s)", got, reason)
	}
}

// ─── classifyAssetFeedChange direct (0% before this file) ───────────────────

func TestClassifyAssetFeedChangeBranches(t *testing.T) {
	d := NewDriver("acme-prod")
	if got, _ := d.ClassifyChange("assetfeed", "feed.target", nil, "t", nil); got != "unsupported" {
		t.Errorf("feed.target: got %q", got)
	}
	if got, _ := d.ClassifyChange("assetfeed", "service.managed", nil, true, nil); got != "unsupported" {
		t.Errorf("service.managed: got %q", got)
	}
	if got, _ := d.ClassifyChange("assetfeed", "no.such.path", nil, "x", nil); got != "unsupported" {
		t.Errorf("unknown path: got %q", got)
	}
}

// TestClassifyChangeRemainingBranches fills in the branches of classifyGCSChange/
// classifyPubSubChange/classifyPubSubQueueChange/classifySecretChange that the
// per-service update test files (gcs_update_test.go etc.) do not reach — the
// "unsupported"/platform-property/default paths and the remaining immutable
// siblings.
func TestClassifyChangeRemainingBranches(t *testing.T) {
	d := NewDriver("acme-prod")
	cases := []struct {
		service, path string
		want          string
	}{
		// GCS
		{"gcs", "durability.class", "immutable"},
		{"gcs", "replication.enabled", "immutable"},
		{"gcs", "replication.destinationRegion", "immutable"},
		{"gcs", "retention.minimum", "unsupported"},
		{"gcs", "retention.locked", "unsupported"},
		{"gcs", "retention.maximum", "unsupported"},
		{"gcs", "network.publicExposure", "unsupported"},
		{"gcs", "encryption.customerManagedKeys", "unsupported"},
		{"gcs", "encryption.atRest", "unsupported"},
		{"gcs", "service.managed", "unsupported"},
		{"gcs", "no.such.path", "unsupported"},
		// Pub/Sub topic
		{"pubsub-topic", "location.region", "unsupported"},
		{"pubsub-topic", "encryption.atRest", "unsupported"},
		{"pubsub-topic", "service.managed", "unsupported"},
		{"pubsub-topic", "no.such.path", "unsupported"},
		// Pub/Sub queue
		{"pubsub-queue", "ordering.enabled", "immutable"},
		{"pubsub-queue", "encryption.customerManagedKeys", "unsupported"},
		{"pubsub-queue", "location.region", "unsupported"},
		{"pubsub-queue", "encryption.atRest", "unsupported"},
		{"pubsub-queue", "service.managed", "unsupported"},
		{"pubsub-queue", "no.such.path", "unsupported"},
		// Secret Manager
		{"secretmanager", "location.region", "immutable"},
		{"secretmanager", "encryption.atRest", "unsupported"},
		{"secretmanager", "service.managed", "unsupported"},
		{"secretmanager", "no.such.path", "unsupported"},
	}
	for _, c := range cases {
		got, _ := d.ClassifyChange(c.service, c.path, nil, "x", nil)
		if got != c.want {
			t.Errorf("%s/%s: got %q, want %q", c.service, c.path, got, c.want)
		}
	}
}

// ─── update() dispatch: unwired services fail honestly ─────────────────────

func TestUpdateDispatchUnwiredServicesFail(t *testing.T) {
	d := NewDriver("acme-prod")
	for _, svc := range []string{"cloudrun", "vpc", "cloudfunctions", "cloudfunctions-fn",
		"bigquery", "cloudscheduler", "vpngateway", "backupvault", "assetfeed"} {
		cr := d.Update(svc, "cap", "prod", "pid", nil, nil, []string{"x"}, "k")
		if cr.Status != "failed" || !strings.Contains(cr.Reason, "not wired yet") {
			t.Errorf("%s: expected an honest not-wired-yet failure, got %+v", svc, cr)
		}
	}
}

func TestUpdateUnknownServiceFailsClosed(t *testing.T) {
	d := NewDriver("acme-prod")
	cr := d.Update("__not_a_service__", "cap", "prod", "pid", nil, nil, nil, "k")
	if cr.Status != "failed" {
		t.Fatalf("an unknown service must fail closed, got %+v", cr)
	}
}

// ─── Cloud SQL Update: error branches beyond the existing golden/refusal tests ───

func TestUpdateCloudSQLErrorBranches(t *testing.T) {
	t.Run("pre-update transport error is unknown", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := testDriver(t, srv)
		srv.Close()
		cr := d.Update("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x",
			map[string]any{"recovery.rpo": "5m"}, nil, []string{"recovery.rpo"}, "k1")
		if cr.Status != "unknown" {
			t.Fatalf("a pre-update transport error must be unknown, got %+v", cr)
		}
	})

	t.Run("pre-update non-200 fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		d := testDriver(t, srv)
		cr := d.Update("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x",
			map[string]any{"recovery.rpo": "5m"}, nil, []string{"recovery.rpo"}, "k1")
		if cr.Status != "failed" {
			t.Fatalf("a bad pre-update read status must fail, got %+v", cr)
		}
	})

	t.Run("pre-update unparseable body fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()
		d := testDriver(t, srv)
		cr := d.Update("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x",
			map[string]any{"recovery.rpo": "5m"}, nil, []string{"recovery.rpo"}, "k1")
		if cr.Status != "failed" || !strings.Contains(cr.Reason, "unparseable") {
			t.Fatalf("an unparseable pre-update read must fail honestly, got %+v", cr)
		}
	})

	t.Run("invalid providerId fails before any network call", func(t *testing.T) {
		d := NewDriver("acme-prod")
		cr := d.Update("cloudsql", "orders-db", "production", "not-a-valid-pid",
			map[string]any{"recovery.rpo": "5m"}, nil, []string{"recovery.rpo"}, "k1")
		if cr.Status != "failed" {
			t.Fatalf("an invalid providerId must fail closed, got %+v", cr)
		}
	})

	t.Run("cross-project providerId fails", func(t *testing.T) {
		d := NewDriver("acme-prod")
		cr := d.Update("cloudsql", "orders-db", "production", "other-prod:europe-west1:orders-db-x",
			map[string]any{"recovery.rpo": "5m"}, nil, []string{"recovery.rpo"}, "k1")
		if cr.Status != "failed" {
			t.Fatalf("a cross-project providerId must fail closed, got %+v", cr)
		}
	})

	t.Run("patch transport error is unknown", func(t *testing.T) {
		labels := `{"settings":{"settingsVersion":"7","userLabels":{"groundhold-capability":"orders-db","groundhold-environment":"production"}}}`
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				_, _ = w.Write([]byte(labels))
			}
		}))
		d := testDriver(t, srv)
		d.HTTP = &http.Client{Transport: failOnMethod{method: "PATCH", next: srv.Client().Transport}}
		defer srv.Close()
		cr := d.Update("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x",
			map[string]any{"recovery.rpo": "5m"}, nil, []string{"recovery.rpo"}, "k1")
		if cr.Status != "unknown" {
			t.Fatalf("a patch transport error must be unknown, got %+v", cr)
		}
	})

	t.Run("patch 4xx fails cleanly", func(t *testing.T) {
		labels := `{"settings":{"settingsVersion":"7","userLabels":{"groundhold-capability":"orders-db","groundhold-environment":"production"}}}`
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "GET":
				_, _ = w.Write([]byte(labels))
			case "PATCH":
				w.WriteHeader(http.StatusBadRequest)
			}
		}))
		defer srv.Close()
		d := testDriver(t, srv)
		cr := d.Update("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x",
			map[string]any{"recovery.rpo": "5m"}, nil, []string{"recovery.rpo"}, "k1")
		if cr.Status != "failed" {
			t.Fatalf("a 400 on patch must fail cleanly, got %+v", cr)
		}
	})

	t.Run("patch response with no operation name is unknown", func(t *testing.T) {
		labels := `{"settings":{"settingsVersion":"7","userLabels":{"groundhold-capability":"orders-db","groundhold-environment":"production"}}}`
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "GET":
				_, _ = w.Write([]byte(labels))
			case "PATCH":
				_, _ = w.Write([]byte(`{}`))
			}
		}))
		defer srv.Close()
		d := testDriver(t, srv)
		cr := d.Update("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x",
			map[string]any{"recovery.rpo": "5m"}, nil, []string{"recovery.rpo"}, "k1")
		if cr.Status != "unknown" || !strings.Contains(cr.Reason, "no operation") {
			t.Fatalf("a nameless patch operation must be unknown, got %+v", cr)
		}
	})

	t.Run("full success polls to done and carries the providerId", func(t *testing.T) {
		labels := `{"settings":{"settingsVersion":"7","userLabels":{"groundhold-capability":"orders-db","groundhold-environment":"production"}}}`
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"status":"DONE"}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(labels))
			case r.Method == "PATCH":
				_, _ = w.Write([]byte(`{"name":"op1"}`))
			}
		}))
		defer srv.Close()
		d := testDriver(t, srv)
		cr := d.Update("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x",
			map[string]any{"recovery.rpo": "5m"}, nil, []string{"recovery.rpo"}, "k1")
		if cr.Status != "succeeded" || cr.ProviderID != "acme-prod:europe-west1:orders-db-x" {
			t.Fatalf("a clean patch + done poll must succeed with the providerId, got %+v", cr)
		}
	})
}

// ─── Cloud SQL Delete: error branches ───────────────────────────────────────

func TestDeleteCloudSQLBranches(t *testing.T) {
	ownedLabels := `"userLabels":{"groundhold-capability":"orders-db","groundhold-environment":"production"}`

	t.Run("404 pre-delete read is idempotent success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		d := testDriver(t, srv)
		cr := d.Delete("cloudsql", "orders-db", "production", "acme-prod:europe-west1:gone", "k1")
		if cr.Status != "succeeded" {
			t.Fatalf("a vanished instance must be idempotent success, got %+v", cr)
		}
	})

	t.Run("pre-delete transport error is unknown", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := testDriver(t, srv)
		srv.Close()
		cr := d.Delete("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x", "k1")
		if cr.Status != "unknown" {
			t.Fatalf("a pre-delete transport error must be unknown, got %+v", cr)
		}
	})

	t.Run("pre-delete non-200/404 fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		d := testDriver(t, srv)
		cr := d.Delete("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x", "k1")
		if cr.Status != "failed" {
			t.Fatalf("a bad pre-delete read status must fail, got %+v", cr)
		}
	})

	t.Run("pre-delete unparseable body fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()
		d := testDriver(t, srv)
		cr := d.Delete("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x", "k1")
		if cr.Status != "failed" || !strings.Contains(cr.Reason, "unparseable") {
			t.Fatalf("an unparseable pre-delete read must fail honestly, got %+v", cr)
		}
	})

	t.Run("foreign labels refuse the delete", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"settings":{"userLabels":{"team":"someone-else"}}}`))
		}))
		defer srv.Close()
		d := testDriver(t, srv)
		cr := d.Delete("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x", "k1")
		if cr.Status != "failed" || !strings.Contains(cr.Reason, "not ours") {
			t.Fatalf("a foreign instance must refuse the delete, got %+v", cr)
		}
	})

	t.Run("deletion protection blocks the delete", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"settings":{` + ownedLabels + `,"deletionProtectionEnabled":true}}`))
		}))
		defer srv.Close()
		d := testDriver(t, srv)
		cr := d.Delete("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x", "k1")
		if cr.Status != "failed" || !strings.Contains(cr.Reason, "deletion protection is enabled") {
			t.Fatalf("deletion protection must block the delete, got %+v", cr)
		}
	})

	t.Run("non-bool deletion protection flag refuses ambiguously", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"settings":{` + ownedLabels + `,"deletionProtectionEnabled":"true"}}`))
		}))
		defer srv.Close()
		d := testDriver(t, srv)
		cr := d.Delete("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x", "k1")
		if cr.Status != "failed" || !strings.Contains(cr.Reason, "not a boolean") {
			t.Fatalf("a non-bool protection flag must refuse ambiguously, got %+v", cr)
		}
	})

	t.Run("delete transport error is unknown with pid", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				_, _ = w.Write([]byte(`{"settings":{` + ownedLabels + `}}`))
			}
		}))
		d := testDriver(t, srv)
		d.HTTP = &http.Client{Transport: failOnMethod{method: "DELETE", next: srv.Client().Transport}}
		defer srv.Close()
		cr := d.Delete("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x", "k1")
		if cr.Status != "unknown" || cr.ProviderID != "acme-prod:europe-west1:orders-db-x" {
			t.Fatalf("a delete transport error must be unknown with the providerId, got %+v", cr)
		}
	})

	t.Run("delete 5xx is unknown with pid", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "GET":
				_, _ = w.Write([]byte(`{"settings":{` + ownedLabels + `}}`))
			case "DELETE":
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		}))
		defer srv.Close()
		d := testDriver(t, srv)
		cr := d.Delete("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x", "k1")
		if cr.Status != "unknown" || cr.ProviderID != "acme-prod:europe-west1:orders-db-x" {
			t.Fatalf("a 5xx on delete must be unknown with the providerId, got %+v", cr)
		}
	})

	t.Run("delete 4xx fails cleanly", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "GET":
				_, _ = w.Write([]byte(`{"settings":{` + ownedLabels + `}}`))
			case "DELETE":
				w.WriteHeader(http.StatusBadRequest)
			}
		}))
		defer srv.Close()
		d := testDriver(t, srv)
		cr := d.Delete("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x", "k1")
		if cr.Status != "failed" {
			t.Fatalf("a 400 on delete must fail cleanly, got %+v", cr)
		}
	})

	t.Run("delete response with no operation name is unknown", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "GET":
				_, _ = w.Write([]byte(`{"settings":{` + ownedLabels + `}}`))
			case "DELETE":
				_, _ = w.Write([]byte(`{}`))
			}
		}))
		defer srv.Close()
		d := testDriver(t, srv)
		cr := d.Delete("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x", "k1")
		if cr.Status != "unknown" || !strings.Contains(cr.Reason, "no operation") {
			t.Fatalf("a nameless delete operation must be unknown, got %+v", cr)
		}
	})

	t.Run("full success polls to done and carries the providerId", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"status":"DONE"}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"settings":{` + ownedLabels + `}}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"op1"}`))
			}
		}))
		defer srv.Close()
		d := testDriver(t, srv)
		cr := d.Delete("cloudsql", "orders-db", "production", "acme-prod:europe-west1:orders-db-x", "k1")
		if cr.Status != "succeeded" || cr.ProviderID != "acme-prod:europe-west1:orders-db-x" {
			t.Fatalf("a clean delete + done poll must succeed with the providerId, got %+v", cr)
		}
	})

	t.Run("invalid providerId fails before any network call", func(t *testing.T) {
		d := NewDriver("acme-prod")
		cr := d.Delete("cloudsql", "orders-db", "production", "not-a-valid-pid", "k1")
		if cr.Status != "failed" {
			t.Fatalf("an invalid providerId must fail closed, got %+v", cr)
		}
	})

	t.Run("cross-project providerId fails", func(t *testing.T) {
		d := NewDriver("acme-prod")
		cr := d.Delete("cloudsql", "orders-db", "production", "other-prod:europe-west1:orders-db-x", "k1")
		if cr.Status != "failed" {
			t.Fatalf("a cross-project providerId must fail closed, got %+v", cr)
		}
	})

	t.Run("unknown service fails closed", func(t *testing.T) {
		d := NewDriver("acme-prod")
		cr := d.Delete("__not_a_service__", "orders-db", "production", "a:b:c", "k1")
		if cr.Status != "failed" {
			t.Fatalf("an unknown service must fail closed, got %+v", cr)
		}
	})
}
