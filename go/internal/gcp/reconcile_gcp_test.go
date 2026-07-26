package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The generalized reconciler (reconcile_gcp.go) concludes a pending receipt for
// EVERY GCP service, not just Cloud SQL. These tests exercise the shared dispatch,
// verdict ladder and google-LRO-first path across representative services: an async
// label-owned service (memorystore), a sync label-owned service driven through the
// deterministic-id REBUILD (secretmanager), a description-marker service
// (serviceaccount), a content-addressed service (firestore), a server-assigned-id
// service (dashboard) and a stateful/structural service (gke). Four-valued honesty
// throughout: succeeded only on found+ours+ready; failed on foreign-owned; unknown on
// absent/unreadable/not-ready.

func recDriver(t *testing.T, project string) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver(project)
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = time.Second
	d.GKELROTimeout = time.Second // keep GKE LRO polls fast (default is 60m)
	return d
}

// ---- memorystore: async, label ownership, google LRO-first ----

func TestReconcileMemorystore(t *testing.T) {
	// instance JSON keyed by whether it is ours; operation JSON by the ?op=.
	var instBody string
	var opBody string
	var serveInstance bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/instances/"):
				if !serveInstance {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_, _ = w.Write([]byte(instBody))
			default: // operation poll: memorystoreBase + "/" + opName
				_, _ = w.Write([]byte(opBody))
			}
		}))
	defer srv.Close()
	d := recDriver(t, "acme-prod")
	d.MemorystoreBaseURL = srv.URL

	pid := gredisProviderID("acme-prod", "europe-central2", "red-x")
	ours := `{"labels":{"groundhold-capability":"cache","groundhold-environment":"prod"},"state":"READY"}`
	foreign := `{"labels":{},"state":"READY"}`
	create := func() map[string]any {
		return map[string]any{"target": "gcp.memorystore/cache",
			"operation": "create", "targetProviderId": pid}
	}

	// found + ours + ready -> succeeded with the pinned id
	serveInstance, instBody = true, ours
	if r := d.Reconcile("cache", "prod", create()); r.Status != "succeeded" || r.ProviderID != pid {
		t.Fatalf("owned+ready must succeed: %+v", r)
	}
	// found + foreign -> failed
	instBody = foreign
	if r := d.Reconcile("cache", "prod", create()); r.Status != "failed" {
		t.Fatalf("foreign must fail: %+v", r)
	}
	// absent -> unknown (may have failed or not yet visible)
	serveInstance = false
	if r := d.Reconcile("cache", "prod", create()); r.Status != "unknown" {
		t.Fatalf("absent create must stay unknown: %+v", r)
	}
	// delete: absent -> succeeded; present -> failed
	del := map[string]any{"target": "gcp.memorystore/cache",
		"operation": "delete", "targetProviderId": pid}
	if r := d.Reconcile("cache", "prod", del); r.Status != "succeeded" || r.ProviderID != pid {
		t.Fatalf("delete of an absent instance must succeed: %+v", r)
	}
	serveInstance, instBody = true, ours
	if r := d.Reconcile("cache", "prod", del); r.Status != "failed" {
		t.Fatalf("delete of a live instance must fail: %+v", r)
	}

	// LRO-first: a DONE operation carrying an error concludes failed BEFORE any read.
	serveInstance = false
	opBody = `{"done":true,"error":{"message":"quota exceeded"}}`
	withOp := map[string]any{"target": "gcp.memorystore/cache", "operation": "create",
		"targetProviderId": pid, "providerOperation": "operations/op1"}
	if r := d.Reconcile("cache", "prod", withOp); r.Status != "failed" {
		t.Fatalf("DONE+error op must conclude failed: %+v", r)
	}
	// a still-running operation stays unknown.
	opBody = `{"done":false}`
	if r := d.Reconcile("cache", "prod", withOp); r.Status != "unknown" {
		t.Fatalf("running op must stay unknown: %+v", r)
	}
	// a DONE+clean operation falls through to the resource read (owned -> succeeded).
	opBody = `{"done":true}`
	serveInstance, instBody = true, ours
	if r := d.Reconcile("cache", "prod", withOp); r.Status != "succeeded" {
		t.Fatalf("DONE-clean op must fall through to a succeeded read: %+v", r)
	}
}

// ---- secretmanager: sync, label ownership, deterministic-id REBUILD (no persisted id) ----

func TestReconcileSecretRebuildsID(t *testing.T) {
	body := `{"labels":{"groundhold-capability":"sec","groundhold-environment":"prod"}}`
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
	defer srv.Close()
	d := recDriver(t, "acme-prod")
	d.SecretBaseURL = srv.URL

	// a create receipt that persisted NO providerId: the reconciler REBUILDS the
	// deterministic id from (project, env, cap, gen) and concludes by reading it.
	want := gsecretProviderID("acme-prod", resourceName("acme-prod", "prod", "sec", 1, 255))
	r := d.Reconcile("sec", "prod", map[string]any{
		"target": "gcp.secretmanager/sec", "operation": "create", "generation": 1})
	if r.Status != "succeeded" || r.ProviderID != want {
		t.Fatalf("rebuilt-id create must succeed with the deterministic id: %+v (want %s)", r, want)
	}
}

// ---- serviceaccount: description-marker ownership ----

func TestReconcileServiceAccountMarker(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
	defer srv.Close()
	d := recDriver(t, "acme-prod")
	d.IAMBaseURL = srv.URL

	pid := gsaProviderID("acme-prod", "pv-sa-abc")
	create := map[string]any{"target": "gcp.serviceaccount/sa",
		"operation": "create", "targetProviderId": pid}

	body = `{"description":` + jsonString(vpcOwnerMarker("sa", "prod")) + `}`
	if r := d.Reconcile("sa", "prod", create); r.Status != "succeeded" || r.ProviderID != pid {
		t.Fatalf("our marker must succeed: %+v", r)
	}
	body = `{"description":"someone else's account"}`
	if r := d.Reconcile("sa", "prod", create); r.Status != "failed" {
		t.Fatalf("a foreign marker must fail: %+v", r)
	}
}

// ---- firestore: content-addressed ownership (found implies ours) ----

func TestReconcileFirestore(t *testing.T) {
	var found bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if !found {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/databases/db-x"}`))
		}))
	defer srv.Close()
	d := recDriver(t, "acme-prod")
	d.FirestoreBaseURL = srv.URL

	pid := firestoreProviderID("acme-prod", "db-x")
	create := map[string]any{"target": "gcp.firestore/fs",
		"operation": "create", "targetProviderId": pid}
	found = true
	if r := d.Reconcile("fs", "prod", create); r.Status != "succeeded" || r.ProviderID != pid {
		t.Fatalf("found database at our id must succeed: %+v", r)
	}
	found = false
	if r := d.Reconcile("fs", "prod", create); r.Status != "unknown" {
		t.Fatalf("absent create must stay unknown: %+v", r)
	}
}

// ---- dashboard: server-assigned id ----

func TestReconcileDashboardServerAssigned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"displayName":"groundhold dash (prod)"}`))
		}))
	defer srv.Close()
	d := recDriver(t, "acme-prod")
	d.DashboardBaseURL = srv.URL

	// no persisted id: a server-assigned create cannot be concluded — unknown + hint.
	noID := d.Reconcile("dash", "prod", map[string]any{
		"target": "gcp.dashboard/dash", "operation": "create"})
	if noID.Status != "unknown" || !strings.Contains(noID.Reason, "displayName") {
		t.Fatalf("server-assigned create with no id must be unknown w/ a displayName hint: %+v", noID)
	}
	// with a persisted id + matching displayName marker: succeeded.
	pid := gdashProviderID("acme-prod", "1234567890")
	ok := d.Reconcile("dash", "prod", map[string]any{
		"target": "gcp.dashboard/dash", "operation": "create", "targetProviderId": pid})
	if ok.Status != "succeeded" || ok.ProviderID != pid {
		t.Fatalf("matching displayName must succeed: %+v", ok)
	}
}

// ---- gke: stateful/structural readiness ----

func TestReconcileGKEReadiness(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
	defer srv.Close()
	d := recDriver(t, "acme-prod")
	gkeBaseURLOverride = srv.URL
	t.Cleanup(func() { gkeBaseURLOverride = "" })

	pid := gkeProviderID("acme-prod", "europe-central2", "cl-x")
	create := map[string]any{"target": "gcp.gke/k8s",
		"operation": "create", "targetProviderId": pid}
	labels := `"resourceLabels":{"groundhold-capability":"k8s","groundhold-environment":"prod"}`

	body = `{"status":"RUNNING",` + labels + `}`
	if r := d.Reconcile("k8s", "prod", create); r.Status != "succeeded" || r.ProviderID != pid {
		t.Fatalf("RUNNING+ours must succeed: %+v", r)
	}
	body = `{"status":"PROVISIONING",` + labels + `}`
	if r := d.Reconcile("k8s", "prod", create); r.Status != "unknown" {
		t.Fatalf("not-ready cluster must stay unknown: %+v", r)
	}
	body = `{"status":"RUNNING","resourceLabels":{}}`
	if r := d.Reconcile("k8s", "prod", create); r.Status != "failed" {
		t.Fatalf("foreign cluster must fail: %+v", r)
	}
}

// jsonString quotes s as a JSON string literal for embedding in a fixture.
func jsonString(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// TestReconcileAsyncNotReady pins the fix for three async services (filestore,
// managedkafka, certmanager) that previously hardcoded ready:true and so concluded
// SUCCEEDED for a resource still provisioning (or failed). A live, owned resource in a
// non-terminal state must reconcile UNKNOWN — never a fabricated succeeded. Ready-state
// success is already covered elsewhere; this is the negative the earlier tests missed.
func TestReconcileAsyncNotReady(t *testing.T) {
	body := func(state string) string {
		return `{"labels":{"groundhold-capability":"x","groundhold-environment":"prod"},"state":"` + state + `"}`
	}
	newSrv := func(payload string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(payload))
		}))
	}
	d := recDriver(t, "acme-prod")

	// filestore CREATING -> unknown
	s1 := newSrv(body("CREATING"))
	defer s1.Close()
	d.FilestoreBaseURL = s1.URL
	if r := d.Reconcile("x", "prod", map[string]any{"target": "gcp.filestore/x", "operation": "create",
		"targetProviderId": filestoreProviderID("acme-prod", "europe-west1", "fs-x")}); r.Status != "unknown" {
		t.Fatalf("filestore CREATING must be unknown, got %+v", r)
	}
	// managedkafka CREATING -> unknown
	s2 := newSrv(body("CREATING"))
	defer s2.Close()
	d.ManagedKafkaBaseURL = s2.URL
	if r := d.Reconcile("x", "prod", map[string]any{"target": "gcp.managedkafka/x", "operation": "create",
		"targetProviderId": managedKafkaProviderID("acme-prod", "europe-west1", "kf-x")}); r.Status != "unknown" {
		t.Fatalf("managedkafka CREATING must be unknown, got %+v", r)
	}
	// certmanager managed.state PROVISIONING -> unknown
	s3 := newSrv(`{"labels":{"groundhold-capability":"x","groundhold-environment":"prod"},"managed":{"state":"PROVISIONING"}}`)
	defer s3.Close()
	d.CertManagerBaseURL = s3.URL
	if r := d.Reconcile("x", "prod", map[string]any{"target": "gcp.certmanager/x", "operation": "create",
		"targetProviderId": certManagerProviderID("acme-prod", "europe-west1", "ct-x")}); r.Status != "unknown" {
		t.Fatalf("certmanager PROVISIONING must be unknown, got %+v", r)
	}
}
