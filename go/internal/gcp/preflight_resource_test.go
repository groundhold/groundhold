package gcp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// resourceIAMServer answers testIamPermissions at the resource scope, echoing
// every requested permission EXCEPT those in deny. It PINS the HTTP method per
// service (GCS=GET, Cloud Run=POST) — the getIamPolicy incident proved method
// drift is real, so a regression must fail here, not only against live GCP.
func resourceIAMServer(t *testing.T, deny map[string]bool, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, "/iam/testPermissions") &&
				!strings.HasSuffix(r.URL.Path, ":testIamPermissions") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if status != 0 && status != 200 {
				w.WriteHeader(status)
				return
			}
			// GCS is a GET with query perms; Cloud Run is a POST with a body.
			var reqPerms []string
			if strings.HasSuffix(r.URL.Path, "/iam/testPermissions") {
				if r.Method != "GET" {
					t.Errorf("GCS testIamPermissions must be GET, got %s", r.Method)
				}
				reqPerms = r.URL.Query()["permissions"]
			} else {
				if r.Method != "POST" {
					t.Errorf("Cloud Run testIamPermissions must be POST, got %s", r.Method)
				}
				var b struct {
					Permissions []string `json:"permissions"`
				}
				_ = json.NewDecoder(r.Body).Decode(&b)
				reqPerms = b.Permissions
			}
			granted := []string{}
			for _, p := range reqPerms {
				if !deny[p] {
					granted = append(granted, p)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"permissions": granted})
		}))
}

func TestResourcePermissionsGCSAuthoritativeDenial(t *testing.T) {
	srv := resourceIAMServer(t, map[string]bool{"storage.buckets.delete": true}, 200)
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.GcsBaseURL = srv.URL
	denied, err := d.CheckResourcePermissions("gcs", "gcs:acme-prod:the-bucket",
		[]string{"storage.buckets.get", "storage.buckets.delete"})
	if err != nil {
		t.Fatal(err)
	}
	// resource-level omission IS a denial (authoritative), unlike the project surface
	if len(denied) != 1 || denied[0] != "storage.buckets.delete" {
		t.Fatalf("expected authoritative denied=[storage.buckets.delete], got %v", denied)
	}
}

func TestResourcePermissionsCloudRunPost(t *testing.T) {
	srv := resourceIAMServer(t, nil, 200)
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.RunBaseURL = srv.URL
	denied, err := d.CheckResourcePermissions("cloudrun",
		"cloudrun:acme-prod:europe-central2:web-1",
		[]string{"run.services.get", "run.services.delete"})
	if err != nil {
		t.Fatal(err)
	}
	if len(denied) != 0 {
		t.Fatalf("all held -> no denials, got %v", denied)
	}
}

func TestResourcePermissionsPubSubPost(t *testing.T) {
	srv := resourceIAMServer(t, map[string]bool{"pubsub.topics.delete": true}, 200)
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.PubSubBaseURL = srv.URL
	denied, err := d.CheckResourcePermissions("pubsub-topic", "pubsub:acme-prod:the-topic",
		[]string{"pubsub.topics.get", "pubsub.topics.delete"})
	if err != nil {
		t.Fatal(err)
	}
	// resource-level omission IS an authoritative denial (POST :testIamPermissions)
	if len(denied) != 1 || denied[0] != "pubsub.topics.delete" {
		t.Fatalf("expected authoritative denied=[pubsub.topics.delete], got %v", denied)
	}
}

func TestResourcePermissionsCloudSQLHasNoSurface(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	_, err := d.CheckResourcePermissions("cloudsql", "acme-prod:europe-west1:db-1",
		[]string{"cloudsql.instances.delete"})
	if !errors.Is(err, provider.ErrNoResourceSurface) {
		t.Fatalf("cloud sql must report no resource surface, got %v", err)
	}
}

// A resource that cannot be read (404/500) is inconclusive — an ERROR, never a
// denial. Deleting a bucket whose IAM surface 404s must not be reported as a
// permission denial (the resource may simply be gone — that is drift, not authz).
func TestResourcePermissionsUnreadableIsErrorNotDenial(t *testing.T) {
	srv := resourceIAMServer(t, nil, http.StatusNotFound)
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.GcsBaseURL = srv.URL
	denied, err := d.CheckResourcePermissions("gcs", "gcs:acme-prod:the-bucket",
		[]string{"storage.buckets.delete"})
	if err == nil {
		t.Fatal("an unreadable surface must return an error (inconclusive), not a denial")
	}
	if len(denied) != 0 {
		t.Fatalf("no denials on an unreadable surface, got %v", denied)
	}
}

// A malformed 200 must be an ERROR (inconclusive), NEVER an empty grant set
// that turns every requested permission into an authoritative denial (that
// would resurrect the D78 lie through a parse failure).
func TestResourcePermissionsMalformed200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"permissions": NOT_JSON`))
		}))
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.GcsBaseURL = srv.URL
	denied, err := d.CheckResourcePermissions("gcs", "gcs:acme-prod:the-bucket",
		[]string{"storage.buckets.get", "storage.buckets.delete"})
	if err == nil {
		t.Fatal("a malformed 200 must be an error, not all-denied")
	}
	if len(denied) != 0 {
		t.Fatalf("no denials on a malformed response, got %v", denied)
	}
}

func TestResourcePermissionsCrossProjectRefused(t *testing.T) {
	srv := resourceIAMServer(t, nil, 200)
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod") // pinned project acme-prod
	if _, err := d.CheckResourcePermissions("gcs", "gcs:other-proj:the-bucket",
		[]string{"storage.buckets.delete"}); err == nil {
		t.Fatal("a cross-project providerId must be refused")
	}
}
