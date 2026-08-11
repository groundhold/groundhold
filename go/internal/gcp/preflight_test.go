package gcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testIamPermissions echoes back all requested permissions EXCEPT any in
// deny, so a test can stage exactly which come back missing.
func crmServer(t *testing.T, deny map[string]bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, ":testIamPermissions") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			var body struct {
				Permissions []string `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			granted := []string{}
			for _, p := range body.Permissions {
				if !deny[p] {
					granted = append(granted, p)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"permissions": granted})
		}))
}

// TestCheckPermissionsScopedElsewhereIsUnattestedNotBlocking (D917): a permission not valid
// for a PROJECT resource (billing.*) makes projects.testIamPermissions 400 the WHOLE request.
// The check must peel that permission off (unattested — the project surface cannot vouch for a
// billing-account permission), still attest the project-scoped ones, and NOT fail closed.
func TestCheckPermissionsScopedElsewhereIsUnattestedNotBlocking(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Permissions []string `json:"permissions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, p := range body.Permissions {
			if strings.HasPrefix(p, "billing.") {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":{"code":400,"message":"Permission ` + p + ` is not valid for this resource.","status":"INVALID_ARGUMENT"}}`))
				return
			}
		}
		granted := []string{}
		granted = append(granted, body.Permissions...)
		_ = json.NewEncoder(w).Encode(map[string]any{"permissions": granted})
	}))
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.CRMBaseURL = srv.URL
	denied, unattested, err := d.CheckPermissions("acme-prod",
		[]string{"billing.budgets.create", "resourcemanager.projects.get"})
	if err != nil {
		t.Fatalf("a billing permission must not make the whole preflight fail closed: %v", err)
	}
	if len(denied) != 0 {
		t.Fatalf("nothing was denied, got %v", denied)
	}
	if len(unattested) != 1 || unattested[0] != "billing.budgets.create" {
		t.Fatalf("the billing permission must be unattested (scoped off the project), got %v", unattested)
	}
	// and an all-billing request attests nothing, blocks nothing
	_, un2, err := d.CheckPermissions("acme-prod", []string{"billing.budgets.create", "billing.budgets.delete"})
	if err != nil || len(un2) != 2 {
		t.Fatalf("all-billing preflight: err=%v unattested=%v", err, un2)
	}
}

func TestCheckPermissionsAllHeld(t *testing.T) {
	srv := crmServer(t, nil)
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.CRMBaseURL = srv.URL
	denied, unattested, err := d.CheckPermissions("acme-prod",
		[]string{"cloudsql.instances.create", "cloudsql.instances.get"})
	if err != nil {
		t.Fatal(err)
	}
	if len(denied) != 0 || len(unattested) != 0 {
		t.Fatalf("expected all held, got denied=%v unattested=%v", denied, unattested)
	}
}

// A CRM-ATTESTED permission (cloudsql.*) omitted from the response IS an
// authoritative denial — fast-fail is preserved for the surfaces CRM evaluates.
func TestCheckPermissionsAttestedOmissionIsDenied(t *testing.T) {
	srv := crmServer(t, map[string]bool{"cloudsql.instances.delete": true})
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.CRMBaseURL = srv.URL
	denied, unattested, err := d.CheckPermissions("acme-prod",
		[]string{"cloudsql.instances.delete", "cloudsql.instances.get"})
	if err != nil {
		t.Fatal(err)
	}
	if len(denied) != 1 || denied[0] != "cloudsql.instances.delete" {
		t.Fatalf("expected denied=[cloudsql.instances.delete], got %v", denied)
	}
	if len(unattested) != 0 {
		t.Fatalf("expected no unattested, got %v", unattested)
	}
}

// D78 regression: the CRM project surface omits resource-scoped storage.*
// permissions the identity actually holds. An omission there is NOT a denial —
// it is unattested, so the executor treats it as inconclusive, never as
// provider-permission-denied. (Proven live on an Owner identity.)
func TestCheckPermissionsStorageOmissionIsUnattested(t *testing.T) {
	// The server omits get/getIamPolicy/setIamPolicy but returns create — the
	// exact live pattern that caused groundhold to lie to an authorized user.
	srv := crmServer(t, map[string]bool{
		"storage.buckets.get":          true,
		"storage.buckets.getIamPolicy": true,
		"storage.buckets.setIamPolicy": true,
	})
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.CRMBaseURL = srv.URL
	denied, unattested, err := d.CheckPermissions("acme-prod", []string{
		"storage.buckets.create", "storage.buckets.get",
		"storage.buckets.getIamPolicy", "storage.buckets.setIamPolicy"})
	if err != nil {
		t.Fatal(err)
	}
	if len(denied) != 0 {
		t.Fatalf("storage omission must NEVER be denied, got denied=%v", denied)
	}
	if len(unattested) != 3 {
		t.Fatalf("expected 3 unattested storage permissions, got %v", unattested)
	}
}

// A non-200 on the check itself (CRM API disabled, scope/creds) is an ERROR
// — the executor maps it to preflight-inconclusive, never to a denial.
func TestCheckPermissionsAPIDisabledIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(
				`{"error":{"status":"PERMISSION_DENIED",` +
					`"message":"Cloud Resource Manager API has not been used"}}`))
		}))
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.CRMBaseURL = srv.URL
	if _, _, err := d.CheckPermissions("acme-prod",
		[]string{"cloudsql.instances.create"}); err == nil {
		t.Fatal("expected an error when the check cannot run")
	}
}
