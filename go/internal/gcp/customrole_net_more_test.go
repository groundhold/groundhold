package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file extends customrole_test.go, which pins the happy create/observe/
// delete loop and the mutating/privileged classification. These tests pin the
// remaining branches: sameStringSet (0% before this file), splitGCRoleProviderID's
// validation ladder, getCustomRole's error branches, createCustomRole's
// transport/5xx/conflict-mismatch branches, observeCustomRole's not-found/
// soft-deleted branch, and deleteCustomRole's transport/5xx branches.

// --- sameStringSet -----------------------------------------------------

func TestSameStringSet(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{[]string{"a", "b"}, []string{"b", "a"}, true}, // order-independent
		{[]string{"a", "b"}, []string{"a"}, false},     // different length
		{[]string{"a", "b"}, []string{"a", "c"}, false},
		{nil, nil, true},
		{[]string{}, []string{}, true},
	}
	for _, c := range cases {
		if got := sameStringSet(c.a, c.b); got != c.want {
			t.Errorf("sameStringSet(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// --- splitGCRoleProviderID -----------------------------------------------

func TestSplitGCRoleProviderID(t *testing.T) {
	if _, _, err := splitGCRoleProviderID(gcRoleProviderID("acme-prod", "viewer_role")); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	cases := []string{
		"role:acme-prod:viewer", // wrong prefix
		"gcrole:acme-prod",      // too few parts
		"gcrole:BAD PROJECT:x",  // invalid project
		"gcrole:acme-prod:a b",  // invalid roleId (space)
		"gcrole:acme-prod:x!",   // invalid roleId char
	}
	for _, c := range cases {
		if _, _, err := splitGCRoleProviderID(c); err == nil {
			t.Errorf("accepted malformed gcrole id %q", c)
		}
	}
}

// --- getCustomRole error branches -------------------------------------

func TestGetCustomRoleErrorBranches(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := customRoleDriver(t, srv)
		srv.Close()
		if _, _, err := d.getCustomRole("acme-prod", "viewer"); err == nil {
			t.Fatal("expected a transport error")
		}
	})
	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		d := customRoleDriver(t, srv)
		if _, _, err := d.getCustomRole("acme-prod", "viewer"); err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("expected an HTTP 403 error, got %v", err)
		}
	})
	t.Run("unparseable body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()
		d := customRoleDriver(t, srv)
		if _, _, err := d.getCustomRole("acme-prod", "viewer"); err == nil {
			t.Fatal("expected a body-parse error")
		}
	})
	t.Run("404 is a clean absence", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		d := customRoleDriver(t, srv)
		_, found, err := d.getCustomRole("acme-prod", "viewer")
		if err != nil || found {
			t.Fatalf("a 404 must be found=false, err=nil, got found=%v err=%v", found, err)
		}
	})
}

// --- createCustomRole transport/5xx/conflict branches ------------------

func TestCreateCustomRoleTransportErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d := customRoleDriver(t, srv)
	srv.Close()
	res := d.createCustomRole("viewer", "prod", roleAttrs(), nil, 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a lost create must be unknown WITH the deterministic pid, got %+v", res)
	}
}

func TestCreateCustomRole5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	d := customRoleDriver(t, srv)
	res := d.createCustomRole("viewer", "prod", roleAttrs(), nil, 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a 503 create must be unknown WITH the pid, got %+v", res)
	}
}

func TestCreateCustomRoleTerminalRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"malformed role"}}`))
		}
	}))
	defer srv.Close()
	d := customRoleDriver(t, srv)
	res := d.createCustomRole("viewer", "prod", roleAttrs(), nil, 1)
	if res.Status != "failed" {
		t.Fatalf("a clean 400 must be a terminal failed, got %+v", res)
	}
}

func TestCreateCustomRoleConflictReadUnreadableIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			w.WriteHeader(http.StatusConflict)
		case "GET":
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	d := customRoleDriver(t, srv)
	res := d.createCustomRole("viewer", "prod", roleAttrs(), nil, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("an unreadable follow-up must be unknown, got %+v", res)
	}
}

func TestCreateCustomRoleConflictDifferentPermsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			w.WriteHeader(http.StatusConflict)
		case "GET":
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/roles/viewer","includedPermissions":["storage.objects.delete"]}`))
		}
	}))
	defer srv.Close()
	d := customRoleDriver(t, srv)
	res := d.createCustomRole("viewer", "prod", roleAttrs(), nil, 1) // roleAttrs has get/list, not delete
	if res.Status != "failed" || !strings.Contains(res.Reason, "DIFFERENT permission set") {
		t.Fatalf("a conflicting role with different permissions must refuse, got %+v", res)
	}
}

func TestCreateCustomRoleConflictNotFoundOnFollowupRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			w.WriteHeader(http.StatusConflict)
		case "GET":
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	d := customRoleDriver(t, srv)
	res := d.createCustomRole("viewer", "prod", roleAttrs(), nil, 1)
	if res.Status != "failed" {
		t.Fatalf("a conflict whose follow-up read is 404 (not found) must refuse, got %+v", res)
	}
}

func TestCreateCustomRoleConflictSamePermsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			w.WriteHeader(http.StatusConflict)
		case "GET":
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/roles/viewer",` +
				`"includedPermissions":["storage.objects.get","storage.objects.list"]}`))
		}
	}))
	defer srv.Close()
	d := customRoleDriver(t, srv)
	res := d.createCustomRole("viewer", "prod", roleAttrs(), nil, 1) // same set, different order
	if res.Status != "succeeded" {
		t.Fatalf("a matching conflict (idempotent) must succeed, got %+v", res)
	}
}

// --- observeCustomRole not-found / soft-deleted branch ------------------

func TestObserveCustomRoleNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := customRoleDriver(t, srv)
	obs, diags, err := d.observeCustomRole("viewer", gcRoleProviderID("acme-prod", gcRoleID("prod", "viewer", 1)))
	// Corrected with D521: this asserted SILENCE for an absent bound resource,
	// which is the defect F-LC3 exists to prevent.
	if err != nil || !absentMarked(obs) || len(diags) == 0 {
		t.Fatalf("a gone role must be nothing-to-observe, got obs=%v diags=%v err=%v", obs, diags, err)
	}
}

func TestObserveCustomRoleSoftDeleted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"projects/acme-prod/roles/viewer","deleted":true,` +
			`"includedPermissions":["storage.objects.get"]}`))
	}))
	defer srv.Close()
	d := customRoleDriver(t, srv)
	obs, diags, err := d.observeCustomRole("viewer", gcRoleProviderID("acme-prod", gcRoleID("prod", "viewer", 1)))
	// Corrected with D521: this asserted SILENCE for an absent bound resource,
	// which is the defect F-LC3 exists to prevent.
	if err != nil || !absentMarked(obs) || len(diags) == 0 {
		t.Fatalf("a soft-deleted role must be nothing-to-observe, got obs=%v diags=%v err=%v", obs, diags, err)
	}
}

func TestObserveCustomRoleErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	d := customRoleDriver(t, srv)
	if _, _, err := d.observeCustomRole("viewer", gcRoleProviderID("acme-prod", gcRoleID("prod", "viewer", 1))); err == nil {
		t.Fatal("an unreadable role must propagate an error, not nothing-to-observe")
	}
}

func TestObserveCustomRoleCrossProjectRefused(t *testing.T) {
	d := customRoleDriver(t, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	if _, _, err := d.observeCustomRole("viewer", gcRoleProviderID("other-proj", "viewer")); err == nil || !strings.Contains(err.Error(), "cross-project") {
		t.Fatalf("a cross-project pid must refuse, got %v", err)
	}
}

// --- deleteCustomRole transport/5xx branches -----------------------------

func TestDeleteCustomRoleTransportErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d := customRoleDriver(t, srv)
	srv.Close()
	res := d.deleteCustomRole("viewer", "prod", gcRoleProviderID("acme-prod", gcRoleID("prod", "viewer", 1)))
	if res.Status != "unknown" {
		t.Fatalf("a lost delete must be unknown, got %+v", res)
	}
}

func TestDeleteCustomRole5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	d := customRoleDriver(t, srv)
	res := d.deleteCustomRole("viewer", "prod", gcRoleProviderID("acme-prod", gcRoleID("prod", "viewer", 1)))
	if res.Status != "unknown" {
		t.Fatalf("a 503 delete must be unknown, got %+v", res)
	}
}

func TestDeleteCustomRoleNotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := customRoleDriver(t, srv)
	res := d.deleteCustomRole("viewer", "prod", gcRoleProviderID("acme-prod", gcRoleID("prod", "viewer", 1)))
	if res.Status != "succeeded" {
		t.Fatalf("a 404 delete must be idempotent success, got %+v", res)
	}
}

func TestDeleteCustomRoleTerminalRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"bad delete"}}`))
	}))
	defer srv.Close()
	d := customRoleDriver(t, srv)
	res := d.deleteCustomRole("viewer", "prod", gcRoleProviderID("acme-prod", gcRoleID("prod", "viewer", 1)))
	if res.Status != "failed" {
		t.Fatalf("a clean 400 delete must be a terminal failed, got %+v", res)
	}
}

func TestDeleteCustomRoleCrossProjectRefused(t *testing.T) {
	d := customRoleDriver(t, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	res := d.deleteCustomRole("viewer", "prod", gcRoleProviderID("other-proj", "viewer"))
	if res.Status != "failed" || !strings.Contains(res.Reason, "cross-project") {
		t.Fatalf("a cross-project pid must refuse the delete, got %+v", res)
	}
}
