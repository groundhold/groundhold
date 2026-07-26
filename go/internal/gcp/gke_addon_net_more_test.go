package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// This file extends gke_addon_test.go, which pins the happy create/observe/
// delete loop, the idempotent-enabled and missing-cluster branches, and
// discoverGKEAddon. These tests pin the remaining branches: updateGKEAddon
// (0% before this file — the addon-is-a-flag honest refusal), setAddon's
// error/empty-op branches, pollGKEAddonOperation's failed/timeout branches,
// getGKEAddonCluster's transport-retry path, createGKEAddon's 5xx/terminal/
// cluster-vanished branches, deleteGKEAddon's 5xx/terminal branches, and
// discoverGKEAddon's list-error branch.

// --- updateGKEAddon: the honest "nothing to patch" refusal ------------------

func TestUpdateGKEAddonRefusesAnyPath(t *testing.T) {
	d := gkeAddonDriver(t, gkeAddonServer(t, true, true))
	pid := gkeAddonProviderID("acme-prod", "us-central1", "acme-eks", "gce-pd-csi-driver")
	res := d.updateGKEAddon("csi", "prod", pid, map[string]any{"addon.name": "x"}, nil, []string{"addon.name"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "nothing to patch") {
		t.Fatalf("any change path must be honestly refused, got %+v", res)
	}
}

func TestUpdateGKEAddonNoChangesSucceeds(t *testing.T) {
	// no changes at all is a legitimate (empty) no-op update.
	d := gkeAddonDriver(t, gkeAddonServer(t, true, true))
	pid := gkeAddonProviderID("acme-prod", "us-central1", "acme-eks", "gce-pd-csi-driver")
	res := d.updateGKEAddon("csi", "prod", pid, nil, nil, nil)
	if res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("an empty change set must succeed as a no-op, got %+v", res)
	}
}

func TestUpdateGKEAddonBadProviderIDRefuses(t *testing.T) {
	d := gkeAddonDriver(t, gkeAddonServer(t, true, true))
	res := d.updateGKEAddon("csi", "prod", "gke-addon:acme-prod:us-central1:c:not-an-addon",
		nil, nil, []string{"addon.name"})
	if res.Status != "failed" {
		t.Fatalf("a malformed providerId must refuse, got %+v", res)
	}
}

// --- setAddon / pollGKEAddonOperation error branches -----------------------

func TestSetAddonTransportError(t *testing.T) {
	srv := gkeAddonServer(t, false, true)
	d := gkeAddonDriver(t, srv)
	srv.Close()
	spec := gkeAddonRegistry["gce-pd-csi-driver"]
	if _, _, _, err := d.setAddon("acme-prod", "us-central1", "acme-eks", spec, true); err == nil {
		t.Fatal("expected a transport error")
	}
}

func TestSetAddonNon200ReturnsNoOpName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	gkeAddonBaseOverride = srv.URL
	defer func() { gkeAddonBaseOverride = "" }()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	spec := gkeAddonRegistry["gce-pd-csi-driver"]
	opName, st, _, err := d.setAddon("acme-prod", "us-central1", "acme-eks", spec, true)
	if err != nil || opName != "" || st != http.StatusForbidden {
		t.Fatalf("a non-200 setAddons must return no op name, got opName=%q st=%d err=%v", opName, st, err)
	}
}

func TestSetAddonEmptyBodyReturnsNoOpName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	gkeAddonBaseOverride = srv.URL
	defer func() { gkeAddonBaseOverride = "" }()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	spec := gkeAddonRegistry["gce-pd-csi-driver"]
	opName, st, _, err := d.setAddon("acme-prod", "us-central1", "acme-eks", spec, true)
	if err != nil || opName != "" || st != http.StatusOK {
		t.Fatalf("an empty setAddons body must return no op name, got opName=%q st=%d err=%v", opName, st, err)
	}
}

func TestPollGKEAddonOperationFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"DONE","error":{"message":"quota exceeded"}}`))
	}))
	defer srv.Close()
	gkeAddonBaseOverride = srv.URL
	defer func() { gkeAddonBaseOverride = "" }()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	res := d.pollGKEAddonOperation("acme-prod", "us-central1", "operation-abc")
	if res.Status != "failed" || !strings.Contains(res.Reason, "quota exceeded") {
		t.Fatalf("a failed op must map to failed, got %+v", res)
	}
}

func TestPollGKEAddonOperationTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"RUNNING"}`))
	}))
	defer srv.Close()
	gkeAddonBaseOverride = srv.URL
	defer func() { gkeAddonBaseOverride = "" }()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.GKELROTimeout = 5 * time.Millisecond
	res := d.pollGKEAddonOperation("acme-prod", "us-central1", "operation-abc")
	if res.Status != "unknown" || !strings.Contains(res.Reason, "poll timeout") {
		t.Fatalf("a still-running op at timeout must be unknown, got %+v", res)
	}
}

// --- getGKEAddonCluster transient-retry ------------------------------------

func TestGetGKEAddonClusterRetriesOnTransient(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"name":"acme-eks","location":"us-central1","status":"RUNNING"}`))
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	doc, found, err := d.getGKEAddonCluster("acme-prod", "us-central1", "acme-eks")
	if err != nil || !found || doc.Name != "acme-eks" {
		t.Fatalf("a transient 503 must be retried to success, got doc=%+v found=%v err=%v", doc, found, err)
	}
	if n < 2 {
		t.Fatalf("expected at least 2 attempts, got %d", n)
	}
}

func TestGetGKEAddonClusterTransportErrorAfterRetries(t *testing.T) {
	srv := gkeAddonServer(t, false, true)
	d := gkeAddonDriver(t, srv)
	srv.Close()
	if _, _, err := d.getGKEAddonCluster("acme-prod", "us-central1", "acme-eks"); err == nil {
		t.Fatal("expected a transport error after exhausting retries")
	}
}

func TestGetGKEAddonClusterUnparseableBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	if _, _, err := d.getGKEAddonCluster("acme-prod", "us-central1", "acme-eks"); err == nil {
		t.Fatal("expected a body-parse error")
	}
}

// --- createGKEAddon additional branches ------------------------------------

func TestCreateGKEAddonClusterReadTransportErrorIsUnknown(t *testing.T) {
	srv := gkeAddonServer(t, false, true)
	d := gkeAddonDriver(t, srv)
	srv.Close()
	res := d.createGKEAddon("prod", "csi", gkeAddonAttrs(), gkeAddonImpl(), 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("a lost pre-create cluster read must be unknown, got %+v", res)
	}
}

func TestCreateGKEAddonSetAddonsClusterVanishedRefuses(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":setAddons"):
			w.WriteHeader(http.StatusNotFound) // vanished between read and mutate
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/clusters/"):
			n++
			_, _ = w.Write([]byte(`{"name":"acme-eks","location":"us-central1","status":"RUNNING",` +
				`"addonsConfig":{"gcePersistentDiskCsiDriverConfig":{"enabled":false}}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	res := d.createGKEAddon("prod", "csi", gkeAddonAttrs(), gkeAddonImpl(), 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "vanished before setAddons") {
		t.Fatalf("a cluster gone at setAddons time must refuse, got %+v", res)
	}
}

func TestCreateGKEAddonSetAddons5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":setAddons"):
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"message":"boom"}}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/clusters/"):
			_, _ = w.Write([]byte(`{"name":"acme-eks","location":"us-central1","status":"RUNNING",` +
				`"addonsConfig":{"gcePersistentDiskCsiDriverConfig":{"enabled":false}}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	res := d.createGKEAddon("prod", "csi", gkeAddonAttrs(), gkeAddonImpl(), 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a 503 on setAddons must be unknown WITH the pid, got %+v", res)
	}
}

func TestCreateGKEAddonSetAddonsTerminalRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":setAddons"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"malformed addon config"}}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/clusters/"):
			_, _ = w.Write([]byte(`{"name":"acme-eks","location":"us-central1","status":"RUNNING",` +
				`"addonsConfig":{"gcePersistentDiskCsiDriverConfig":{"enabled":false}}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	res := d.createGKEAddon("prod", "csi", gkeAddonAttrs(), gkeAddonImpl(), 1)
	if res.Status != "failed" {
		t.Fatalf("a clean 400 on setAddons must be a terminal failed, got %+v", res)
	}
}

func TestCreateGKEAddonSetAddonsEmptyOperationIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":setAddons"):
			_, _ = w.Write([]byte(`{}`)) // 200 but no op
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/clusters/"):
			_, _ = w.Write([]byte(`{"name":"acme-eks","location":"us-central1","status":"RUNNING",` +
				`"addonsConfig":{"gcePersistentDiskCsiDriverConfig":{"enabled":false}}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	res := d.createGKEAddon("prod", "csi", gkeAddonAttrs(), gkeAddonImpl(), 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "carried no operation") {
		t.Fatalf("an empty setAddons response must be unknown, got %+v", res)
	}
}

func TestCreateGKEAddonTransportErrorOnSetAddonsIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/clusters/") {
			_, _ = w.Write([]byte(`{"name":"acme-eks","location":"us-central1","status":"RUNNING",` +
				`"addonsConfig":{"gcePersistentDiskCsiDriverConfig":{"enabled":false}}}`))
		}
	}))
	d := gkeAddonDriver(t, srv)
	srv.Close()
	res := d.createGKEAddon("prod", "csi", gkeAddonAttrs(), gkeAddonImpl(), 1)
	if res.Status != "unknown" {
		t.Fatalf("a lost setAddons call must be unknown, got %+v", res)
	}
}

// --- deleteGKEAddon additional branches ------------------------------------

func TestDeleteGKEAddonClusterReadTransportErrorIsUnknown(t *testing.T) {
	srv := gkeAddonServer(t, true, true)
	d := gkeAddonDriver(t, srv)
	srv.Close()
	pid := gkeAddonProviderID("acme-prod", "us-central1", "acme-eks", "gce-pd-csi-driver")
	res := d.deleteGKEAddon("csi", "prod", pid)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("a lost pre-delete cluster read must be unknown, got %+v", res)
	}
}

func TestDeleteGKEAddonAlreadyDisabledIdempotent(t *testing.T) {
	srv := gkeAddonServer(t, false, true) // already disabled
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	pid := gkeAddonProviderID("acme-prod", "us-central1", "acme-eks", "gce-pd-csi-driver")
	res := d.deleteGKEAddon("csi", "prod", pid)
	if res.Status != "succeeded" {
		t.Fatalf("an already-disabled addon must be idempotent success, got %+v", res)
	}
}

func TestDeleteGKEAddonSetAddonsClusterVanishedIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":setAddons"):
			w.WriteHeader(http.StatusNotFound)
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/clusters/"):
			_, _ = w.Write([]byte(`{"name":"acme-eks","location":"us-central1","status":"RUNNING",` +
				`"addonsConfig":{"gcePersistentDiskCsiDriverConfig":{"enabled":true}}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	pid := gkeAddonProviderID("acme-prod", "us-central1", "acme-eks", "gce-pd-csi-driver")
	res := d.deleteGKEAddon("csi", "prod", pid)
	if res.Status != "succeeded" {
		t.Fatalf("a cluster gone at setAddons(disable) time must be idempotent success, got %+v", res)
	}
}

func TestDeleteGKEAddonSetAddons5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":setAddons"):
			w.WriteHeader(http.StatusServiceUnavailable)
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/clusters/"):
			_, _ = w.Write([]byte(`{"name":"acme-eks","location":"us-central1","status":"RUNNING",` +
				`"addonsConfig":{"gcePersistentDiskCsiDriverConfig":{"enabled":true}}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	pid := gkeAddonProviderID("acme-prod", "us-central1", "acme-eks", "gce-pd-csi-driver")
	res := d.deleteGKEAddon("csi", "prod", pid)
	if res.Status != "unknown" {
		t.Fatalf("a 503 on setAddons(disable) must be unknown, got %+v", res)
	}
}

func TestDeleteGKEAddonSetAddonsTerminalRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":setAddons"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"cannot disable"}}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/clusters/"):
			_, _ = w.Write([]byte(`{"name":"acme-eks","location":"us-central1","status":"RUNNING",` +
				`"addonsConfig":{"gcePersistentDiskCsiDriverConfig":{"enabled":true}}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	pid := gkeAddonProviderID("acme-prod", "us-central1", "acme-eks", "gce-pd-csi-driver")
	res := d.deleteGKEAddon("csi", "prod", pid)
	if res.Status != "failed" {
		t.Fatalf("a clean 400 on setAddons(disable) must be a terminal failed, got %+v", res)
	}
}

func TestDeleteGKEAddonSetAddonsEmptyOperationIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":setAddons"):
			_, _ = w.Write([]byte(`{}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/clusters/"):
			_, _ = w.Write([]byte(`{"name":"acme-eks","location":"us-central1","status":"RUNNING",` +
				`"addonsConfig":{"gcePersistentDiskCsiDriverConfig":{"enabled":true}}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	pid := gkeAddonProviderID("acme-prod", "us-central1", "acme-eks", "gce-pd-csi-driver")
	res := d.deleteGKEAddon("csi", "prod", pid)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "carried no operation") {
		t.Fatalf("an empty setAddons(disable) response must be unknown, got %+v", res)
	}
}

// --- discoverGKEAddon error branches ----------------------------------

func TestDiscoverGKEAddonListTransportErrorIsError(t *testing.T) {
	srv := gkeAddonServer(t, true, true)
	d := gkeAddonDriver(t, srv)
	srv.Close()
	if _, _, err := d.discoverGKEAddon(""); err == nil {
		t.Fatal("expected a transport error")
	}
}

func TestDiscoverGKEAddonListNon200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	if _, _, err := d.discoverGKEAddon(""); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected an HTTP 403 error, got %v", err)
	}
}

func TestDiscoverGKEAddonUnparseableBodyIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	if _, _, err := d.discoverGKEAddon(""); err == nil {
		t.Fatal("expected a body-parse error")
	}
}

func TestDiscoverGKEAddonSkipsUnnamedClusters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/locations/-/clusters") {
			_, _ = w.Write([]byte(`{"clusters":[{"name":"","location":"us-central1"},` +
				`{"name":"c","location":""}]}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	found, _, err := d.discoverGKEAddon("")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("clusters missing a name or location must be skipped, got %+v", found)
	}
}

func TestDiscoverGKEAddonObserveErrorIsDiagnosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/locations/-/clusters"):
			_, _ = w.Write([]byte(`{"clusters":[{"name":"acme-eks","location":"us-central1",` +
				`"addonsConfig":{"gcePersistentDiskCsiDriverConfig":{"enabled":true}}}]}`))
		case strings.Contains(r.URL.Path, "/clusters/"):
			w.WriteHeader(http.StatusForbidden) // observeGKEAddon's own cluster read fails
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	found, diags, err := d.discoverGKEAddon("")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("an observe error must not produce a discovered resource, got %+v", found)
	}
	if len(diags) == 0 {
		t.Fatal("an observe error during discover must be diagnosed")
	}
}
