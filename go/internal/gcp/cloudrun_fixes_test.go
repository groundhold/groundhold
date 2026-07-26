package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A providerId pointing at a DIFFERENT project must not route a real mutation
// there (a forged/stale binding), even when charset-valid.
func TestCloudRunCrossProjectRefused(t *testing.T) {
	srv := runServer(t, map[string]string{"groundhold-capability": "be",
		"groundhold-environment": "prod"}, "INGRESS_TRAFFIC_ALL", 200, "")
	defer srv.Close()
	d := runDriver(t, srv) // d.Project == "acme-prod"
	res := d.deleteCloudRun("be", "prod", "cloudrun:other-proj:europe-central2:be-x")
	if res.Status != "failed" || !strings.Contains(res.Reason, "cross-project") {
		t.Fatalf("got %+v, want cross-project refusal", res)
	}
}

// A getIamPolicy 200 with no etag means no CAS — writing back would strip the
// whole policy. A public create must FAIL rather than risk that.
func TestCloudRunPublicNoEtagRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
				_, _ = w.Write([]byte(`{"bindings":[]}`)) // no etag
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/services"):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-central2/operations/op1"}`))
			case strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			default:
				w.WriteHeader(500)
			}
		}))
	defer srv.Close()
	d := runDriver(t, srv)
	res := d.createCloudRun("be", "prod", publicAttrs(), map[string]any{"image": "img"}, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "etag") {
		t.Fatalf("got %+v, want failure on the missing etag (CAS-less write)", res)
	}
}

// On 409 the desired exposure must actually match the LIVE service — Cloud Run
// update is not wired, so an owned-but-internal service under a public
// contract is a mismatch, not a convergence.
func TestCloudRun409IngressMismatchFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/services"):
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"already exists"}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"ingress":"INGRESS_TRAFFIC_INTERNAL_ONLY",` +
					`"labels":{"groundhold-capability":"be","groundhold-environment":"prod"}}`))
			default:
				w.WriteHeader(500)
			}
		}))
	defer srv.Close()
	d := runDriver(t, srv)
	res := d.createCloudRun("be", "prod", publicAttrs(), map[string]any{"image": "img"}, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "does not match desired exposure") {
		t.Fatalf("got %+v, want failure on ingress mismatch", res)
	}
}

// resume calls Reconcile for EVERY pending receipt; a Cloud Run receipt must
// NOT be reconciled with Cloud SQL logic (could bind the wrong identity). With
// the generalized reconciler (every service wired) a Cloud Run create receipt
// that persisted NO providerId stays unknown — its region is a user attribute,
// so the id is not recomputable — and it NEVER falls through to a sqladmin read.
func TestReconcileCloudRunNoIDStaysUnknown(t *testing.T) {
	d := NewDriver("acme-prod")
	res := d.Reconcile("be", "prod", map[string]any{
		"target": "gcp.cloudrun/be", "operation": "create"})
	if res.Status != "unknown" || res.ProviderID != "" {
		t.Fatalf("got %+v, want unknown with no fabricated id", res)
	}
	if strings.Contains(res.Reason, "instance") || strings.Contains(res.Reason, "sqladmin") {
		t.Fatalf("reason %q suggests a Cloud SQL fallthrough", res.Reason)
	}
}

// The generalized reconciler CONCLUDES a Cloud Run create receipt whose id
// survived a lost response (persisted as targetProviderId): the live service
// carrying our labels means the create landed — succeeded WITH the id.
func TestReconcileCloudRunConcludesByID(t *testing.T) {
	srv := runServer(t, map[string]string{"groundhold-capability": "be",
		"groundhold-environment": "prod"}, "INGRESS_TRAFFIC_ALL", 200, "")
	defer srv.Close()
	d := runDriver(t, srv) // d.Project == "acme-prod"
	pid := "cloudrun:acme-prod:europe-central2:be-x"
	ok := d.Reconcile("be", "prod", map[string]any{
		"target": "gcp.cloudrun/be", "operation": "create", "targetProviderId": pid})
	if ok.Status != "succeeded" || ok.ProviderID != pid {
		t.Fatalf("owned live service must conclude succeeded with the pinned id: %+v", ok)
	}
	// a foreign service (labels do not match) concludes failed, never succeeded.
	srv2 := runServer(t, map[string]string{"groundhold-capability": "other",
		"groundhold-environment": "prod"}, "INGRESS_TRAFFIC_ALL", 200, "")
	defer srv2.Close()
	d2 := runDriver(t, srv2)
	foreign := d2.Reconcile("be", "prod", map[string]any{
		"target": "gcp.cloudrun/be", "operation": "create", "targetProviderId": pid})
	if foreign.Status != "failed" {
		t.Fatalf("foreign-owned service must conclude failed: %+v", foreign)
	}
}
