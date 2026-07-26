package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// runServer routes the Cloud Run v2 calls. It is STATEFUL for IAM: getIamPolicy
// returns an allUsers invoker binding only AFTER setIamPolicy was called, so a
// public-create's read-modify-write-confirm sequence is exercised end to end.
// setIamStatus lets a test simulate Domain-Restricted-Sharing.
func runServer(t *testing.T, labels map[string]string, ingress string, setIamStatus int, setIamBody string) *httptest.Server {
	t.Helper()
	granted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case strings.HasSuffix(p, ":getIamPolicy"):
				// Cloud Run v2 getIamPolicy is a GET; a POST hits no route live
				// (HTML 404). Pin the method so a regression fails here, not only
				// against the real API.
				if r.Method != "GET" {
					t.Errorf("getIamPolicy must be GET, got %s", r.Method)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if granted {
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[` +
						`{"role":"roles/run.invoker","members":["allUsers"]}]}`))
				} else {
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[]}`))
				}
			case strings.HasSuffix(p, ":setIamPolicy"):
				if r.Method != "POST" {
					t.Errorf("setIamPolicy must be POST, got %s", r.Method)
				}
				if setIamStatus != 0 && setIamStatus != 200 {
					w.WriteHeader(setIamStatus)
					_, _ = w.Write([]byte(setIamBody))
					return
				}
				body, _ := io.ReadAll(r.Body)
				// must be append-only read-modify-write: carry the etag
				if !strings.Contains(string(body), `"etag":"e1"`) {
					t.Errorf("setIamPolicy without the etag (lost-update risk): %s", body)
				}
				granted = true
				_, _ = w.Write([]byte(`{"etag":"e2"}`))
			case r.Method == "POST" && strings.HasSuffix(p, "/services"):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-central2/operations/op1"}`))
			case strings.Contains(p, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-central2/operations/opdel"}`))
			case r.Method == "GET": // services.get
				// a created/adopted service always carries its server-assigned uri
				// (the D330 output derivation reads it).
				svc := map[string]any{"ingress": ingress, "labels": labels,
					"uri": "https://svc-fake.a.run.app"}
				_ = json.NewEncoder(w).Encode(svc)
			default:
				w.WriteHeader(500)
			}
		}))
}

func runDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.RunBaseURL = srv.URL
	d.PollInterval = 0
	return d
}

func publicAttrs() map[string]any {
	return map[string]any{"location.region": "europe-central2",
		"network.publicExposure": true, "service.managed": true}
}

func TestCloudRunCreatePublicGrantsInvoker(t *testing.T) {
	srv := runServer(t, nil, "INGRESS_TRAFFIC_ALL", 200, "")
	defer srv.Close()
	d := runDriver(t, srv)
	res := d.createCloudRun("be", "prod", publicAttrs(),
		map[string]any{"image": "img"}, 1)
	if res.Status != "succeeded" {
		t.Fatalf("got %+v, want succeeded", res)
	}
	if !strings.HasPrefix(res.ProviderID, "cloudrun:acme-prod:europe-central2:") {
		t.Fatalf("providerId=%q, want cloudrun-prefixed", res.ProviderID)
	}
}

// The critical honesty case: create succeeds but the allUsers grant is blocked
// by org policy — the service exists yet is NOT public, so the result must be
// FAILED (never succeeded), naming DRS distinctly from a permission error.
func TestCloudRunPublicBlockedByDRSIsFailed(t *testing.T) {
	srv := runServer(t, nil, "INGRESS_TRAFFIC_ALL", 400,
		`{"error":{"message":"One or more users named in the policy do not `+
			`belong to a permitted customer, per domain restricted sharing."}}`)
	defer srv.Close()
	d := runDriver(t, srv)
	res := d.createCloudRun("be", "prod", publicAttrs(),
		map[string]any{"image": "img"}, 1)
	if res.Status != "failed" {
		t.Fatalf("got %+v, want failed (a non-public service must not report succeeded)", res)
	}
	if !strings.Contains(res.Reason, "domain-restricted-sharing") {
		t.Fatalf("reason=%q, want the DRS org-policy reason", res.Reason)
	}
}

func TestCloudRunCreatePrivateSkipsIAM(t *testing.T) {
	srv := runServer(t, nil, "INGRESS_TRAFFIC_INTERNAL_ONLY", 500, "boom")
	defer srv.Close()
	d := runDriver(t, srv)
	attrs := map[string]any{"location.region": "europe-central2",
		"network.publicExposure": false, "service.managed": true}
	res := d.createCloudRun("be", "prod", attrs, map[string]any{"image": "img"}, 1)
	if res.Status != "succeeded" {
		t.Fatalf("got %+v, want succeeded (private needs no IAM)", res)
	}
}

func TestCloudRunDeleteRefusesNotOurs(t *testing.T) {
	srv := runServer(t, map[string]string{"groundhold-capability": "other",
		"groundhold-environment": "prod"}, "INGRESS_TRAFFIC_ALL", 200, "")
	defer srv.Close()
	d := runDriver(t, srv)
	res := d.deleteCloudRun("be", "prod", "cloudrun:acme-prod:europe-central2:be-x")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("got %+v, want failed on ownership", res)
	}
}

func TestCloudRunDeleteOursSucceeds(t *testing.T) {
	srv := runServer(t, map[string]string{"groundhold-capability": "be",
		"groundhold-environment": "prod"}, "INGRESS_TRAFFIC_ALL", 200, "")
	defer srv.Close()
	d := runDriver(t, srv)
	res := d.deleteCloudRun("be", "prod", "cloudrun:acme-prod:europe-central2:be-x")
	if res.Status != "succeeded" {
		t.Fatalf("got %+v, want succeeded", res)
	}
}

func TestSplitRunProviderID(t *testing.T) {
	if _, _, _, err := splitRunProviderID("cloudrun:p:r:name"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	bad := []string{
		"p:r:name",                          // no service token (cloudsql form)
		"cloudsql:p:r:name",                 // wrong service token
		"cloudrun:p:r:name:extra",           // too many parts
		"cloudrun:p:r:../evil",              // path traversal in name
		"cloudrun:p:r:UPPER",                // charset
		"projects/p/locations/r/services/n", // slash-form REST name
	}
	for _, b := range bad {
		if _, _, _, err := splitRunProviderID(b); err == nil {
			t.Errorf("accepted a malformed/foreign providerId: %q", b)
		}
	}
}

// TestCloudRunOutputsURI: the D330 output derivation reads the server-assigned
// *.run.app uri via one services.get. A readable service publishes uri; an
// unreadable/empty one is an ERROR (reconcile), never a fabricated absence.
func TestCloudRunOutputsURI(t *testing.T) {
	const pid = "cloudrun:acme-prod:europe-central2:be-abc123"
	t.Run("readable service publishes uri", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				_, _ = w.Write([]byte(`{"uri":"https://be-abc123-ew.a.run.app","ingress":"INGRESS_TRAFFIC_ALL"}`))
				return
			}
			w.WriteHeader(500)
		}))
		defer srv.Close()
		d := runDriver(t, srv)
		outs, err := d.ReadOutputs("cloudrun", pid)
		if err != nil {
			t.Fatalf("ReadOutputs: %v", err)
		}
		if outs["uri"] != "https://be-abc123-ew.a.run.app" {
			t.Fatalf("uri = %v, want the run.app host", outs["uri"])
		}
	})
	t.Run("empty uri is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"ingress":"INGRESS_TRAFFIC_ALL"}`))
		}))
		defer srv.Close()
		d := runDriver(t, srv)
		if _, err := d.ReadOutputs("cloudrun", pid); err == nil {
			t.Fatal("an empty uri must be an error, not a fabricated absence")
		}
	})
	t.Run("read failure is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		d := runDriver(t, srv)
		if _, err := d.ReadOutputs("cloudrun", pid); err == nil {
			t.Fatal("a non-200 read must be an error (reconcile)")
		}
	})
}
