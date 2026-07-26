package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// cfServer routes both the Cloud Functions v2 calls AND the backing Cloud Run
// IAM calls (public exposure's second gate). IAM is stateful: the run policy
// gains the allUsers invoker only after setIamPolicy.
func cfServer(t *testing.T, opError string, ingress string) *httptest.Server {
	t.Helper()
	granted := false
	fnDoc := func() string {
		return `{"labels":{"groundhold-capability":"api","groundhold-environment":"prod"},` +
			`"serviceConfig":{"ingressSettings":"` + ingress + `","minInstanceCount":1,` +
			`"service":"projects/acme-prod/locations/europe-central2/services/api-run"}}`
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			// Cloud Run IAM (backing service) — getIamPolicy is GET, setIamPolicy POST
			case strings.HasSuffix(p, ":getIamPolicy"):
				if r.Method != "GET" {
					t.Errorf("getIamPolicy must be GET, got %s", r.Method)
				}
				if granted {
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[{"role":"roles/run.invoker","members":["allUsers"]}]}`))
				} else {
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[]}`))
				}
			case strings.HasSuffix(p, ":setIamPolicy"):
				if r.Method != "POST" {
					t.Errorf("setIamPolicy must be POST, got %s", r.Method)
				}
				granted = true
				_, _ = w.Write([]byte(`{"etag":"e2"}`))
			// Cloud Functions operations (LRO {done,error})
			case strings.Contains(p, "/operations/"):
				if opError != "" {
					_, _ = w.Write([]byte(`{"name":"op","done":true,"error":{"message":"` + opError + `"}}`))
				} else {
					_, _ = w.Write([]byte(`{"name":"op","done":true}`))
				}
			case r.Method == "POST" && strings.Contains(p, "/functions"):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-central2/operations/op-create"}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-central2/operations/op-del"}`))
			case r.Method == "GET" && strings.Contains(p, "/functions/"):
				_, _ = w.Write([]byte(fnDoc()))
			case r.Method == "GET" && strings.Contains(p, "/services/"):
				// the backing Cloud Run service (observe reads invokerIamDisabled)
				_, _ = w.Write([]byte(`{"invokerIamDisabled":false}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
}

func cfDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.CfBaseURL = srv.URL
	d.RunBaseURL = srv.URL // backing-service IAM points at the same test server
	return d
}

func TestCreateCloudFunctionPublicGrantsInvoker(t *testing.T) {
	srv := cfServer(t, "", "ALLOW_ALL")
	defer srv.Close()
	d := cfDriver(t, srv)
	res := d.createCloudFunction("api", "prod", cfAttrs(), cfImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "cloudfunctions:acme-prod:") {
		t.Fatalf("got %+v, want succeeded + cf-prefixed id", res)
	}
}

// A function op that DONE-errors is failed, no pid (nothing durable committed).
func TestCreateCloudFunctionOpErrorFails(t *testing.T) {
	srv := cfServer(t, "BUILD_FAILED", "ALLOW_ALL")
	defer srv.Close()
	d := cfDriver(t, srv)
	res := d.createCloudFunction("api", "prod", cfAttrs(), cfImpl(), 1)
	if res.Status != "failed" {
		t.Fatalf("a DONE-with-error op must fail, got %+v", res)
	}
}

func TestObserveCloudFunctionPublicTwoGate(t *testing.T) {
	srv := cfServer(t, "", "ALLOW_ALL")
	defer srv.Close()
	d := cfDriver(t, srv)
	// create first so the backing invoker binding exists
	if r := d.createCloudFunction("api", "prod", cfAttrs(), cfImpl(), 1); r.Status != "succeeded" {
		t.Fatalf("setup create failed: %+v", r)
	}
	obs, _, err := d.observeCloudFunction("api", "cloudfunctions:acme-prod:europe-central2:api-1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["network.publicExposure"] != true {
		t.Fatalf("ALLOW_ALL + allUsers invoker must be public, got %v", got["network.publicExposure"])
	}
	if got["replicas.minimum"] != float64(1) {
		t.Fatalf("minInstanceCount 1 -> replicas.minimum 1, got %v", got["replicas.minimum"])
	}
}

// Internal ingress is definitively private regardless of IAM — no backing-service read needed.
func TestObserveCloudFunctionInternalIsPrivate(t *testing.T) {
	srv := cfServer(t, "", "ALLOW_INTERNAL_ONLY")
	defer srv.Close()
	d := cfDriver(t, srv)
	obs, _, err := d.observeCloudFunction("api", "cloudfunctions:acme-prod:europe-central2:api-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "network.publicExposure" && o.Value != false {
			t.Fatalf("internal ingress must be private, got %v", o.Value)
		}
	}
}

func TestDeleteCloudFunctionOurs(t *testing.T) {
	srv := cfServer(t, "", "ALLOW_ALL")
	defer srv.Close()
	d := cfDriver(t, srv)
	res := d.deleteCloudFunction("api", "prod", "cloudfunctions:acme-prod:europe-central2:api-1")
	if res.Status != "succeeded" {
		t.Fatalf("delete of an owned function must succeed, got %+v", res)
	}
}

func TestDeleteCloudFunctionForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"other","groundhold-environment":"prod"}}`))
		}))
	defer srv.Close()
	d := cfDriver(t, srv)
	res := d.deleteCloudFunction("api", "prod", "cloudfunctions:acme-prod:europe-central2:api-1")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign-labeled function must refuse delete, got %+v", res)
	}
}

// D84 review #1: a 409 on an ours function whose live ingress != desired must
// refuse (update not wired), never report succeeded — the exposure would lie.
func TestCreateCloudFunction409IngressMismatchRefused(t *testing.T) {
	// existing function is ALLOW_INTERNAL_ONLY; the create wants public (ALLOW_ALL)
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.Contains(r.URL.Path, "/functions"):
				w.WriteHeader(http.StatusConflict)
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/functions/"):
				_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"api","groundhold-environment":"prod"},` +
					`"serviceConfig":{"ingressSettings":"ALLOW_INTERNAL_ONLY"}}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
	defer srv.Close()
	d := cfDriver(t, srv)
	res := d.createCloudFunction("api", "prod", cfAttrs(), cfImpl(), 1) // cfAttrs is public
	if res.Status != "failed" || !strings.Contains(res.Reason, "ingress") {
		t.Fatalf("ingress mismatch on 409 must refuse, got %+v", res)
	}
}

// D84 review #2: a backing service with invokerIamDisabled=true is public even
// with no allUsers binding — observe must measure publicExposure=true.
func TestObserveCloudFunctionInvokerDisabledPublic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
				t.Errorf("must not consult IAM policy when invokerIamDisabled is set")
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/functions/"):
				_, _ = w.Write([]byte(`{"serviceConfig":{"ingressSettings":"ALLOW_ALL",` +
					`"service":"projects/acme-prod/locations/europe-central2/services/api-run"}}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/services/"):
				_, _ = w.Write([]byte(`{"invokerIamDisabled":true}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
	defer srv.Close()
	d := cfDriver(t, srv)
	obs, _, err := d.observeCloudFunction("api", "cloudfunctions:acme-prod:europe-central2:api-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "network.publicExposure" && o.Value != true {
			t.Fatalf("invokerIamDisabled must measure public, got %v", o.Value)
		}
	}
}

func TestSplitFunctionProviderIDAndBacking(t *testing.T) {
	if _, _, _, err := splitFunctionProviderID("cloudfunctions:p:europe-central2:api-fn"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	for _, bad := range []string{"p:r:n", "gcs:p:r:n", "cloudfunctions:p:r:n:x", "cloudfunctions:p:UP:n"} {
		if _, _, _, err := splitFunctionProviderID(bad); err == nil {
			t.Errorf("accepted malformed cf id %q", bad)
		}
	}
	if p, r, n, ok := backingService("projects/acme/locations/europe-central2/services/svc-1"); !ok ||
		p != "acme" || r != "europe-central2" || n != "svc-1" {
		t.Fatalf("backingService parse = %s/%s/%s ok=%v", p, r, n, ok)
	}
	if _, _, _, ok := backingService("projects/acme/services/svc"); ok {
		t.Error("malformed backing-service path must be rejected")
	}
}
