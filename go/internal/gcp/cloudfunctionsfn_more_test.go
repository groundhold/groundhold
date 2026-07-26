package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file extends cloudfunctionsfn_test.go, which pins the happy paths
// (public create, observe, delete-foreign-refused, output URL) plus the
// transient-fault and bounded-poll certifications. These tests pin the
// remaining branches of the low-level readers (getFnServerless,
// fnServerlessPublicURL, runFnInvokerState, readFnInvokerPolicy),
// discoverCloudFunctionFn (list -> reverse-map, the least-covered function in
// the file), deleteCloudFunctionFn's pre-delete/delete error branches, and
// createCloudFunctionFn's conflict/exposure-gate branches.

// ─── getFnServerless / fnServerlessPublicURL / runFnInvokerState / readFnInvokerPolicy ───

func TestGetFnServerlessErrorBranches(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := fnDriver(t, srv)
		srv.Close()
		if _, err := d.getFnServerless("acme-prod", "europe-west1", "api-fn"); err == nil {
			t.Fatal("expected a transport error")
		}
	})
	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		_, err := d.getFnServerless("acme-prod", "europe-west1", "api-fn")
		if err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("expected an HTTP 403 error, got %v", err)
		}
	})
	t.Run("unparseable body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		_, err := d.getFnServerless("acme-prod", "europe-west1", "api-fn")
		if err == nil || !strings.Contains(err.Error(), "did not parse") {
			t.Fatalf("expected a body-parse error, got %v", err)
		}
	})
}

func TestFnServerlessPublicURLErrorBranches(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := fnDriver(t, srv)
		srv.Close()
		if _, err := d.fnServerlessPublicURL("acme-prod", "europe-west1", "api-fn"); err == nil {
			t.Fatal("expected a transport error")
		}
	})
	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		if _, err := d.fnServerlessPublicURL("acme-prod", "europe-west1", "api-fn"); err == nil {
			t.Fatal("expected an HTTP error")
		}
	})
	t.Run("unparseable body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		if _, err := d.fnServerlessPublicURL("acme-prod", "europe-west1", "api-fn"); err == nil {
			t.Fatal("expected a body-parse error")
		}
	})
	// ALLOW_ALL but neither url nor serviceConfig.uri is present: the API
	// promised public exposure but has not yet surfaced the trigger — this
	// must be an ERROR (reconcile), never a silent empty string.
	t.Run("ALLOW_ALL with no url yet", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"serviceConfig":{"ingressSettings":"ALLOW_ALL"}}`))
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		_, err := d.fnServerlessPublicURL("acme-prod", "europe-west1", "api-fn")
		if err == nil || !strings.Contains(err.Error(), "no url yet") {
			t.Fatalf("expected the 'no url yet' error, got %v", err)
		}
	})
	// the backing Cloud Run uri is an acceptable fallback when url is absent.
	t.Run("falls back to serviceConfig.uri", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"serviceConfig":{"ingressSettings":"ALLOW_ALL","uri":"https://backing.a.run.app"}}`))
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		url, err := d.fnServerlessPublicURL("acme-prod", "europe-west1", "api-fn")
		if err != nil || url != "https://backing.a.run.app" {
			t.Fatalf("url=%q err=%v", url, err)
		}
	})
}

func TestRunFnInvokerStateErrorBranches(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := fnDriver(t, srv)
		srv.Close()
		if _, err := d.runFnInvokerState("acme-prod", "europe-west1", "api-run"); err == nil {
			t.Fatal("expected a transport error")
		}
	})
	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		if _, err := d.runFnInvokerState("acme-prod", "europe-west1", "api-run"); err == nil {
			t.Fatal("expected an HTTP error")
		}
	})
	t.Run("unparseable body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		if _, err := d.runFnInvokerState("acme-prod", "europe-west1", "api-run"); err == nil {
			t.Fatal("expected a body-parse error")
		}
	})
}

func TestReadFnInvokerPolicyErrorBranches(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := fnDriver(t, srv)
		srv.Close()
		if _, err := d.readFnInvokerPolicy("acme-prod", "europe-west1", "api-run"); err == nil {
			t.Fatal("expected a transport error")
		}
	})
	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		if _, err := d.readFnInvokerPolicy("acme-prod", "europe-west1", "api-run"); err == nil {
			t.Fatal("expected an HTTP error")
		}
	})
	t.Run("unparseable body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		if _, err := d.readFnInvokerPolicy("acme-prod", "europe-west1", "api-run"); err == nil {
			t.Fatal("expected a body-parse error")
		}
	})
	t.Run("no allUsers binding is a clean false", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"bindings":[{"role":"roles/run.invoker","members":["user:a@b.com"]}]}`))
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		public, err := d.readFnInvokerPolicy("acme-prod", "europe-west1", "api-run")
		if err != nil || public {
			t.Fatalf("public=%v err=%v, want false/nil", public, err)
		}
	})
}

// ─── observeCloudFunctionFn diagnostics ─────────────────────────────────────

func TestObserveCloudFunctionFnDiagnosticBranches(t *testing.T) {
	const pid = "cffn:acme-prod:europe-west1:api-fn"

	t.Run("unknown ingress value is a diagnostic, not a fabricated observation", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"serviceConfig":{"ingressSettings":"","minInstanceCount":0}}`))
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		obs, diags, err := d.observeCloudFunctionFn("api", pid)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range obs {
			if o.Path == "network.publicExposure" {
				t.Fatalf("an unknown ingress must not publish network.publicExposure, got %+v", o)
			}
		}
		if len(diags) == 0 {
			t.Fatal("expected a diagnostic for the unknown ingress value")
		}
	})

	t.Run("ALLOW_INTERNAL_ONLY observes publicExposure false directly", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"serviceConfig":{"ingressSettings":"ALLOW_INTERNAL_ONLY","minInstanceCount":0}}`))
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		obs, diags, err := d.observeCloudFunctionFn("api", pid)
		if err != nil || len(diags) != 0 {
			t.Fatalf("obs=%v diags=%v err=%v", obs, diags, err)
		}
		found := false
		for _, o := range obs {
			if o.Path == "network.publicExposure" {
				found = true
				if o.Value != false {
					t.Fatalf("ALLOW_INTERNAL_ONLY must observe publicExposure=false, got %v", o.Value)
				}
			}
		}
		if !found {
			t.Fatal("expected a network.publicExposure observation")
		}
	})

	t.Run("ALLOW_ALL with unparseable backing service path is a diagnostic", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"serviceConfig":{"ingressSettings":"ALLOW_ALL","minInstanceCount":0,"service":"not-a-path"}}`))
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		obs, diags, err := d.observeCloudFunctionFn("api", pid)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range obs {
			if o.Path == "network.publicExposure" {
				t.Fatalf("an unparseable backing path must not publish publicExposure, got %+v", o)
			}
		}
		if len(diags) == 0 {
			t.Fatal("expected a diagnostic for the unparseable backing service path")
		}
	})

	t.Run("ALLOW_ALL with cross-project backing service is a diagnostic", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"serviceConfig":{"ingressSettings":"ALLOW_ALL","minInstanceCount":0,"service":"projects/other-prod/locations/europe-west1/services/api-run"}}`))
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		_, diags, err := d.observeCloudFunctionFn("api", pid)
		if err != nil {
			t.Fatal(err)
		}
		if len(diags) == 0 {
			t.Fatal("expected a diagnostic for the cross-project backing service")
		}
	})

	t.Run("ALLOW_ALL with an unreadable backing service state is a diagnostic", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/functions/"):
				_, _ = w.Write([]byte(`{"serviceConfig":{"ingressSettings":"ALLOW_ALL","minInstanceCount":0,"service":"projects/acme-prod/locations/europe-west1/services/api-run"}}`))
			case strings.Contains(r.URL.Path, "/services/"):
				w.WriteHeader(http.StatusForbidden)
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		_, diags, err := d.observeCloudFunctionFn("api", pid)
		if err != nil {
			t.Fatal(err)
		}
		if len(diags) == 0 {
			t.Fatal("expected a diagnostic for the unreadable backing service")
		}
	})

	t.Run("ALLOW_ALL with disabled invoker IAM observes publicExposure true without reading the policy", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/functions/"):
				_, _ = w.Write([]byte(`{"serviceConfig":{"ingressSettings":"ALLOW_ALL","minInstanceCount":0,"service":"projects/acme-prod/locations/europe-west1/services/api-run"}}`))
			case strings.Contains(r.URL.Path, "/services/"):
				_, _ = w.Write([]byte(`{"invokerIamDisabled":true}`))
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		obs, diags, err := d.observeCloudFunctionFn("api", pid)
		if err != nil || len(diags) != 0 {
			t.Fatalf("obs=%v diags=%v err=%v", obs, diags, err)
		}
		found := false
		for _, o := range obs {
			if o.Path == "network.publicExposure" {
				found = true
				if o.Value != true {
					t.Fatalf("invokerIamDisabled=true must observe publicExposure=true, got %v", o.Value)
				}
			}
		}
		if !found {
			t.Fatal("expected a network.publicExposure observation")
		}
	})

	t.Run("ALLOW_ALL with an unreadable IAM policy is a diagnostic", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/functions/"):
				_, _ = w.Write([]byte(`{"serviceConfig":{"ingressSettings":"ALLOW_ALL","minInstanceCount":0,"service":"projects/acme-prod/locations/europe-west1/services/api-run"}}`))
			case strings.Contains(r.URL.Path, "/services/") && strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
				w.WriteHeader(http.StatusForbidden)
			case strings.Contains(r.URL.Path, "/services/"):
				_, _ = w.Write([]byte(`{"invokerIamDisabled":false}`))
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		_, diags, err := d.observeCloudFunctionFn("api", pid)
		if err != nil {
			t.Fatal(err)
		}
		if len(diags) == 0 {
			t.Fatal("expected a diagnostic for the unreadable IAM policy")
		}
	})

	t.Run("ALLOW_ALL with a readable policy lacking allUsers observes publicExposure false", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/functions/"):
				_, _ = w.Write([]byte(`{"serviceConfig":{"ingressSettings":"ALLOW_ALL","minInstanceCount":0,"service":"projects/acme-prod/locations/europe-west1/services/api-run"}}`))
			case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
				_, _ = w.Write([]byte(`{"bindings":[]}`))
			case strings.Contains(r.URL.Path, "/services/"):
				_, _ = w.Write([]byte(`{"invokerIamDisabled":false}`))
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		obs, diags, err := d.observeCloudFunctionFn("api", pid)
		if err != nil || len(diags) != 0 {
			t.Fatalf("obs=%v diags=%v err=%v", obs, diags, err)
		}
		found := false
		for _, o := range obs {
			if o.Path == "network.publicExposure" {
				found = true
				if o.Value != false {
					t.Fatalf("no allUsers binding must observe publicExposure=false, got %v", o.Value)
				}
			}
		}
		if !found {
			t.Fatal("expected a network.publicExposure observation")
		}
	})
}

// ─── discoverCloudFunctionFn ─────────────────────────────────────────────────

func TestDiscoverCloudFunctionFnHappyAndSkips(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/functions") && r.Method == "GET":
			_, _ = w.Write([]byte(`{"functions":[
				{"name":"projects/acme-prod/locations/europe-west1/functions/api-fn"},
				{"name":"malformed"},
				{"name":"projects/acme-prod/locations/europe-west1/functions/bad-fn"}
			]}`))
		case strings.HasSuffix(r.URL.Path, "/functions/api-fn"):
			_, _ = w.Write([]byte(`{"serviceConfig":{"ingressSettings":"ALLOW_INTERNAL_ONLY","minInstanceCount":0}}`))
		case strings.HasSuffix(r.URL.Path, "/functions/bad-fn"):
			w.WriteHeader(http.StatusForbidden) // observe fails for this one
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	d := fnDriver(t, srv)

	out, diags, err := d.discoverCloudFunctionFn("europe-west1")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].ProviderID != "cffn:acme-prod:europe-west1:api-fn" {
		t.Fatalf("discover must yield exactly the one observable function, got %+v", out)
	}
	if out[0].ResourceType != "capability.function.serverless" {
		t.Fatalf("ResourceType = %q", out[0].ResourceType)
	}
	found := false
	for _, dg := range diags {
		if strings.Contains(dg, "bad-fn") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a diagnostic naming the unobservable function, got %v", diags)
	}
}

func TestDiscoverCloudFunctionFnListErrors(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := fnDriver(t, srv)
		srv.Close()
		if _, _, err := d.discoverCloudFunctionFn("europe-west1"); err == nil {
			t.Fatal("expected a transport error")
		}
	})
	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		if _, _, err := d.discoverCloudFunctionFn("europe-west1"); err == nil {
			t.Fatal("expected an HTTP error")
		}
	})
	t.Run("unparseable body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		if _, _, err := d.discoverCloudFunctionFn("europe-west1"); err == nil {
			t.Fatal("expected an unparseable-response error")
		}
	})
}

// ─── deleteCloudFunctionFn error branches ───────────────────────────────────

const fnDeletePID = "cffn:acme-prod:europe-west1:api-fn"

func TestDeleteCloudFunctionFnBranches(t *testing.T) {
	t.Run("404 pre-delete read is idempotent success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.deleteCloudFunctionFn("api", "prod", fnDeletePID)
		if res.Status != "succeeded" || res.ProviderID != fnDeletePID {
			t.Fatalf("a vanished function must be idempotent success, got %+v", res)
		}
	})

	t.Run("pre-delete transport error is unknown", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := fnDriver(t, srv)
		srv.Close()
		res := d.deleteCloudFunctionFn("api", "prod", fnDeletePID)
		if res.Status != "unknown" {
			t.Fatalf("a pre-delete transport error must be unknown, got %+v", res)
		}
	})

	t.Run("pre-delete non-200/404 fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.deleteCloudFunctionFn("api", "prod", fnDeletePID)
		if res.Status != "failed" {
			t.Fatalf("a bad pre-delete read status must fail, got %+v", res)
		}
	})

	t.Run("pre-delete unparseable body refuses an ambiguous delete", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.deleteCloudFunctionFn("api", "prod", fnDeletePID)
		if res.Status != "unknown" || !strings.Contains(res.Reason, "unparseable") {
			t.Fatalf("an unparseable pre-delete body must refuse ambiguously (unknown), got %+v", res)
		}
	})

	t.Run("delete transport error is unknown with pid", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"api","groundhold-environment":"prod"}}`))
				return
			}
		}))
		d := fnDriver(t, srv)
		d.HTTP = &http.Client{Transport: failOnMethod{method: "DELETE", next: srv.Client().Transport}}
		defer srv.Close()
		res := d.deleteCloudFunctionFn("api", "prod", fnDeletePID)
		if res.Status != "unknown" || res.ProviderID != fnDeletePID {
			t.Fatalf("a delete transport error must be unknown with the providerId, got %+v", res)
		}
	})

	t.Run("delete 404 is idempotent success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "GET":
				_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"api","groundhold-environment":"prod"}}`))
			case "DELETE":
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.deleteCloudFunctionFn("api", "prod", fnDeletePID)
		if res.Status != "succeeded" || res.ProviderID != fnDeletePID {
			t.Fatalf("a 404 on delete must be idempotent success, got %+v", res)
		}
	})

	t.Run("delete 5xx is unknown with pid", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "GET":
				_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"api","groundhold-environment":"prod"}}`))
			case "DELETE":
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.deleteCloudFunctionFn("api", "prod", fnDeletePID)
		if res.Status != "unknown" || res.ProviderID != fnDeletePID {
			t.Fatalf("a 5xx on delete must be unknown with the providerId, got %+v", res)
		}
	})

	t.Run("delete 4xx fails cleanly", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "GET":
				_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"api","groundhold-environment":"prod"}}`))
			case "DELETE":
				w.WriteHeader(http.StatusBadRequest)
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.deleteCloudFunctionFn("api", "prod", fnDeletePID)
		if res.Status != "failed" {
			t.Fatalf("a 400 on delete must fail cleanly, got %+v", res)
		}
	})

	t.Run("delete response with no operation name is unknown", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "GET":
				_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"api","groundhold-environment":"prod"}}`))
			case "DELETE":
				_, _ = w.Write([]byte(`{}`))
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.deleteCloudFunctionFn("api", "prod", fnDeletePID)
		if res.Status != "unknown" || !strings.Contains(res.Reason, "no operation") {
			t.Fatalf("a nameless delete operation must be unknown, got %+v", res)
		}
	})

	t.Run("full success polls to done", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"api","groundhold-environment":"prod"}}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op-del"}`))
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.deleteCloudFunctionFn("api", "prod", fnDeletePID)
		if res.Status != "succeeded" || res.ProviderID != fnDeletePID {
			t.Fatalf("a clean delete + done poll must succeed with the providerId, got %+v", res)
		}
	})

	t.Run("invalid providerId fails before any network call", func(t *testing.T) {
		d := NewDriver("acme-prod")
		res := d.deleteCloudFunctionFn("api", "prod", "not-a-valid-pid")
		if res.Status != "failed" {
			t.Fatalf("an invalid providerId must fail closed, got %+v", res)
		}
	})

	t.Run("cross-project providerId fails", func(t *testing.T) {
		d := NewDriver("acme-prod")
		res := d.deleteCloudFunctionFn("api", "prod", "cffn:other-prod:europe-west1:api-fn")
		if res.Status != "failed" {
			t.Fatalf("a cross-project providerId must fail closed, got %+v", res)
		}
	})
}

// ─── createCloudFunctionFn conflict / exposure-gate branches ────────────────

func TestCreateCloudFunctionFnConflictBranches(t *testing.T) {
	t.Run("conflict where the existing function read fails is unknown", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST":
				w.WriteHeader(http.StatusConflict)
			case r.Method == "GET":
				w.WriteHeader(http.StatusForbidden)
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.createCloudFunctionFn("api", "prod", fnAttrs(), fnImpl(), 1)
		if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
			t.Fatalf("an unreadable conflicting function must be unknown, got %+v", res)
		}
	})

	t.Run("conflict with foreign labels fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST":
				w.WriteHeader(http.StatusConflict)
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"other","groundhold-environment":"prod"},"serviceConfig":{"ingressSettings":"ALLOW_ALL"}}`))
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.createCloudFunctionFn("api", "prod", fnAttrs(), fnImpl(), 1)
		if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
			t.Fatalf("a conflicting foreign function must fail, got %+v", res)
		}
	})

	t.Run("conflict with mismatched ingress fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST":
				w.WriteHeader(http.StatusConflict)
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"api","groundhold-environment":"prod"},"serviceConfig":{"ingressSettings":"ALLOW_INTERNAL_ONLY"}}`))
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.createCloudFunctionFn("api", "prod", fnAttrs(), fnImpl(), 1) // fnAttrs wants public (ALLOW_ALL)
		if res.Status != "failed" || !strings.Contains(res.Reason, "does not match desired") {
			t.Fatalf("a conflicting ingress mismatch must fail, got %+v", res)
		}
	})

	t.Run("non-conflict 4xx on create fails cleanly", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				w.WriteHeader(http.StatusBadRequest)
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.createCloudFunctionFn("api", "prod", fnAttrs(), fnImpl(), 1)
		if res.Status != "failed" {
			t.Fatalf("a 400 on create must fail cleanly, got %+v", res)
		}
	})

	t.Run("5xx on create is unknown with pid", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.createCloudFunctionFn("api", "prod", fnAttrs(), fnImpl(), 1)
		if res.Status != "unknown" || res.ProviderID == "" {
			t.Fatalf("a 5xx on create must be unknown WITH the deterministic pid, got %+v", res)
		}
	})

	t.Run("create response with no operation name is unknown", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				_, _ = w.Write([]byte(`{}`))
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.createCloudFunctionFn("api", "prod", fnAttrs(), fnImpl(), 1)
		if res.Status != "unknown" || !strings.Contains(res.Reason, "no operation") {
			t.Fatalf("a nameless create operation must be unknown, got %+v", res)
		}
	})

	t.Run("public create whose backing service is not yet readable is unknown", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "POST":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op-create"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/functions/"):
				// no serviceConfig.service yet
				_, _ = w.Write([]byte(`{"serviceConfig":{"ingressSettings":"ALLOW_ALL"}}`))
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.createCloudFunctionFn("api", "prod", fnAttrs(), fnImpl(), 1)
		if res.Status != "unknown" || !strings.Contains(res.Reason, "not yet readable") {
			t.Fatalf("a missing backing service must be unknown, got %+v", res)
		}
	})

	t.Run("public create with an unparseable backing service path is unknown", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "POST":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op-create"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/functions/"):
				_, _ = w.Write([]byte(`{"serviceConfig":{"ingressSettings":"ALLOW_ALL","service":"not-a-path"}}`))
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.createCloudFunctionFn("api", "prod", fnAttrs(), fnImpl(), 1)
		if res.Status != "unknown" || !strings.Contains(res.Reason, "unparseable") {
			t.Fatalf("an unparseable backing-service path must be unknown, got %+v", res)
		}
	})

	t.Run("public create with a cross-project backing service is unknown", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "POST":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op-create"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/functions/"):
				_, _ = w.Write([]byte(`{"serviceConfig":{"ingressSettings":"ALLOW_ALL","service":"projects/other-prod/locations/europe-west1/services/api-run"}}`))
			}
		}))
		defer srv.Close()
		d := fnDriver(t, srv)
		res := d.createCloudFunctionFn("api", "prod", fnAttrs(), fnImpl(), 1)
		if res.Status != "unknown" || !strings.Contains(res.Reason, "outside the function's project") {
			t.Fatalf("a cross-project backing service must be unknown, got %+v", res)
		}
	})
}

// TestCreateCloudFunctionFnPrivateNoExposureGate: a private create never
// touches the exposure gate (no setIamPolicy) and succeeds directly off the
// operation poll.
func TestCreateCloudFunctionFnPrivateNoExposureGate(t *testing.T) {
	iamCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":setIamPolicy"), strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			iamCalled = true
			_, _ = w.Write([]byte(`{}`))
		case strings.Contains(r.URL.Path, "/operations/"):
			_, _ = w.Write([]byte(`{"done":true}`))
		case r.Method == "POST":
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op-create"}`))
		}
	}))
	defer srv.Close()
	d := fnDriver(t, srv)
	attrs := fnAttrs()
	attrs["network.publicExposure"] = false
	res := d.createCloudFunctionFn("api", "prod", attrs, fnImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("a private create must succeed, got %+v", res)
	}
	if iamCalled {
		t.Fatal("a private create must never touch the IAM exposure gate")
	}
}
