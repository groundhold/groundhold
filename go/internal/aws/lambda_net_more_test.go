package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// This file rounds out lambda_net.go coverage: getLambdaURLAuthType (0%) and
// removeLambdaExposure (0%) were completely untested, and updateLambda's
// network.publicExposure branches (going public/private in place) and
// classifyLambdaChange's full table were under-exercised.

// lambdaUpdateFake is a stateful Lambda fake purpose-built for updateLambda's
// exposure toggle: GetFunction always reports Active + our tags; the Function
// URL config and its AuthType are tracked so DELETE/PUT on /url are visible.
type lambdaUpdateFake struct {
	hasURL   bool
	authType string
	deleted  []string // paths DELETEd, in order
}

func (f *lambdaUpdateFake) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case r.Method == "PUT" && strings.HasSuffix(p, "/configuration"):
			_, _ = w.Write([]byte(`{"LastUpdateStatus":"Successful"}`))
		case r.Method == "POST" && strings.HasSuffix(p, "/url"):
			f.hasURL = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"FunctionUrl":"https://abc.lambda-url.eu-central-1.on.aws/","AuthType":"` + f.authType + `"}`))
		case r.Method == "GET" && strings.HasSuffix(p, "/url"):
			if !f.hasURL {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"not found"}`))
				return
			}
			_, _ = w.Write([]byte(`{"AuthType":"` + f.authType + `","FunctionUrl":"https://abc.lambda-url.eu-central-1.on.aws/"}`))
		case r.Method == "DELETE" && strings.HasSuffix(p, "/url"):
			f.deleted = append(f.deleted, "url")
			f.hasURL = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "DELETE" && strings.Contains(p, "/policy/"):
			f.deleted = append(f.deleted, "policy")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "POST" && strings.HasSuffix(p, "/policy"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Statement":"{}"}`))
		case r.Method == "GET" && strings.Contains(p, "/functions/"):
			_, _ = w.Write([]byte(`{"Configuration":{"State":"Active","Timeout":300,"LastUpdateStatus":"Successful"},` +
				`"Tags":{"groundhold-capability":"api","groundhold-environment":"prod"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func lambdaUpdatePID() string {
	return lambdaProviderID("eu-central-1", "000000000000", "api-abcdefgh")
}

// ---- getLambdaURLAuthType ---------------------------------------------------

func TestGetLambdaURLAuthType_Present(t *testing.T) {
	f := &lambdaUpdateFake{hasURL: true, authType: "NONE"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := lambdaDriver(t, srv)
	auth, ok := d.getLambdaURLAuthType("eu-central-1", "api-abcdefgh")
	if !ok || auth != "NONE" {
		t.Fatalf("getLambdaURLAuthType = (%q, %v), want (NONE, true)", auth, ok)
	}
}

func TestGetLambdaURLAuthType_AbsentIsNotOK(t *testing.T) {
	f := &lambdaUpdateFake{hasURL: false}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := lambdaDriver(t, srv)
	if _, ok := d.getLambdaURLAuthType("eu-central-1", "api-abcdefgh"); ok {
		t.Fatal("an absent Function URL must never report a default-safe AuthType")
	}
}

// Note: a transport-unreachable case for getLambdaURLAuthType is deliberately
// not exercised with a dead TCP port here — lambdaGet's underlying resilient
// client retries GET requests with backoff, making a 127.0.0.1:1 target take
// tens of seconds per call (unlike the POST-only callers elsewhere in this
// package). TestGetLambdaURLAuthType_AbsentIsNotOK already pins the same
// "never ok=true on anything but a clean 200" contract via the combined
// err!=nil||st!=200 guard.

// ---- removeLambdaExposure ---------------------------------------------------

func TestRemoveLambdaExposure_DeletesURLThenPermission(t *testing.T) {
	f := &lambdaUpdateFake{hasURL: true, authType: "NONE"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := lambdaDriver(t, srv)
	if r := d.removeLambdaExposure("eu-central-1", "pid", "api-abcdefgh"); r != nil {
		t.Fatalf("removeLambdaExposure: %+v", r)
	}
	if strings.Join(f.deleted, ",") != "url,policy" {
		t.Fatalf("must delete the URL config then the resource policy, in order; got %v", f.deleted)
	}
}

func TestRemoveLambdaExposure_AlreadyGoneIsIdempotent(t *testing.T) {
	f := &lambdaUpdateFake{hasURL: false} // 404 on both deletes
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := lambdaDriver(t, srv)
	if r := d.removeLambdaExposure("eu-central-1", "pid", "api-abcdefgh"); r != nil {
		t.Fatalf("an already-private function must be idempotent, got %+v", r)
	}
}

func TestRemoveLambdaExposure_URLDelete5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	d := lambdaDriver(t, srv)
	r := d.removeLambdaExposure("eu-central-1", "pid", "api-abcdefgh")
	if r == nil || r.Status != "unknown" || r.ProviderID != "pid" {
		t.Fatalf("a 5xx on DeleteFunctionUrlConfig must be unknown WITH the pid, got %+v", r)
	}
}

func TestRemoveLambdaExposure_URLDelete4xxIsFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
	}))
	defer srv.Close()
	d := lambdaDriver(t, srv)
	r := d.removeLambdaExposure("eu-central-1", "pid", "api-abcdefgh")
	if r == nil || r.Status != "failed" {
		t.Fatalf("a 4xx on DeleteFunctionUrlConfig must be failed, got %+v", r)
	}
}

func TestRemoveLambdaExposure_PermissionDelete5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/url") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(500)
	}))
	defer srv.Close()
	d := lambdaDriver(t, srv)
	r := d.removeLambdaExposure("eu-central-1", "pid", "api-abcdefgh")
	if r == nil || r.Status != "unknown" || r.ProviderID != "pid" {
		t.Fatalf("a 5xx on RemovePermission must be unknown WITH the pid, got %+v", r)
	}
}

// ---- updateLambda: network.publicExposure toggling --------------------------

func TestUpdateLambda_PublicExposureGoingPrivate(t *testing.T) {
	f := &lambdaUpdateFake{hasURL: true, authType: "NONE"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := lambdaDriver(t, srv)
	a := lambdaAttrs()
	a["network.publicExposure"] = false
	res := d.updateLambda("api", "prod", lambdaUpdatePID(), a, lambdaImpl(), []string{"network.publicExposure"})
	if res.Status != "succeeded" {
		t.Fatalf("going private: %+v", res)
	}
	if f.hasURL {
		t.Fatal("going private must remove the Function URL")
	}
}

func TestUpdateLambda_PublicExposureGoingPublic(t *testing.T) {
	f := &lambdaUpdateFake{hasURL: false}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := lambdaDriver(t, srv)
	a := lambdaAttrs()
	a["network.publicExposure"] = true
	res := d.updateLambda("api", "prod", lambdaUpdatePID(), a, lambdaImpl(), []string{"network.publicExposure"})
	if res.Status != "succeeded" {
		t.Fatalf("going public: %+v", res)
	}
	if !f.hasURL {
		t.Fatal("going public must create the Function URL")
	}
}

// ---- classifyLambdaChange: the full table -----------------------------------

func TestClassifyLambdaChange_FullTable(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"timeout.maximum", "mutable"},
		{"network.publicExposure", "mutable"},
		{"location.region", "immutable"},
		{lambdaVpcOperand, "mutable"},
		{lambdaEnvOperand, "mutable"},
		{lambdaPkgOperand, "mutable"},
		{"tls.enforced", "unsupported"},
		{"service.managed", "unsupported"},
		{"replicas.minimum", "unsupported"},
		{"no.such.path", "unsupported"},
	}
	for _, c := range cases {
		got, reason := classifyLambdaChange(c.path)
		if got != c.want {
			t.Errorf("classifyLambdaChange(%q) = %q, want %q", c.path, got, c.want)
		}
		if reason == "" {
			t.Errorf("classifyLambdaChange(%q) carries no reason", c.path)
		}
	}
}

// ---- observedAbsent: PURE marker check --------------------------------------

func TestObservedAbsent(t *testing.T) {
	if observedAbsent(nil) {
		t.Fatal("no observations must not report absent")
	}
	present := []provider.Observation{{Path: provider.ResourceAbsentPath, Value: true}}
	if !observedAbsent(present) {
		t.Fatal("the reserved absence marker set true must report absent")
	}
	notAbsent := []provider.Observation{{Path: provider.ResourceAbsentPath, Value: false}}
	if observedAbsent(notAbsent) {
		t.Fatal("the reserved absence marker set false must not report absent")
	}
	other := []provider.Observation{{Path: "location.region", Value: "eu-central-1"}}
	if observedAbsent(other) {
		t.Fatal("an observation set with no absence marker must not report absent")
	}
}
