package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func fnAttrs() map[string]any {
	return map[string]any{
		"location.region":        "europe-west1",
		"network.publicExposure": true,
		"tls.enforced":           true,
		"timeout.maximum":        "5m",
		"replicas.minimum":       float64(0),
		"service.managed":        true,
	}
}

func fnImpl() map[string]any {
	return map[string]any{
		"runtime":     "nodejs20",
		"entry_point": "handler",
		"source":      map[string]any{"bucket": "my-src", "object": "fn.zip"},
	}
}

// fnServer routes Cloud Functions v2 calls AND the backing Cloud Run IAM calls.
// The create LRO is polled by the RESPONSE-DERIVED operation name (op-create) on
// the canonical operations endpoint — the anti-regression guard fails if the
// driver ever polls any OTHER operation path (a constructed one).
func fnServer(t *testing.T, opDone bool, ingress string) *httptest.Server {
	t.Helper()
	granted := false
	fnDoc := func() string {
		return `{"labels":{"groundhold-capability":"api","groundhold-environment":"prod"},` +
			`"serviceConfig":{"ingressSettings":"` + ingress + `","minInstanceCount":0,"timeoutSeconds":300,` +
			`"service":"projects/acme-prod/locations/europe-west1/services/api-run"}}`
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case strings.HasSuffix(p, ":getIamPolicy"):
				if granted {
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[{"role":"roles/run.invoker","members":["allUsers"]}]}`))
				} else {
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[]}`))
				}
			case strings.HasSuffix(p, ":setIamPolicy"):
				granted = true
				_, _ = w.Write([]byte(`{"etag":"e2"}`))
			case strings.Contains(p, "/operations/"):
				if !strings.HasSuffix(p, "/operations/op-create") && !strings.HasSuffix(p, "/operations/op-del") {
					t.Errorf("LRO must poll the RESPONSE-DERIVED operation name, got %s", p)
				}
				if opDone {
					_, _ = w.Write([]byte(`{"name":"op","done":true}`))
				} else {
					_, _ = w.Write([]byte(`{"name":"op","done":false}`))
				}
			case r.Method == "POST" && strings.Contains(p, "/functions"):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op-create"}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op-del"}`))
			case r.Method == "GET" && strings.Contains(p, "/functions/"):
				_, _ = w.Write([]byte(fnDoc()))
			case r.Method == "GET" && strings.Contains(p, "/services/"):
				_, _ = w.Write([]byte(`{"invokerIamDisabled":false}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
}

func fnDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.CfBaseURL = srv.URL
	d.RunBaseURL = srv.URL
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestBuildCloudFunctionFnHonorsAndRefuses(t *testing.T) {
	req, err := BuildCloudFunctionFnRequest("acme-prod", "prod", "api", fnAttrs(), fnImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	sc := req.Body["serviceConfig"].(map[string]any)
	if sc["ingressSettings"] != "ALLOW_ALL" || sc["timeoutSeconds"] != 300 || sc["minInstanceCount"] != 0 {
		t.Fatalf("serviceConfig = %+v", sc)
	}

	refusals := map[string]map[string]any{
		"tls-off":         {"tls.enforced": false},
		"timeout-too-big": {"timeout.maximum": "90m"}, // 5400s > gen2's 3600s ceiling
		"unmanaged":       {"service.managed": false},
		"unknown-attr":    {"memory.size": 512},
	}
	for name, extra := range refusals {
		a := fnAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildCloudFunctionFnRequest("acme-prod", "prod", "api", a, fnImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// a warm floor > 0 IS honored on GCP (unlike Lambda).
	a := fnAttrs()
	a["replicas.minimum"] = float64(3)
	if _, err := BuildCloudFunctionFnRequest("acme-prod", "prod", "api", a, fnImpl(), 1); err != nil {
		t.Errorf("replicas.minimum>0 must be honored on GCP: %v", err)
	}
	if _, err := BuildCloudFunctionFnRequest("acme-prod", "prod", "api", fnAttrs(), map[string]any{"entry_point": "h"}, 1); err == nil {
		t.Error("missing runtime/source must refuse")
	}
}

// TestBuildCloudFunctionFnVpcAndEnv pins the D308 GCP parity: the vpc_connector
// operand maps to serviceConfig.vpcConnector (literal, a distinct GCP resource),
// vpc_connector_egress_settings to vpcConnectorEgressSettings, and the environment
// map to serviceConfig.environmentVariables. An unresolved $ref in an env value
// (validate/preflight only) is tolerated, not misread as a literal.
func TestBuildCloudFunctionFnVpcAndEnv(t *testing.T) {
	impl := fnImpl()
	impl["vpc_connector"] = "projects/acme-prod/locations/europe-west1/connectors/serverless-conn"
	impl["vpc_connector_egress_settings"] = "PRIVATE_RANGES_ONLY"
	impl["environment"] = map[string]any{
		"LOG_LEVEL":     "info",
		"DATABASE_HOST": map[string]any{"$ref": map[string]any{"capability": "db", "output": "privateIpAddress"}},
	}
	req, err := BuildCloudFunctionFnRequest("acme-prod", "prod", "api", fnAttrs(), impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	sc := req.Body["serviceConfig"].(map[string]any)
	if sc["vpcConnector"] != "projects/acme-prod/locations/europe-west1/connectors/serverless-conn" {
		t.Fatalf("vpcConnector = %v", sc["vpcConnector"])
	}
	if sc["vpcConnectorEgressSettings"] != "PRIVATE_RANGES_ONLY" {
		t.Fatalf("vpcConnectorEgressSettings = %v", sc["vpcConnectorEgressSettings"])
	}
	env, ok := sc["environmentVariables"].(map[string]any)
	if !ok || env["LOG_LEVEL"] != "info" {
		t.Fatalf("environmentVariables = %v", sc["environmentVariables"])
	}
	// the unresolved $ref value is tolerated (dropped here, resolved at apply),
	// never written as a literal map.
	if _, has := env["DATABASE_HOST"]; has {
		t.Fatalf("an unresolved $ref must not be written as a literal env value, got %v", env["DATABASE_HOST"])
	}

	refusals := map[string]map[string]any{
		"bad-connector":     {"vpc_connector": "not-a-connector"},
		"egress-no-conn":    {"vpc_connector_egress_settings": "ALL_TRAFFIC"},
		"bad-egress":        {"vpc_connector": "projects/p/locations/europe-west1/connectors/c", "vpc_connector_egress_settings": "SOMETHING"},
		"env-not-a-map":     {"environment": "nope"},
		"env-secret-number": {"environment": map[string]any{"DB_PASS": 42}},
	}
	for name, extra := range refusals {
		im := fnImpl()
		for k, v := range extra {
			im[k] = v
		}
		if _, err := BuildCloudFunctionFnRequest("acme-prod", "prod", "api", fnAttrs(), im, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

func TestCreateCloudFunctionFnPublic(t *testing.T) {
	srv := fnServer(t, true, "ALLOW_ALL")
	defer srv.Close()
	d := fnDriver(t, srv)
	res := d.createCloudFunctionFn("api", "prod", fnAttrs(), fnImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "cffn:acme-prod:") {
		t.Fatalf("create: %+v", res)
	}
}

func TestObserveCloudFunctionFn(t *testing.T) {
	srv := fnServer(t, true, "ALLOW_ALL")
	defer srv.Close()
	d := fnDriver(t, srv)
	if r := d.createCloudFunctionFn("api", "prod", fnAttrs(), fnImpl(), 1); r.Status != "succeeded" {
		t.Fatalf("setup create failed: %+v", r)
	}
	obs, _, err := d.observeCloudFunctionFn("api", "cffn:acme-prod:europe-west1:api-abcdefgh")
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
	if got["timeout.maximum"] != "300s" {
		t.Fatalf("timeoutSeconds 300 -> 300s, got %v", got["timeout.maximum"])
	}
	if got["replicas.minimum"] != float64(0) {
		t.Fatalf("minInstanceCount 0 -> replicas.minimum 0, got %v", got["replicas.minimum"])
	}
}

func TestDeleteCloudFunctionFnForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"other","groundhold-environment":"prod"}}`))
		}))
	defer srv.Close()
	d := fnDriver(t, srv)
	res := d.deleteCloudFunctionFn("api", "prod", "cffn:acme-prod:europe-west1:api-abcdefgh")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign-labeled function must refuse delete, got %+v", res)
	}
}

func TestSplitFnServerlessProviderID(t *testing.T) {
	if _, _, _, err := splitFnServerlessProviderID("cffn:p:europe-west1:api-fn"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	for _, bad := range []string{"p:r:n", "cloudfunctions:p:r:n", "cffn:p:r:n:x", "cffn:p:UP:n"} {
		if _, _, _, err := splitFnServerlessProviderID(bad); err == nil {
			t.Errorf("accepted malformed cffn id %q", bad)
		}
	}
}

func fnServerlessRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	if strings.HasSuffix(req.URL.Path, ":setIamPolicy") {
		return certifynet.RoleMutateOpaque
	}
	return certifynet.RoleMutateParsed
}

// TestReadStormCloudFunctionFn: a private create whose leading op-poll reads
// throttle must still succeed — the operation poll loop rides the transient class
// out (D260/D266).
func TestReadStormCloudFunctionFn(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "tok")
	attrs := map[string]any{
		"location.region": "europe-west1", "network.publicExposure": false,
		"tls.enforced": true, "service.managed": true,
	}
	p := &certifynet.Probe{
		AssertTransient: true, // D237 sweep
		Name:            "gcp/cloudfunctions-fn",
		Classify:        fnServerlessRole,
		OwnerTagValue:   "api",
		DeterministicID: true,
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := newGcpHonestyDriver(happyURL, rt)
			d.PollInterval = 0
			d.PollTimeout = time.Second
			return d
		},
		Ops: []certifynet.Op{{
			Name:  "create",
			Happy: func() *httptest.Server { return fnServer(t, true, "ALLOW_INTERNAL_ONLY") },
			Run: func(pr provider.Provider) provider.CreateResult {
				return pr.Create("cloudfunctions-fn", "api", "prod", attrs, fnImpl(), "k", 1)
			},
		}},
	}
	certifynet.CertifyReadRetry(t, p)
}

// TestBoundedPollCloudFunctionFn: an operation that never reports done must
// conclude unknown-with-pid within the poll budget, never hang or fabricate success.
func TestBoundedPollCloudFunctionFn(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "tok")
	attrs := map[string]any{
		"location.region": "europe-west1", "network.publicExposure": false,
		"tls.enforced": true, "service.managed": true,
	}
	name := FunctionName("acme-prod", "prod", "api", 1)
	p := &certifynet.LifecycleProbe{
		Name:        "gcp/cloudfunctions-fn",
		StuckServer: func() *httptest.Server { return fnServer(t, false, "ALLOW_INTERNAL_ONLY") },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := newGcpHonestyDriver(happyURL, rt)
			d.PollInterval = 0
			d.PollTimeout = time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("cloudfunctions-fn", "api", "prod", attrs, fnImpl(), "k", 1)
		},
		PID: fnServerlessProviderID("acme-prod", "europe-west1", name),
	}
	certifynet.CertifyBoundedPoll(t, p)
}

// TestFnServerlessOutputURL: the D330 output derivation publishes the public
// HTTPS trigger (url) ONLY for a PUBLIC function (ingress ALLOW_ALL) — a private
// function omits url (no-public-output), the mirror of AWS lambda's functionUrl.
func TestFnServerlessOutputURL(t *testing.T) {
	const pid = "cffn:acme-prod:europe-west1:api-abcdefgh"
	server := func(ingress, url string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && strings.Contains(r.URL.Path, "/functions/") {
				_, _ = w.Write([]byte(`{"url":"` + url + `","serviceConfig":{"ingressSettings":"` + ingress + `"}}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
	}
	t.Run("public function publishes url", func(t *testing.T) {
		srv := server("ALLOW_ALL", "https://api-abc-ew.a.run.app")
		defer srv.Close()
		d := fnDriver(t, srv)
		outs, err := d.ReadOutputs("cloudfunctionsfn", pid)
		if err != nil {
			t.Fatalf("ReadOutputs: %v", err)
		}
		if outs["url"] != "https://api-abc-ew.a.run.app" {
			t.Fatalf("url = %v, want the public trigger", outs["url"])
		}
	})
	t.Run("private function publishes no url", func(t *testing.T) {
		srv := server("ALLOW_INTERNAL_ONLY", "https://api-abc-ew.a.run.app")
		defer srv.Close()
		d := fnDriver(t, srv)
		outs, err := d.ReadOutputs("cloudfunctionsfn", pid)
		if err != nil {
			t.Fatalf("ReadOutputs: %v", err)
		}
		if _, has := outs["url"]; has {
			t.Fatalf("a private function must publish no url, got %+v", outs)
		}
	})
}
