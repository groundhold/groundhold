package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func lambdaAttrs() map[string]any {
	return map[string]any{
		"location.region":        "eu-central-1",
		"network.publicExposure": true,
		"tls.enforced":           true,
		"timeout.maximum":        "5m",
		"replicas.minimum":       float64(0),
		"service.managed":        true,
	}
}

func lambdaImpl() map[string]any {
	return map[string]any{
		"image_uri": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/fn:sha",
		"role_arn":  "arn:aws:iam::123456789012:role/fn-exec",
	}
}

func TestBuildLambdaHonorsAndRefuses(t *testing.T) {
	p, err := BuildLambda("000000000000", "prod", "api", lambdaAttrs(), lambdaImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Region != "eu-central-1" || !p.Public || p.TimeoutSec != 300 {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("api", "prod")
	if body["PackageType"] != "Image" || body["Timeout"].(int) != 300 {
		t.Fatalf("create body = %+v", body)
	}

	refusals := map[string]map[string]any{
		"tls-off":         {"tls.enforced": false},
		"timeout-too-big": {"timeout.maximum": "20m"}, // 1200s > Lambda's 900s ceiling
		"warm-floor":      {"replicas.minimum": float64(2)},
		"unmanaged":       {"service.managed": false},
		"unknown-attr":    {"memory.size": 512},
	}
	for name, extra := range refusals {
		a := lambdaAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildLambda("000000000000", "prod", "api", a, lambdaImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// implementation gaps refuse
	if _, err := BuildLambda("000000000000", "prod", "api", lambdaAttrs(), map[string]any{"role_arn": "arn:x"}, 1); err == nil {
		t.Error("missing image_uri must refuse")
	}
	if _, err := BuildLambda("000000000000", "prod", "api", lambdaAttrs(), map[string]any{"image_uri": "x"}, 1); err == nil {
		t.Error("missing role_arn must refuse")
	}
}

// lambdaFake is a stateful Lambda fake: GetFunction is 404 before CreateFunction
// and 200 after (State = readyState). The anti-regression guard fails the test if
// the driver EVER polls an operation-by-id path — Lambda's create LRO must poll the
// OBSERVABLE GetFunction state, never a synthetic operations endpoint (D273).
type lambdaFake struct {
	t          *testing.T
	created    bool
	readyState string // "Active" (happy) or "Pending" (stuck)
	capValue   string // ownership tag value; "" => our default "api"
}

func (f *lambdaFake) handler() http.HandlerFunc {
	capVal := f.capValue
	if capVal == "" {
		capVal = "api"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.Contains(p, "operation") {
			f.t.Errorf("Lambda create/poll must NEVER hit an operation-by-id path, got %s %s", r.Method, p)
		}
		switch {
		case r.Method == "POST" && strings.HasSuffix(p, "/url"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"FunctionUrl":"https://abc.lambda-url.eu-central-1.on.aws/","AuthType":"NONE"}`))
		case r.Method == "POST" && strings.HasSuffix(p, "/policy"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Statement":"{}"}`))
		case r.Method == "POST" && strings.HasSuffix(p, "/functions"):
			f.created = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"FunctionName":"fn","State":"Pending"}`))
		case r.Method == "GET" && strings.HasSuffix(p, "/policy"):
			// D534: the fake accepted the POST that CREATES the anonymous invoke
			// grant and modelled no GET, because the driver never read it back. It
			// does now, so the fake must answer with what the create put there —
			// otherwise the fixture reports a private function the create just made
			// public (the D520 class: a fixture that mirrors the driver's blind spot).
			_, _ = w.Write([]byte(`{"Policy":"{\"Version\":\"2012-10-17\",\"Statement\":` +
				`[{\"Effect\":\"Allow\",\"Principal\":\"*\",` +
				`\"Action\":\"lambda:InvokeFunctionUrl\"}]}"}`))
		case r.Method == "GET" && strings.HasSuffix(p, "/url"):
			_, _ = w.Write([]byte(`{"AuthType":"NONE","FunctionUrl":"https://abc.lambda-url.eu-central-1.on.aws/"}`))
		case r.Method == "GET" && strings.Contains(p, "/functions/"):
			if !f.created {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"Function not found"}`))
				return
			}
			_, _ = w.Write([]byte(`{"Configuration":{"State":"` + f.readyState + `","Timeout":300},` +
				`"Tags":{"groundhold-capability":"` + capVal + `","groundhold-environment":"prod"}}`))
		case r.Method == "DELETE":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func lambdaDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver("eu-central-1")
	d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	d.Account = "000000000000"
	d.LambdaBaseURL = srv.URL
	// D1031: observeLambda now reads the default log group (/aws/lambda/<fn>) via
	// DescribeLogGroups. Point logs at the same fake so no observe test reaches the
	// real endpoint; the lambda fakes 404 that route (→ a diagnostic, no observation),
	// which the existing tests ignore. A test that cares serves its own logs response.
	d.LogsBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

// TestBuildLambdaArchitecture (D1001): the architectures operand sets Architectures on
// the create body (so an arm64 image gets an arm64 function), is emitted as a drift
// target ONLY when declared, and refuses an unknown value rather than silently
// defaulting to a wrong architecture — the field case where an arm64 image on a silent
// x86_64 function created "Active" yet died on first invoke.
func TestBuildLambdaArchitecture(t *testing.T) {
	// absent: no Architectures in the body (AWS default x86_64), no drift target.
	p, err := BuildLambda("000000000000", "prod", "api", lambdaAttrs(), lambdaImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.ArchitectureSet {
		t.Fatal("absent operand must not set the architecture")
	}
	if _, has := p.createBody("api", "prod")["Architectures"]; has {
		t.Fatal("absent operand must not send Architectures (AWS default stands)")
	}

	// arm64 declared: create body carries ["arm64"].
	impl := lambdaImpl()
	impl["architectures"] = "arm64"
	p, err = BuildLambda("000000000000", "prod", "api", lambdaAttrs(), impl, 1)
	if err != nil || p.Architecture != "arm64" || !p.ArchitectureSet {
		t.Fatalf("arm64 plan = %+v err=%v", p, err)
	}
	got := p.createBody("api", "prod")["Architectures"]
	arr, ok := got.([]any)
	if !ok || len(arr) != 1 || arr[0] != "arm64" {
		t.Fatalf("create body Architectures = %v, want [arm64]", got)
	}

	// single-element list accepted; amd64 alias normalises to x86_64.
	impl["architectures"] = []any{"amd64"}
	if p, err = BuildLambda("000000000000", "prod", "api", lambdaAttrs(), impl, 1); err != nil || p.Architecture != "x86_64" {
		t.Fatalf("amd64 list should normalise to x86_64: %+v err=%v", p, err)
	}

	// unknown / multi refuse.
	for name, v := range map[string]any{
		"unknown": "risc-v",
		"two":     []any{"arm64", "x86_64"},
	} {
		impl["architectures"] = v
		if _, err := BuildLambda("000000000000", "prod", "api", lambdaAttrs(), impl, 1); err == nil {
			t.Errorf("%s architecture must refuse", name)
		}
	}
}

func TestLambdaCreateObserveDelete(t *testing.T) {
	f := &lambdaFake{t: t, readyState: "Active"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := lambdaDriver(t, srv)

	res := d.createLambda("eu-central-1", "000000000000", "prod", "api", lambdaAttrs(), lambdaImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "lambda:eu-central-1:000000000000:") {
		t.Fatalf("create: %+v", res)
	}

	obs, _, err := d.observeLambda("api", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["network.publicExposure"] != true {
		t.Fatalf("AuthType NONE must observe public, got %v", got["network.publicExposure"])
	}
	if got["timeout.maximum"] != "300s" {
		t.Fatalf("Timeout 300 must observe 300s, got %v", got["timeout.maximum"])
	}

	del := d.deleteLambda("api", "prod", res.ProviderID)
	if del.Status != "succeeded" {
		t.Fatalf("delete of an owned function must succeed, got %+v", del)
	}
}

func TestLambdaCreateForeignRefused(t *testing.T) {
	f := &lambdaFake{t: t, readyState: "Active", capValue: "someone-else", created: true}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := lambdaDriver(t, srv)
	res := d.createLambda("eu-central-1", "000000000000", "prod", "api", lambdaAttrs(), lambdaImpl(), 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign-tagged function must refuse create, got %+v", res)
	}
}

func TestLambdaDeleteForeignRefused(t *testing.T) {
	f := &lambdaFake{t: t, readyState: "Active", capValue: "someone-else", created: true}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := lambdaDriver(t, srv)
	res := d.deleteLambda("api", "prod", "lambda:eu-central-1:000000000000:api-abcdefgh")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign-tagged function must refuse delete, got %+v", res)
	}
}

func TestSplitLambdaProviderID(t *testing.T) {
	if _, _, _, err := splitLambdaProviderID("lambda:eu-central-1:000000000000:api-abcdefgh"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	for _, bad := range []string{"r:n", "apigw:eu-central-1:000000000000:x", "lambda:eu-central-1:000000000000:api:x", "lambda:BADREGION:000000000000:api"} {
		if _, _, _, err := splitLambdaProviderID(bad); err == nil {
			t.Errorf("accepted malformed lambda id %q", bad)
		}
	}
}

func lambdaRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

func newLambdaHonestyDriver(happyURL string, rt http.RoundTripper) *Driver {
	d := NewDriver("eu-central-1")
	d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	d.Account = "000000000000"
	d.LambdaBaseURL = happyURL
	d.HTTP = &http.Client{Transport: rt}
	d.PollInterval = 0
	d.PollTimeout = time.Second
	return d
}

// TestReadStormLambda: a create whose leading ownership/poll reads throttle must
// still succeed — lambdaGet retries the transient class (D260/D266).
func TestReadStormLambda(t *testing.T) {
	attrs := map[string]any{
		"location.region": "eu-central-1", "network.publicExposure": false,
		"tls.enforced": true, "service.managed": true,
	}
	p := &certifynet.Probe{
		AssertTransient: true, // D237 sweep
		Name:            "aws/lambda",
		Classify:        lambdaRole,
		OwnerTagValue:   "api",
		DeterministicID: true,
		// F-LC3 (D523): hand-wired.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("lambda", "api", lambdaProviderID("eu-central-1", "000000000000", "api-abcdefgh"))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newLambdaHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{{
			Name: "create",
			Happy: func() *httptest.Server {
				return httptest.NewServer((&lambdaFake{t: t, readyState: "Active"}).handler())
			},
			Run: func(pr provider.Provider) provider.CreateResult {
				return pr.Create("lambda", "api", "prod", attrs, lambdaImpl(), "k", 1)
			},
		}},
	}
	certifynet.CertifyReadRetry(t, p)
}

// TestBoundedPollLambda: a function that never leaves Pending must conclude
// unknown-with-pid within the poll budget, never hang or fabricate success.
func TestBoundedPollLambda(t *testing.T) {
	attrs := map[string]any{
		"location.region": "eu-central-1", "network.publicExposure": false,
		"tls.enforced": true, "service.managed": true,
	}
	name := ECSName("000000000000", "prod", "api", 1)
	p := &certifynet.LifecycleProbe{
		Name: "aws/lambda",
		StuckServer: func() *httptest.Server {
			return httptest.NewServer((&lambdaFake{t: t, readyState: "Pending"}).handler())
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newLambdaHonestyDriver(happyURL, rt)
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("lambda", "api", "prod", attrs, lambdaImpl(), "k", 1)
		},
		PID: lambdaProviderID("eu-central-1", "000000000000", name),
	}
	certifynet.CertifyBoundedPoll(t, p)
}

func lambdaRESTRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingLambda enrols lambda in the D391 gate. Lambda uses the strongest
// form of the property: an ownership PRE-READ before any mutation, so a function of ours
// already standing is bound with no CreateFunction issued at all — the same shape as
// KMS and VPC, and the one where zero mutations is the whole proof.
func TestAdoptsExistingLambda(t *testing.T) {
	name := ECSName("000000000000", "prod", "api", 1) // lambda shares the deterministic namer
	p := &certifynet.ExistingProbe{
		Name:     "aws/lambda",
		Classify: lambdaRESTRole,
		ExistingServer: func() *httptest.Server {
			f := &lambdaFake{t: t, readyState: "Active", created: true}
			return httptest.NewServer(f.handler())
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.LambdaBaseURL = happyURL
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("lambda", "api", "prod", lambdaAttrs(), lambdaImpl(), "api", 1)
		},
		PID:              lambdaProviderID("eu-central-1", "000000000000", name),
		AllowedMutations: 2, // exposure repair on the adopted function, never a create
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
