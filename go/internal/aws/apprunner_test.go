package aws

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func apprunnerAttrs() map[string]any {
	return map[string]any{
		"location.region":        "eu-central-1",
		"network.publicExposure": true,
		"availability.class":     "regional",
		"service.managed":        true,
	}
}

func apprunnerImpl() map[string]any {
	return map[string]any{
		"image": "public.ecr.aws/nginx/nginx:latest",
		"port":  float64(8080),
	}
}

func TestBuildAppRunnerGolden(t *testing.T) {
	plan, err := BuildAppRunnerRequests("000000000000", "prod", "app", apprunnerAttrs(), apprunnerImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !apprunnerNameOK.MatchString(plan.Name) {
		t.Fatalf("name invalid: %q (len %d)", plan.Name, len(plan.Name))
	}
	for _, want := range []string{
		`"ServiceName":`, `"ImageIdentifier":"public.ecr.aws/nginx/nginx:latest"`,
		`"ImageRepositoryType":"ECR_PUBLIC"`, `"Port":"8080"`,
		`"IsPubliclyAccessible":true`, `"groundhold-capability"`,
	} {
		if !strings.Contains(plan.CreateServiceBody, want) {
			t.Errorf("create body missing %q\n%s", want, plan.CreateServiceBody)
		}
	}
	// a public.ecr.aws image needs NO access role and NO autoscaling arn (default MinSize 1).
	if strings.Contains(plan.CreateServiceBody, "AuthenticationConfiguration") {
		t.Errorf("public image must not carry AuthenticationConfiguration\n%s", plan.CreateServiceBody)
	}
	if strings.Contains(plan.CreateServiceBody, "AutoScalingConfigurationArn") {
		t.Errorf("minimum<=1 must ride the default autoscaling (no arn)\n%s", plan.CreateServiceBody)
	}
}

// TestBuildAppRunnerRefusesScaleToZero is the load-bearing refusal: App Runner has
// NO scale-to-zero, so replicas.minimum:0 must be REFUSED (fail-closed) with the
// diagnostic pointing at the serverless twin — never a silent 0->1 clamp.
func TestBuildAppRunnerRefusesScaleToZero(t *testing.T) {
	a := apprunnerAttrs()
	a["replicas.minimum"] = float64(0)
	_, err := BuildAppRunnerRequests("000000000000", "prod", "app", a, apprunnerImpl(), 1)
	if err == nil {
		t.Fatal("replicas.minimum:0 on App Runner must be refused (no scale-to-zero)")
	}
	for _, want := range []string{"no scale-to-zero", "capability.function.serverless"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal must name %q, got: %v", want, err)
		}
	}
}

// TestBuildAppRunnerMinAboveOneNeedsOperand: minimum>1 honors an
// AutoScalingConfiguration MinSize, brought as an operand (the one-binding rule).
func TestBuildAppRunnerMinAboveOneNeedsOperand(t *testing.T) {
	a := apprunnerAttrs()
	a["replicas.minimum"] = float64(3)
	if _, err := BuildAppRunnerRequests("a", "e", "app", a, apprunnerImpl(), 1); err == nil {
		t.Fatal("minimum>1 with no autoScalingConfigurationArn must refuse")
	}
	i := apprunnerImpl()
	i["autoScalingConfigurationArn"] = "arn:aws:apprunner:eu-central-1:000000000000:autoscalingconfiguration/hi/1/abc"
	plan, err := BuildAppRunnerRequests("000000000000", "prod", "app", a, i, 1)
	if err != nil {
		t.Fatalf("minimum>1 with an operand must be honored: %v", err)
	}
	if !strings.Contains(plan.CreateServiceBody, `"AutoScalingConfigurationArn":"arn:aws:apprunner:`) {
		t.Errorf("create body missing the autoscaling arn\n%s", plan.CreateServiceBody)
	}
}

func TestBuildAppRunnerRefusals(t *testing.T) {
	cases := map[string]struct {
		a func(map[string]any)
		i func(map[string]any)
	}{
		"signed provenance": {func(a map[string]any) { a["image.signedProvenance"] = true }, nil},
		"no autoscaling":    {func(a map[string]any) { a["autoscaling.enabled"] = false }, nil},
		"not regional":      {func(a map[string]any) { a["availability.class"] = "zonal" }, nil},
		"tls false":         {func(a map[string]any) { a["tls.enforced"] = false }, nil},
		"managed false":     {func(a map[string]any) { a["service.managed"] = false }, nil},
		"unknown attr":      {func(a map[string]any) { a["engine.protocol"] = "x" }, nil},
		"fractional min":    {func(a map[string]any) { a["replicas.minimum"] = 1.5 }, nil},
		"no image":          {nil, func(i map[string]any) { delete(i, "image") }},
		"private no role":   {nil, func(i map[string]any) { i["image"] = "000000000000.dkr.ecr.eu-central-1.amazonaws.com/app:latest" }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a, i := apprunnerAttrs(), apprunnerImpl()
			if c.a != nil {
				c.a(a)
			}
			if c.i != nil {
				c.i(i)
			}
			if _, err := BuildAppRunnerRequests("a", "e", "app", a, i, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}

func TestBuildAppRunnerPrivateECR(t *testing.T) {
	i := apprunnerImpl()
	i["image"] = "000000000000.dkr.ecr.eu-central-1.amazonaws.com/app:latest"
	i["access_role_arn"] = "arn:aws:iam::000000000000:role/AppRunnerECRAccess"
	plan, err := BuildAppRunnerRequests("000000000000", "prod", "app", apprunnerAttrs(), i, 1)
	if err != nil {
		t.Fatalf("private ECR with an access role must be honored: %v", err)
	}
	for _, want := range []string{`"ImageRepositoryType":"ECR"`,
		`"AccessRoleArn":"arn:aws:iam::000000000000:role/AppRunnerECRAccess"`} {
		if !strings.Contains(plan.CreateServiceBody, want) {
			t.Errorf("create body missing %q\n%s", want, plan.CreateServiceBody)
		}
	}
}

func TestClassifyAppRunnerChange(t *testing.T) {
	if c, _ := classifyAppRunnerChange("replicas.minimum"); c != "mutable" {
		t.Errorf("replicas.minimum must be mutable (UpdateService), got %q", c)
	}
	if c, _ := classifyAppRunnerChange("tls.enforced"); c != "unsupported" {
		t.Errorf("tls.enforced must be unsupported (HTTPS by construction), got %q", c)
	}
	if c, _ := classifyAppRunnerChange("location.region"); c != "immutable" {
		t.Errorf("location.region must be immutable (replacement), got %q", c)
	}
}

func TestSplitAppRunnerProviderID(t *testing.T) {
	if _, _, err := splitAppRunnerProviderID("apprunner:eu-central-1:app-abcd1234"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	for _, bad := range []string{"eu:app", "ecs:eu-central-1:app", "apprunner:bad:app", "apprunner:eu-central-1:a"} {
		if _, _, err := splitAppRunnerProviderID(bad); err == nil {
			t.Errorf("accepted malformed apprunner id %q", bad)
		}
	}
}

// apprunnerServer routes AppRunner.<action> by X-Amz-Target. It also RECORDS every
// target seen, so the LRO anti-regression test can assert the poll NEVER hit an
// operation-by-id call (ListOperations / DescribeOperation) — the D273 discipline.
// createStatus drives the poll: first DescribeService is OPERATION_IN_PROGRESS, then
// RUNNING (or the caller pins a permanently-stuck status).
type apprunnerFake struct {
	arn       string
	name      string // the ServiceName ListServices reports (matches the test providerId)
	stuck     string // if set, DescribeService always returns this Status
	tagCap    string
	seen      []string
	describes int
	deleted   bool
}

func (f *apprunnerFake) handler(t *testing.T) *httptest.Server {
	t.Helper()
	if f.arn == "" {
		f.arn = "arn:aws:apprunner:eu-central-1:000000000000:service/app/0123456789abcdef"
	}
	if f.name == "" {
		f.name = "app-abcd1234"
	}
	if f.tagCap == "" {
		f.tagCap = "app"
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		action := target[strings.LastIndex(target, ".")+1:]
		f.seen = append(f.seen, target)
		switch action {
		case "CreateService":
			_, _ = w.Write([]byte(`{"Service":{"ServiceArn":"` + f.arn + `","ServiceName":"app","Status":"OPERATION_IN_PROGRESS"},"OperationId":"op-1"}`))
		case "ListServices":
			_, _ = w.Write([]byte(`{"ServiceSummaryList":[{"ServiceName":"` + f.name + `","ServiceArn":"` + f.arn + `","Status":"RUNNING"}]}`))
		case "ListTagsForResource":
			_, _ = w.Write([]byte(`{"Tags":[{"Key":"groundhold-capability","Value":"` + f.tagCap + `"},{"Key":"groundhold-environment","Value":"prod"}]}`))
		case "DescribeService":
			if f.deleted {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException","Message":"gone"}`))
				return
			}
			status := "RUNNING"
			if f.stuck != "" {
				status = f.stuck
			} else {
				f.describes++
				if f.describes < 2 {
					status = "OPERATION_IN_PROGRESS"
				}
			}
			_, _ = w.Write([]byte(`{"Service":{"ServiceArn":"` + f.arn + `","ServiceName":"app","Status":"` + status + `",` +
				`"NetworkConfiguration":{"IngressConfiguration":{"IsPubliclyAccessible":true}},` +
				`"AutoScalingConfigurationSummary":{"AutoScalingConfigurationArn":"arn:aws:apprunner:eu-central-1:000000000000:autoscalingconfiguration/def/1/xyz"}}}`))
		case "DescribeAutoScalingConfiguration":
			_, _ = w.Write([]byte(`{"AutoScalingConfiguration":{"MinSize":1,"MaxSize":25}}`))
		case "DeleteService":
			f.deleted = true
			_, _ = w.Write([]byte(`{"Service":{"ServiceArn":"` + f.arn + `","Status":"OPERATION_IN_PROGRESS"},"OperationId":"op-2"}`))
		case "UpdateService":
			_, _ = w.Write([]byte(`{"Service":{"ServiceArn":"` + f.arn + `","Status":"OPERATION_IN_PROGRESS"},"OperationId":"op-3"}`))
		default:
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"__type":"UnknownOperationException"}`))
		}
	}))
}

func apprunnerTestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.AppRunnerBaseURL = srv.URL
	d.Account = "000000000000"
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

// TestCreateAppRunnerPollsToRunning: create -> poll DescribeService -> RUNNING.
// It also asserts the D273 discipline: the poll concluded on the OBSERVABLE service
// Status and NEVER hit an operation-by-id call (ListOperations / DescribeOperation).
func TestCreateAppRunnerPollsToRunning(t *testing.T) {
	f := &apprunnerFake{}
	srv := f.handler(t)
	defer srv.Close()
	d := apprunnerTestDriver(t, srv)
	res := d.createAppRunner("eu-central-1", "000000000000", "prod", "app", apprunnerAttrs(), apprunnerImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "apprunner:eu-central-1:") {
		t.Fatalf("got %+v, want succeeded once RUNNING", res)
	}
	sawDescribe := false
	for _, tgt := range f.seen {
		if strings.Contains(tgt, "ListOperations") || strings.Contains(tgt, "DescribeOperation") {
			t.Fatalf("D273 violation: the poll hit an operation-by-id call %q — it must conclude on DescribeService.Status", tgt)
		}
		if strings.HasSuffix(tgt, "DescribeService") {
			sawDescribe = true
		}
	}
	if !sawDescribe {
		t.Fatal("the create poll must read the observable service state via DescribeService")
	}
}

func TestObserveAppRunner(t *testing.T) {
	f := &apprunnerFake{}
	srv := f.handler(t)
	defer srv.Close()
	d := apprunnerTestDriver(t, srv)
	obs, _, err := d.observeAppRunner("app", "apprunner:eu-central-1:app-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["network.publicExposure"] != true {
		t.Fatalf("IsPubliclyAccessible true -> publicExposure true, got %v", got["network.publicExposure"])
	}
	if got["tls.enforced"] != true {
		t.Fatalf("App Runner is HTTPS-only -> tls.enforced true, got %v", got["tls.enforced"])
	}
	if got["replicas.minimum"] != float64(1) {
		t.Fatalf("AutoScalingConfiguration MinSize 1 -> replicas.minimum 1, got %v", got["replicas.minimum"])
	}
}

func TestDeleteAppRunnerForeignRefused(t *testing.T) {
	f := &apprunnerFake{tagCap: "other"}
	srv := f.handler(t)
	defer srv.Close()
	d := apprunnerTestDriver(t, srv)
	res := d.deleteAppRunner("app", "prod", "apprunner:eu-central-1:app-abcd1234")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign-tagged service must refuse delete, got %+v", res)
	}
}

func TestDeleteAppRunnerOurs(t *testing.T) {
	f := &apprunnerFake{}
	srv := f.handler(t)
	defer srv.Close()
	d := apprunnerTestDriver(t, srv)
	res := d.deleteAppRunner("app", "prod", "apprunner:eu-central-1:app-abcd1234")
	if res.Status != "succeeded" {
		t.Fatalf("delete of an owned service must succeed once gone, got %+v", res)
	}
}

// TestBoundedPollAppRunner enrolls App Runner in the D266 bounded-poll gate: a
// service stuck in OPERATION_IN_PROGRESS must conclude unknown-with-pid within the
// poll budget, never hang, never a false success.
func TestBoundedPollAppRunner(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.LifecycleProbe{
		Name: "aws/apprunner",
		StuckServer: func() *httptest.Server {
			f := &apprunnerFake{stuck: "OPERATION_IN_PROGRESS"}
			return f.handler(t)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000"
			d.AppRunnerBaseURL = happyURL
			d.PollInterval = 0
			d.PollTimeout = time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("apprunner", "capability.workload.container", "prod",
				apprunnerAttrs(), apprunnerImpl(), "k", 1)
		},
		PID: apprunnerProviderID("eu-central-1", AppRunnerName("000000000000", "prod", "capability.workload.container", 1)),
	}
	certifynet.CertifyBoundedPoll(t, p)
}

// TestAppRunnerCreateBodyValidJSON guards that the assembled body is well-formed.
func TestAppRunnerCreateBodyValidJSON(t *testing.T) {
	plan, err := BuildAppRunnerRequests("000000000000", "prod", "app", apprunnerAttrs(), apprunnerImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(plan.CreateServiceBody), &m); err != nil {
		t.Fatalf("create body is not valid JSON: %v", err)
	}
}

// apprunnerConflictFake: CreateService is refused (a ServiceName is unique per
// account+region, so a 4xx MAY mean "already exists"), and the standing service is ours.
type apprunnerConflictFake struct{ inner *apprunnerFake }

func (f *apprunnerConflictFake) handler(t *testing.T) *httptest.Server {
	t.Helper()
	inner := f.inner.handler(t)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		if strings.HasSuffix(target, "CreateService") {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"__type":"InvalidRequestException","Message":"service already exists"}`))
			return
		}
		inner.Config.Handler.ServeHTTP(w, r)
	}))
}

func apprunnerRole(req *http.Request, _ []byte) certifynet.Role {
	tgt := req.Header.Get("X-Amz-Target")
	switch tgt[strings.LastIndex(tgt, ".")+1:] {
	case "ListServices", "ListTagsForResource", "DescribeService",
		"DescribeAutoScalingConfiguration":
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingAppRunner enrols apprunner in the D391 gate. Its adoption is the
// most inferential of the family: a 4xx on CreateService MAY mean "already exists", so
// the driver resolves by name and only then decides — which is why the ours case
// deserves an assertion rather than a comment.
func TestAdoptsExistingAppRunner(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	name := AppRunnerName("000000000000", "prod", "capability.workload.container", 1)
	p := &certifynet.ExistingProbe{
		Name:     "aws/apprunner",
		Classify: apprunnerRole,
		ExistingServer: func() *httptest.Server {
			return (&apprunnerConflictFake{inner: &apprunnerFake{
				name: name, tagCap: sanitizeTag("capability.workload.container")}}).handler(t)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.AppRunnerBaseURL = happyURL
			d.PollInterval = 0
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("apprunner", "capability.workload.container", "prod",
				apprunnerAttrs(), apprunnerImpl(), "k", 1)
		},
		AllowedMutations: 1, // the refused CreateService — the detection itself
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
