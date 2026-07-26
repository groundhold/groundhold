package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func ecsAttrs() map[string]any {
	return map[string]any{
		"location.region":        "eu-central-1",
		"network.publicExposure": true,
		"availability.class":     "regional",
		"service.managed":        true,
	}
}

func ecsImpl() map[string]any {
	return map[string]any{
		"image":              "public.ecr.aws/nginx/nginx:latest",
		"subnets":            []any{"subnet-1", "subnet-2"},
		"security_groups":    []any{"sg-1"},
		"execution_role_arn": "arn:aws:iam::000000000000:role/ecsTaskExecutionRole",
	}
}

func TestBuildECSGolden(t *testing.T) {
	plan, err := BuildECSRequests("000000000000", "prod", "app", ecsAttrs(), ecsImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !ecsNameOK.MatchString(plan.Name) {
		t.Fatalf("name invalid: %q", plan.Name)
	}
	for _, want := range []string{`"family":`, `"FARGATE"`, `"networkMode":"awsvpc"`,
		`"image":"public.ecr.aws/nginx/nginx:latest"`, `"executionRoleArn":`, "groundhold-capability"} {
		if !strings.Contains(plan.RegisterTaskBody, want) {
			t.Errorf("task def missing %q", want)
		}
	}
	svc := plan.CreateServiceFn("arn:task:1")
	for _, want := range []string{`"launchType":"FARGATE"`, `"assignPublicIp":"ENABLED"`,
		`"subnets":["subnet-1","subnet-2"]`, `"desiredCount":1`} {
		if !strings.Contains(svc, want) {
			t.Errorf("service missing %q\n%s", want, svc)
		}
	}
}

func TestBuildECSRefusals(t *testing.T) {
	cases := map[string]struct {
		a func(map[string]any)
		i func(map[string]any)
	}{
		"signed provenance": {func(a map[string]any) { a["image.signedProvenance"] = true }, nil},
		"tls no target grp": {func(a map[string]any) { a["tls.enforced"] = true }, nil},
		"tls no port": {func(a map[string]any) { a["tls.enforced"] = true },
			func(i map[string]any) {
				i["targetGroupArn"] = "arn:aws:elasticloadbalancing:eu-central-1:000000000000:targetgroup/tg/abc"
			}},
		"no autoscaling": {func(a map[string]any) { a["autoscaling.enabled"] = false }, nil},
		"not regional":   {func(a map[string]any) { a["availability.class"] = "zonal" }, nil},
		"unknown attr":   {func(a map[string]any) { a["engine.protocol"] = "x" }, nil},
		"no image":       {nil, func(i map[string]any) { delete(i, "image") }},
		"no subnets":     {nil, func(i map[string]any) { delete(i, "subnets") }},
		"no exec role":   {nil, func(i map[string]any) { delete(i, "execution_role_arn") }},
		"fractional min": {func(a map[string]any) { a["replicas.minimum"] = 1.5 }, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a, i := ecsAttrs(), ecsImpl()
			if c.a != nil {
				c.a(a)
			}
			if c.i != nil {
				c.i(i)
			}
			if _, err := BuildECSRequests("a", "e", "app", a, i, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}

// TestBuildECSTLSTargetGroup: tls.enforced=true is honored when the operator
// brings a pre-created TLS target group — the service registers behind it
// (loadBalancers) and the container gets a portMapping, the same operand shape as
// subnets/security_groups/execution_role_arn.
func TestBuildECSTLSTargetGroup(t *testing.T) {
	a := ecsAttrs()
	a["tls.enforced"] = true
	i := ecsImpl()
	i["targetGroupArn"] = "arn:aws:elasticloadbalancing:eu-central-1:000000000000:targetgroup/tg/abc"
	i["containerPort"] = float64(8080)
	plan, err := BuildECSRequests("000000000000", "prod", "app", a, i, 1)
	if err != nil {
		t.Fatalf("tls.enforced with a target group must be honored: %v", err)
	}
	if !strings.Contains(plan.RegisterTaskBody, `"portMappings":[{"containerPort":8080}]`) {
		t.Fatalf("task def missing portMappings\n%s", plan.RegisterTaskBody)
	}
	svc := plan.CreateServiceFn("arn:task:1")
	for _, want := range []string{`"loadBalancers":`, `"targetGroupArn":"arn:aws:elasticloadbalancing`,
		`"containerName":"app"`, `"containerPort":8080`} {
		if !strings.Contains(svc, want) {
			t.Errorf("service missing %q\n%s", want, svc)
		}
	}
}

// TestObserveECSTLSEnforced: observe traces the service's target group to its
// load balancer's listener protocol — an HTTPS listener => tls.enforced true, a
// plaintext HTTP listener => false (measured, never trusting the operand name).
func TestObserveECSTLSEnforced(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol string
		want     bool
	}{
		{"https listener", "HTTPS", true},
		{"http listener", "HTTP", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					if tgt := r.Header.Get("X-Amz-Target"); tgt != "" { // ECS JSON
						if strings.HasSuffix(tgt, "DescribeServices") {
							_, _ = w.Write([]byte(`{"services":[{"status":"ACTIVE","desiredCount":1,` +
								`"networkConfiguration":{"awsvpcConfiguration":{"assignPublicIp":"DISABLED"}},` +
								`"loadBalancers":[{"targetGroupArn":"arn:aws:elasticloadbalancing:eu-central-1:000000000000:targetgroup/tg/abc"}],` +
								`"tags":[{"key":"groundhold-capability","value":"app"}]}]}`))
							return
						}
						w.WriteHeader(400)
						return
					}
					body := make([]byte, r.ContentLength) // ELBv2 Query
					r.Body.Read(body)
					action := ""
					for _, kv := range strings.Split(string(body), "&") {
						if strings.HasPrefix(kv, "Action=") {
							action = strings.TrimPrefix(kv, "Action=")
						}
					}
					switch action {
					case "DescribeTargetGroups":
						_, _ = w.Write([]byte(`<DescribeTargetGroupsResponse><DescribeTargetGroupsResult><TargetGroups><member>` +
							`<LoadBalancerArns><member>arn:aws:elasticloadbalancing:eu-central-1:000000000000:loadbalancer/app/lb/1</member></LoadBalancerArns>` +
							`</member></TargetGroups></DescribeTargetGroupsResult></DescribeTargetGroupsResponse>`))
					case "DescribeListeners":
						_, _ = w.Write([]byte(`<DescribeListenersResponse><DescribeListenersResult><Listeners><member>` +
							`<Protocol>` + tc.protocol + `</Protocol>` +
							`</member></Listeners></DescribeListenersResult></DescribeListenersResponse>`))
					default:
						w.WriteHeader(400)
					}
				}))
			defer srv.Close()
			d := ecsTestDriver(t, srv)
			d.ELBv2BaseURL = srv.URL
			obs, _, err := d.observeECS("app", "ecs:eu-central-1:app-abcd1234")
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["tls.enforced"] != tc.want {
				t.Fatalf("tls.enforced = %v, want %v", got["tls.enforced"], tc.want)
			}
		})
	}
}

// ecsServer routes JSON actions by the X-Amz-Target header. describeState
// controls the service rollout: the first describe returns IN_PROGRESS, then
// COMPLETED with runningCount==desiredCount.
func ecsServer(t *testing.T, tagCap string) *httptest.Server {
	t.Helper()
	describes := 0
	deleted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			target := r.Header.Get("X-Amz-Target")
			action := target[strings.LastIndex(target, ".")+1:]
			switch action {
			case "CreateCluster":
				_, _ = w.Write([]byte(`{"cluster":{"status":"ACTIVE"}}`))
			case "RegisterTaskDefinition":
				_, _ = w.Write([]byte(`{"taskDefinition":{"taskDefinitionArn":"arn:aws:ecs:eu-central-1:000000000000:task-definition/app:1"}}`))
			case "CreateService":
				_, _ = w.Write([]byte(`{"service":{"status":"ACTIVE"}}`))
			case "DescribeServices":
				if deleted {
					// drained after DeleteService — INACTIVE (gone)
					_, _ = w.Write([]byte(`{"services":[{"status":"INACTIVE"}]}`))
					return
				}
				describes++
				running, roll := 0, "IN_PROGRESS"
				if describes >= 2 {
					running, roll = 1, "COMPLETED"
				}
				_, _ = w.Write([]byte(`{"services":[{"status":"ACTIVE","runningCount":` +
					itoa(running) + `,"desiredCount":1,"launchType":"FARGATE",` +
					`"networkConfiguration":{"awsvpcConfiguration":{"assignPublicIp":"ENABLED"}},` +
					`"deployments":[{"rolloutState":"` + roll + `"}],` +
					`"tags":[{"key":"groundhold-capability","value":"` + tagCap + `"},` +
					`{"key":"groundhold-environment","value":"prod"}]}]}`))
			case "DeleteService":
				deleted = true
				_, _ = w.Write([]byte(`{}`))
			case "DeleteCluster":
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	return "1"
}

func ecsTestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.ECSBaseURL = srv.URL
	d.Account = "000000000000"
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second // bound the drain poll in tests
	return d
}

func TestCreateECSPollsToStable(t *testing.T) {
	srv := ecsServer(t, "app")
	defer srv.Close()
	d := ecsTestDriver(t, srv)
	res := d.createECS("eu-central-1", "000000000000", "prod", "app", ecsAttrs(), ecsImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "ecs:eu-central-1:") {
		t.Fatalf("got %+v, want succeeded once stable", res)
	}
}

func TestObserveECS(t *testing.T) {
	srv := ecsServer(t, "app")
	defer srv.Close()
	d := ecsTestDriver(t, srv)
	obs, _, err := d.observeECS("app", "ecs:eu-central-1:app-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["network.publicExposure"] != true {
		t.Fatalf("assignPublicIp ENABLED must be public, got %v", got["network.publicExposure"])
	}
	if got["replicas.minimum"] != float64(1) {
		t.Fatalf("desiredCount 1 -> replicas.minimum 1, got %v", got["replicas.minimum"])
	}
}

func TestDeleteECSForeignRefused(t *testing.T) {
	srv := ecsServer(t, "other") // service tagged for a different capability
	defer srv.Close()
	d := ecsTestDriver(t, srv)
	res := d.deleteECS("app", "prod", "ecs:eu-central-1:app-abcd1234")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign-tagged service must refuse delete, got %+v", res)
	}
}

func TestDeleteECSOurs(t *testing.T) {
	srv := ecsServer(t, "app")
	defer srv.Close()
	d := ecsTestDriver(t, srv)
	res := d.deleteECS("app", "prod", "ecs:eu-central-1:app-abcd1234")
	if res.Status != "succeeded" {
		t.Fatalf("delete of an owned service must succeed, got %+v", res)
	}
}

func TestSplitECSProviderID(t *testing.T) {
	if _, _, err := splitECSProviderID("ecs:eu-central-1:app-abcd1234"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	for _, bad := range []string{"eu:app", "s3:eu-central-1:app", "ecs:bad:app"} {
		if _, _, err := splitECSProviderID(bad); err == nil {
			t.Errorf("accepted malformed ecs id %q", bad)
		}
	}
}
