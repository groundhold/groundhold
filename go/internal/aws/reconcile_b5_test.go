package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rc5Receipt builds the pending-create receipt the way apply.go writes it, so the
// tests drive the PUBLIC Reconcile dispatch (exercising the switch wiring too).
func rc5Receipt(svc string) map[string]any {
	return map[string]any{"target": "aws." + svc + "/x", "operation": "create", "generation": 1}
}

// --- ecs -------------------------------------------------------------------

// TestReconcileECS_Succeeded: a stable, owned service at our deterministic name
// concludes succeeded with the recomputed ecs:region:name pid.
func TestReconcileECS_Succeeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		switch target[strings.LastIndex(target, ".")+1:] {
		case "DescribeServices":
			_, _ = w.Write([]byte(`{"services":[{"status":"ACTIVE","runningCount":1,"desiredCount":1,` +
				`"deployments":[{"rolloutState":"COMPLETED"}],` +
				`"tags":[{"key":"groundhold-capability","value":"app"},` +
				`{"key":"groundhold-environment","value":"prod"}]}]}`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := ecsTestDriver(t, srv)
	res := d.Reconcile("app", "prod", rc5Receipt("ecs"))
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "ecs:eu-central-1:") {
		t.Fatalf("ecs reconcile: %+v", res)
	}
}

// TestReconcileECS_Absent: an empty DescribeServices (readable absence) concludes
// failed — the create did not land.
func TestReconcileECS_Absent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"services":[]}`))
	}))
	defer srv.Close()
	d := ecsTestDriver(t, srv)
	res := d.Reconcile("app", "prod", rc5Receipt("ecs"))
	if res.Status != "failed" {
		t.Fatalf("absent ecs service must conclude failed, got %+v", res)
	}
}

// --- loadbalancer ----------------------------------------------------------

// lbReconcileServer echoes the requested LB name back (so it matches our
// deterministic name), reports the given State.Code, and answers DescribeTags.
func lbReconcileServer(t *testing.T, state, capTag string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		name := r.PostForm.Get("Names.member.1")
		arn := "arn:aws:elasticloadbalancing:eu-central-1:000000000000:loadbalancer/app/" + name + "/50dc6c495c0c9188"
		switch r.PostForm.Get("Action") {
		case "DescribeLoadBalancers":
			_, _ = w.Write([]byte(`<DescribeLoadBalancersResponse><DescribeLoadBalancersResult><LoadBalancers><member>` +
				`<LoadBalancerArn>` + arn + `</LoadBalancerArn>` +
				`<LoadBalancerName>` + name + `</LoadBalancerName>` +
				`<Scheme>internet-facing</Scheme><Type>application</Type>` +
				`<State><Code>` + state + `</Code></State>` +
				`</member></LoadBalancers></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>`))
		case "DescribeTags":
			_, _ = w.Write([]byte(`<DescribeTagsResponse><DescribeTagsResult><TagDescriptions><member><Tags>` +
				`<member><Key>groundhold-capability</Key><Value>` + capTag + `</Value></member>` +
				`<member><Key>groundhold-environment</Key><Value>prod</Value></member>` +
				`</Tags></member></TagDescriptions></DescribeTagsResult></DescribeTagsResponse>`))
		default:
			w.WriteHeader(400)
		}
	}))
}

// TestReconcileLoadBalancer_Succeeded: an active, owned ALB concludes succeeded
// with the recomputed elbv2:region:name pid.
func TestReconcileLoadBalancer_Succeeded(t *testing.T) {
	srv := lbReconcileServer(t, "active", "web")
	defer srv.Close()
	d := elbv2TestDriver(t, srv)
	res := d.Reconcile("web", "prod", rc5Receipt("loadbalancer"))
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "elbv2:eu-central-1:") {
		t.Fatalf("loadbalancer reconcile: %+v", res)
	}
}

// TestReconcileLoadBalancer_Provisioning: a still-provisioning ALB stays unknown —
// the listener cannot be presumed attached, so the receipt stays pending.
func TestReconcileLoadBalancer_Provisioning(t *testing.T) {
	srv := lbReconcileServer(t, "provisioning", "web")
	defer srv.Close()
	d := elbv2TestDriver(t, srv)
	res := d.Reconcile("web", "prod", rc5Receipt("loadbalancer"))
	if res.Status != "unknown" {
		t.Fatalf("provisioning ALB must stay unknown, got %+v", res)
	}
}

// --- eks-addon -------------------------------------------------------------

// addonReconcileServer lists one cluster with one addon carrying the given status
// and tags (region-level enumeration, the bedrock ownership pattern).
func addonReconcileServer(t *testing.T, status, capTag string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/clusters":
			_, _ = w.Write([]byte(`{"clusters":["acme-prod"]}`))
		case "/clusters/acme-prod/addons":
			_, _ = w.Write([]byte(`{"addons":["aws-ebs-csi-driver"]}`))
		case "/clusters/acme-prod/addons/aws-ebs-csi-driver":
			_, _ = w.Write([]byte(`{"addon":{"addonName":"aws-ebs-csi-driver","addonVersion":"v1.29.0-eksbuild.1",` +
				`"status":"` + status + `","tags":{"groundhold-capability":"` + capTag +
				`","groundhold-environment":"prod"}}}`))
		default:
			http.Error(w, "nf", http.StatusNotFound)
		}
	}))
}

// TestReconcileEKSAddon_Succeeded: an ACTIVE, owned addon concludes succeeded with
// the deterministic eks-addon:region:cluster/addon pid.
func TestReconcileEKSAddon_Succeeded(t *testing.T) {
	srv := addonReconcileServer(t, "ACTIVE", sanitizeTag(eksAddonCap))
	defer srv.Close()
	d := eksProvDriver(t, srv)
	res := d.Reconcile(eksAddonCap, "prod", rc5Receipt("eks-addon"))
	if res.Status != "succeeded" || res.ProviderID != addonPID() {
		t.Fatalf("eks-addon reconcile: %+v (want succeeded %s)", res, addonPID())
	}
}

// TestReconcileEKSAddon_Failed: an owned addon in CREATE_FAILED concludes failed —
// the create did not land cleanly.
func TestReconcileEKSAddon_Failed(t *testing.T) {
	srv := addonReconcileServer(t, "CREATE_FAILED", sanitizeTag(eksAddonCap))
	defer srv.Close()
	d := eksProvDriver(t, srv)
	res := d.Reconcile(eksAddonCap, "prod", rc5Receipt("eks-addon"))
	if res.Status != "failed" {
		t.Fatalf("CREATE_FAILED addon must conclude failed, got %+v", res)
	}
}

// --- cloudwatch (alarm) ----------------------------------------------------

// TestReconcileCloudWatchAlarm_Succeeded: a present, owned alarm (synchronous)
// concludes succeeded with the awsalert:region:account:name pid.
func TestReconcileCloudWatchAlarm_Succeeded(t *testing.T) {
	srv := cwAlarmOwnedServer(t)
	defer srv.Close()
	d := cwAlarmDriver(t, srv)
	res := d.Reconcile("cpu", "prod", rc5Receipt("cloudwatch"))
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "awsalert:eu-central-1:000000000000:") {
		t.Fatalf("cloudwatch alarm reconcile: %+v", res)
	}
}

// TestReconcileCloudWatchAlarm_Absent: an empty DescribeAlarms (readable absence)
// concludes failed.
func TestReconcileCloudWatchAlarm_Absent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("Action") == "DescribeAlarms" {
			_, _ = w.Write([]byte(`<DescribeAlarmsResponse><DescribeAlarmsResult><MetricAlarms></MetricAlarms></DescribeAlarmsResult></DescribeAlarmsResponse>`))
			return
		}
		w.WriteHeader(400)
	}))
	defer srv.Close()
	d := cwAlarmDriver(t, srv)
	res := d.Reconcile("cpu", "prod", rc5Receipt("cloudwatch"))
	if res.Status != "failed" {
		t.Fatalf("absent alarm must conclude failed, got %+v", res)
	}
}

// --- cloudwatchdash --------------------------------------------------------

// TestReconcileCWDashboard_Succeeded: a dashboard present at our deterministic name
// concludes succeeded — the name is the ownership handle (no tags). GLOBAL, so no
// region guard.
func TestReconcileCWDashboard_Succeeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("Action") == "GetDashboard" {
			_, _ = w.Write([]byte(`<GetDashboardResponse><GetDashboardResult><DashboardBody>{"widgets":[]}` +
				`</DashboardBody></GetDashboardResult></GetDashboardResponse>`))
			return
		}
		w.WriteHeader(400)
	}))
	defer srv.Close()
	d := cwDashDriver(t, srv)
	res := d.Reconcile("golden", "prod", rc5Receipt("cloudwatchdash"))
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "cwdash:pv-golden-prod-") {
		t.Fatalf("cloudwatchdash reconcile: %+v", res)
	}
}

// TestReconcileCWDashboard_Absent: a *NotFound GetDashboard (readable absence)
// concludes failed.
func TestReconcileCWDashboard_Absent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("Action") == "GetDashboard" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>ResourceNotFound</Code></Error></ErrorResponse>`))
			return
		}
		w.WriteHeader(400)
	}))
	defer srv.Close()
	d := cwDashDriver(t, srv)
	res := d.Reconcile("golden", "prod", rc5Receipt("cloudwatchdash"))
	if res.Status != "failed" {
		t.Fatalf("absent dashboard must conclude failed, got %+v", res)
	}
}
