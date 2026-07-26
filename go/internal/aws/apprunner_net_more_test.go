package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file rounds out apprunner_net.go coverage: updateAppRunner (0%),
// claimAppRunnerARN (0%, exercised only through claim_aws.go's claimARN
// dispatch), and discoverAppRunner's under-tested branches (18.2%) — the
// mutable in-place patch, the takeover claim, and the discovery sweep.

// ---- updateAppRunner --------------------------------------------------

func appRunnerUpdateDriver(t *testing.T, f *apprunnerFake) *Driver {
	t.Helper()
	srv := f.handler(t)
	t.Cleanup(srv.Close)
	return apprunnerTestDriver(t, srv)
}

// TestUpdateAppRunner_ReplicasMinimumAboveOne: minimum>1 with a bound
// AutoScalingConfiguration operand patches via UpdateService and polls back to
// RUNNING — the one mutable App Runner path.
func TestUpdateAppRunner_ReplicasMinimumAboveOne(t *testing.T) {
	f := &apprunnerFake{}
	d := appRunnerUpdateDriver(t, f)
	pid := apprunnerProviderID("eu-central-1", "app-abcd1234")
	a := apprunnerAttrs()
	a["replicas.minimum"] = float64(3)
	i := apprunnerImpl()
	i["autoScalingConfigurationArn"] = "arn:aws:apprunner:eu-central-1:000000000000:autoscalingconfiguration/hi/1/abc"
	res := d.updateAppRunner("app", "prod", pid, a, i, []string{"replicas.minimum"})
	if res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("mutable minimum patch: %+v", res)
	}
	sawUpdate := false
	for _, s := range f.seen {
		if strings.HasSuffix(s, "UpdateService") {
			sawUpdate = true
		}
	}
	if !sawUpdate {
		t.Fatalf("update must issue UpdateService, saw %v", f.seen)
	}
}

// TestUpdateAppRunner_ReplicasMinimumZeroRefuses: App Runner has no
// scale-to-zero — minimum:0 must refuse, never silently clamp to 1.
func TestUpdateAppRunner_ReplicasMinimumZeroRefuses(t *testing.T) {
	f := &apprunnerFake{}
	d := appRunnerUpdateDriver(t, f)
	pid := apprunnerProviderID("eu-central-1", "app-abcd1234")
	a := apprunnerAttrs()
	a["replicas.minimum"] = float64(0)
	res := d.updateAppRunner("app", "prod", pid, a, apprunnerImpl(), []string{"replicas.minimum"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "no scale-to-zero") {
		t.Fatalf("minimum:0 must refuse with the scale-to-zero reason, got %+v", res)
	}
}

// TestUpdateAppRunner_ReplicasMinimumOneIsAReplacement: minimum:1 maps to
// App Runner's DEFAULT autoscaling (no arn) — a downward change to the default
// is a replacement, not an in-place patch, so update must refuse honestly.
func TestUpdateAppRunner_ReplicasMinimumOneIsAReplacement(t *testing.T) {
	f := &apprunnerFake{}
	d := appRunnerUpdateDriver(t, f)
	pid := apprunnerProviderID("eu-central-1", "app-abcd1234")
	a := apprunnerAttrs()
	a["replicas.minimum"] = float64(1)
	res := d.updateAppRunner("app", "prod", pid, a, apprunnerImpl(), []string{"replicas.minimum"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "default autoscaling") {
		t.Fatalf("minimum:1 must refuse as a replacement, got %+v", res)
	}
}

// TestUpdateAppRunner_NotANumberRefuses / FractionalRefuses: refuse-before-mutate
// on a malformed replicas.minimum value.
func TestUpdateAppRunner_NotANumberRefuses(t *testing.T) {
	f := &apprunnerFake{}
	d := appRunnerUpdateDriver(t, f)
	pid := apprunnerProviderID("eu-central-1", "app-abcd1234")
	a := apprunnerAttrs()
	a["replicas.minimum"] = "three"
	res := d.updateAppRunner("app", "prod", pid, a, apprunnerImpl(), []string{"replicas.minimum"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not a number") {
		t.Fatalf("a non-numeric minimum must refuse, got %+v", res)
	}
}

func TestUpdateAppRunner_FractionalRefuses(t *testing.T) {
	f := &apprunnerFake{}
	d := appRunnerUpdateDriver(t, f)
	pid := apprunnerProviderID("eu-central-1", "app-abcd1234")
	a := apprunnerAttrs()
	a["replicas.minimum"] = 2.5
	res := d.updateAppRunner("app", "prod", pid, a, apprunnerImpl(), []string{"replicas.minimum"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "whole number") {
		t.Fatalf("a fractional minimum must refuse, got %+v", res)
	}
}

// TestUpdateAppRunner_UnmappedPathRefuses: no other App Runner attribute is
// patchable in place.
func TestUpdateAppRunner_UnmappedPathRefuses(t *testing.T) {
	f := &apprunnerFake{}
	d := appRunnerUpdateDriver(t, f)
	pid := apprunnerProviderID("eu-central-1", "app-abcd1234")
	res := d.updateAppRunner("app", "prod", pid, apprunnerAttrs(), apprunnerImpl(), []string{"tls.enforced"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "no in-place App Runner mapping") {
		t.Fatalf("an unmapped path must refuse, got %+v", res)
	}
}

// TestUpdateAppRunner_ForeignRefuses: ownership is re-checked before patching.
func TestUpdateAppRunner_ForeignRefuses(t *testing.T) {
	f := &apprunnerFake{tagCap: "someone-else"}
	d := appRunnerUpdateDriver(t, f)
	pid := apprunnerProviderID("eu-central-1", "app-abcd1234")
	res := d.updateAppRunner("app", "prod", pid, apprunnerAttrs(), apprunnerImpl(), []string{"replicas.minimum"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign service must refuse update, got %+v", res)
	}
}

// TestUpdateAppRunner_VanishedFails: the providerId's name is absent from
// ListServices — the function to patch no longer exists.
func TestUpdateAppRunner_VanishedFails(t *testing.T) {
	f := &apprunnerFake{}
	d := appRunnerUpdateDriver(t, f)
	pid := apprunnerProviderID("eu-central-1", "gone-service9")
	res := d.updateAppRunner("app", "prod", pid, apprunnerAttrs(), apprunnerImpl(), []string{"replicas.minimum"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "no longer exists") {
		t.Fatalf("a vanished service must refuse update, got %+v", res)
	}
}

// TestUpdateAppRunner_PreUpdateReadUnknown: an unreachable endpoint makes the
// pre-update resolve ambiguous — unknown WITH the pid (reconcile), not failed.
func TestUpdateAppRunner_PreUpdateReadUnknown(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.AppRunnerBaseURL = "http://127.0.0.1:1" // nothing listens here
	pid := apprunnerProviderID("eu-central-1", "app-abcd1234")
	res := d.updateAppRunner("app", "prod", pid, apprunnerAttrs(), apprunnerImpl(), []string{"replicas.minimum"})
	if res.Status != "unknown" || res.ProviderID != pid {
		t.Fatalf("an unreachable pre-update read must be unknown WITH the pid, got %+v", res)
	}
}

// apprunnerUpdateFailFake answers ListServices/ListTagsForResource/DescribeService
// normally but injects an HTTP status for UpdateService — the knob apprunnerFake
// (shared with the create/delete tests) does not expose.
type apprunnerUpdateFailFake struct {
	updateStatus int
}

func (f *apprunnerUpdateFailFake) handler(t *testing.T) *httptest.Server {
	t.Helper()
	arn := "arn:aws:apprunner:eu-central-1:000000000000:service/app/0123456789abcdef"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		action := target[strings.LastIndex(target, ".")+1:]
		switch action {
		case "ListServices":
			_, _ = w.Write([]byte(`{"ServiceSummaryList":[{"ServiceName":"app-abcd1234","ServiceArn":"` + arn + `"}]}`))
		case "ListTagsForResource":
			_, _ = w.Write([]byte(`{"Tags":[{"Key":"groundhold-capability","Value":"app"},{"Key":"groundhold-environment","Value":"prod"}]}`))
		case "UpdateService":
			w.WriteHeader(f.updateStatus)
			_, _ = w.Write([]byte(`{"__type":"InvalidRequestException","message":"boom"}`))
		default:
			w.WriteHeader(400)
		}
	}))
}

// TestUpdateAppRunner_UpdateService5xxIsUnknown: a server error during the patch
// call itself is ambiguous — unknown WITH the pid, never failed.
func TestUpdateAppRunner_UpdateService5xxIsUnknown(t *testing.T) {
	f := &apprunnerUpdateFailFake{updateStatus: 503}
	srv := f.handler(t)
	defer srv.Close()
	d := apprunnerTestDriver(t, srv)
	pid := apprunnerProviderID("eu-central-1", "app-abcd1234")
	a := apprunnerAttrs()
	a["replicas.minimum"] = float64(3)
	i := apprunnerImpl()
	i["autoScalingConfigurationArn"] = "arn:aws:apprunner:eu-central-1:000000000000:autoscalingconfiguration/hi/1/abc"
	res := d.updateAppRunner("app", "prod", pid, a, i, []string{"replicas.minimum"})
	if res.Status != "unknown" || res.ProviderID != pid {
		t.Fatalf("a 5xx UpdateService must be unknown WITH the pid, got %+v", res)
	}
}

// TestUpdateAppRunner_UpdateService4xxIsFailed: a clean 4xx on the patch call
// itself is a clean failure.
func TestUpdateAppRunner_UpdateService4xxIsFailed(t *testing.T) {
	f := &apprunnerUpdateFailFake{updateStatus: 400}
	srv := f.handler(t)
	defer srv.Close()
	d := apprunnerTestDriver(t, srv)
	pid := apprunnerProviderID("eu-central-1", "app-abcd1234")
	a := apprunnerAttrs()
	a["replicas.minimum"] = float64(3)
	i := apprunnerImpl()
	i["autoScalingConfigurationArn"] = "arn:aws:apprunner:eu-central-1:000000000000:autoscalingconfiguration/hi/1/abc"
	res := d.updateAppRunner("app", "prod", pid, a, i, []string{"replicas.minimum"})
	if res.Status != "failed" {
		t.Fatalf("a 4xx UpdateService must be failed, got %+v", res)
	}
}

// ---- claimAppRunnerARN (via the Claim dispatch, D145's describe-to-resolve path) --

// TestClaimAppRunnerResolvesArnThenTagsViaRGT: the providerId carries only the
// deterministic NAME; claim resolves the live ARN (ListServices) then stamps
// groundhold's ownership tags via the additive Resource Groups Tagging API.
func TestClaimAppRunnerResolvesArnThenTagsViaRGT(t *testing.T) {
	arn := "arn:aws:apprunner:eu-central-1:000000000000:service/app-abcd1234/0123456789abcdef"
	var rgtBody string
	rgtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = io.ReadFull(r.Body, b)
		rgtBody = string(b)
		_, _ = w.Write([]byte(`{"FailedResourcesMap":{}}`))
	}))
	defer rgtSrv.Close()
	arSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ServiceSummaryList":[{"ServiceName":"app-abcd1234","ServiceArn":"` + arn + `"}]}`))
	}))
	defer arSrv.Close()

	d := rgtTestDriver(t, rgtSrv)
	d.AppRunnerBaseURL = arSrv.URL

	pid := apprunnerProviderID("eu-central-1", "app-abcd1234")
	cr := d.Claim("apprunner", "app", "prod", pid)
	if cr.Status != "succeeded" || cr.ProviderID != pid {
		t.Fatalf("apprunner claim must resolve the ARN then succeed with the pid, got %+v", cr)
	}
	if !strings.Contains(rgtBody, arn) || !strings.Contains(rgtBody, `"groundhold-capability":"app"`) {
		t.Fatalf("the RGT tag body must carry the resolved ARN + groundhold tags:\n%s", rgtBody)
	}
}

// TestClaimAppRunnerVanishedFails: a describe that finds no service is a clean
// failure, never a fabricated ARN.
func TestClaimAppRunnerVanishedFails(t *testing.T) {
	arSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ServiceSummaryList":[]}`))
	}))
	defer arSrv.Close()
	d := rgtTestDriver(t, arSrv)
	d.AppRunnerBaseURL = arSrv.URL
	cr := d.Claim("apprunner", "app", "prod", apprunnerProviderID("eu-central-1", "gone-service9"))
	if cr.Status != "failed" {
		t.Fatalf("a vanished apprunner service must fail the claim, got %+v", cr)
	}
}

// ---- discoverAppRunner --------------------------------------------------

// TestDiscoverAppRunner_MultipleServices: the sweep reverse-maps every listed
// service into capability.workload.container.
func TestDiscoverAppRunner_MultipleServices(t *testing.T) {
	arn1 := "arn:aws:apprunner:eu-central-1:000000000000:service/app-one1234/1111111111111111"
	arn2 := "arn:aws:apprunner:eu-central-1:000000000000:service/app-two5678/2222222222222222"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		action := target[strings.LastIndex(target, ".")+1:]
		switch action {
		case "ListServices":
			_, _ = w.Write([]byte(`{"ServiceSummaryList":[` +
				`{"ServiceName":"app-one1234","ServiceArn":"` + arn1 + `"},` +
				`{"ServiceName":"app-two5678","ServiceArn":"` + arn2 + `"}]}`))
		case "DescribeService":
			b, _ := io.ReadAll(r.Body)
			arn := arn1
			if strings.Contains(string(b), "app-two5678") {
				arn = arn2
			}
			_, _ = w.Write([]byte(`{"Service":{"ServiceArn":"` + arn + `","ServiceName":"x","Status":"RUNNING",` +
				`"NetworkConfiguration":{"IngressConfiguration":{"IsPubliclyAccessible":false}}}}`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := apprunnerTestDriver(t, srv)

	found, diags, err := d.discoverAppRunner("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("want 2 discovered services, got %d (diags %v)", len(found), diags)
	}
	seen := map[string]bool{}
	for _, f := range found {
		if f.ResourceType != "capability.workload.container" {
			t.Fatalf("resourceType = %q", f.ResourceType)
		}
		seen[f.ProviderID] = true
	}
	if !seen[apprunnerProviderID("eu-central-1", "app-one1234")] || !seen[apprunnerProviderID("eu-central-1", "app-two5678")] {
		t.Fatalf("discovered pids = %v", found)
	}
}

// TestDiscoverAppRunner_UnrepresentableNameDiags: a service name too short for
// the apprunner:region:name providerId shape is skipped with a diagnostic, not
// silently dropped or a crash.
func TestDiscoverAppRunner_UnrepresentableNameDiags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		if strings.HasSuffix(target, "ListServices") {
			_, _ = w.Write([]byte(`{"ServiceSummaryList":[{"ServiceName":"ab","ServiceArn":"arn:aws:apprunner:eu-central-1:000000000000:service/ab/1111111111111111"}]}`))
			return
		}
		w.WriteHeader(400)
	}))
	defer srv.Close()
	d := apprunnerTestDriver(t, srv)
	found, diags, err := d.discoverAppRunner("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("an unrepresentable name must not be discovered, got %+v", found)
	}
	if len(diags) != 1 || !strings.Contains(diags[0], "needs adoption by explicit id") {
		t.Fatalf("diags = %v, want one naming the adoption escape hatch", diags)
	}
}

// TestDiscoverAppRunner_TransportErrorFails: an unreachable endpoint surfaces a
// real error, never a silent empty list.
func TestDiscoverAppRunner_TransportErrorFails(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.AppRunnerBaseURL = "http://127.0.0.1:1"
	if _, _, err := d.discoverAppRunner("eu-central-1"); err == nil {
		t.Fatal("an unreachable endpoint must surface an error, not a silent empty list")
	}
}
