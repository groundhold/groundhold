package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The Acme blocker, reconciled: a converge/apply killed mid-create of a
// VPC-attached Lambda strands a pending create receipt; resume -> Reconcile must
// conclude it honestly from the OBSERVABLE GetFunction state (never an
// operation-by-id path, D273). Each test drives the PUBLIC Reconcile dispatch with
// the pending-create receipt apply.go writes, so the switch wiring is exercised too.

// lambdaReconcileDriver builds a driver whose Lambda endpoint is the test server,
// with a SHORT poll budget so the still-Pending deadline path is fast.
func lambdaReconcileDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver("eu-central-1")
	d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	d.Account = "000000000000"
	d.LambdaBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 20 * time.Millisecond
	return d
}

// lambdaGetServer answers GetFunction for the ONE deterministic function name with
// the given Configuration JSON + tags. A non-matching name (or empty cfg) is a 404.
func lambdaGetServer(t *testing.T, cfgJSON, capTag string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "operation") {
			t.Errorf("reconcile must NEVER poll an operation-by-id path, got %s %s", r.Method, r.URL.Path)
		}
		if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/functions/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if cfgJSON == "" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Function not found"}`))
			return
		}
		_, _ = w.Write([]byte(`{"Configuration":` + cfgJSON + `,` +
			`"Tags":{"groundhold-capability":"` + capTag + `","groundhold-environment":"prod"}}`))
	}))
}

func lambdaReconcilePID() string {
	name := ECSName("000000000000", "prod", "api", 1)
	return lambdaProviderID("eu-central-1", "000000000000", name)
}

// Active + Successful -> succeeded WITH the recomputed pid (the create landed).
func TestReconcileLambda_ActiveSucceeded(t *testing.T) {
	srv := lambdaGetServer(t, `{"State":"Active","LastUpdateStatus":"Successful","Timeout":300}`, "api")
	defer srv.Close()
	d := lambdaReconcileDriver(t, srv)
	res := d.Reconcile("api", "prod", rc5Receipt("lambda"))
	if res.Status != "succeeded" || res.ProviderID != lambdaReconcilePID() {
		t.Fatalf("Active+Successful must conclude succeeded with the pid, got %+v (want pid %s)", res, lambdaReconcilePID())
	}
}

// A fresh create reports LastUpdateStatus="" once Active — still a succeeded create.
func TestReconcileLambda_ActiveNoUpdateStatus(t *testing.T) {
	srv := lambdaGetServer(t, `{"State":"Active","Timeout":300}`, "api")
	defer srv.Close()
	d := lambdaReconcileDriver(t, srv)
	res := d.Reconcile("api", "prod", rc5Receipt("lambda"))
	if res.Status != "succeeded" {
		t.Fatalf("Active with empty LastUpdateStatus must conclude succeeded, got %+v", res)
	}
}

// State=Failed -> failed, with the StateReason NAMED.
func TestReconcileLambda_Failed(t *testing.T) {
	srv := lambdaGetServer(t, `{"State":"Failed","StateReason":"ENI limit exceeded in subnet"}`, "api")
	defer srv.Close()
	d := lambdaReconcileDriver(t, srv)
	res := d.Reconcile("api", "prod", rc5Receipt("lambda"))
	if res.Status != "failed" || !strings.Contains(res.Reason, "ENI limit exceeded") {
		t.Fatalf("Failed must conclude failed with the reason named, got %+v", res)
	}
}

// LastUpdateStatus=Failed -> failed, with the LastUpdateStatusReason NAMED.
func TestReconcileLambda_LastUpdateFailed(t *testing.T) {
	srv := lambdaGetServer(t, `{"State":"Active","LastUpdateStatus":"Failed","LastUpdateStatusReason":"role missing ENI perms"}`, "api")
	defer srv.Close()
	d := lambdaReconcileDriver(t, srv)
	res := d.Reconcile("api", "prod", rc5Receipt("lambda"))
	if res.Status != "failed" || !strings.Contains(res.Reason, "role missing ENI perms") {
		t.Fatalf("LastUpdateStatus=Failed must conclude failed with the reason named, got %+v", res)
	}
}

// State=Pending forever -> poll to the deadline, then unknown WITH the pid (the
// receipt stays pending; resume can be re-run once ENIs settle).
func TestReconcileLambda_PendingDeadlineUnknown(t *testing.T) {
	srv := lambdaGetServer(t, `{"State":"Pending"}`, "api")
	defer srv.Close()
	d := lambdaReconcileDriver(t, srv)
	res := d.Reconcile("api", "prod", rc5Receipt("lambda"))
	if res.Status != "unknown" || res.ProviderID != lambdaReconcilePID() {
		t.Fatalf("still-Pending must stay unknown WITH the pid, got %+v (want pid %s)", res, lambdaReconcilePID())
	}
	if !strings.Contains(res.Reason, "still provisioning") {
		t.Fatalf("deadline reason must name the still-provisioning state, got %q", res.Reason)
	}
}

// 404 (readable absence) -> failed: the create did not land, never a fabricated success.
func TestReconcileLambda_AbsentFailed(t *testing.T) {
	srv := lambdaGetServer(t, "", "api")
	defer srv.Close()
	d := lambdaReconcileDriver(t, srv)
	res := d.Reconcile("api", "prod", rc5Receipt("lambda"))
	if res.Status != "failed" || !strings.Contains(res.Reason, "not present") {
		t.Fatalf("a 404 must conclude failed/absent, got %+v", res)
	}
}

// A read error (5xx) -> unknown WITH the pid AND the cause NAMED (D306): never a
// bare "unreadable", never a fabricated absence.
func TestReconcileLambda_ReadErrorUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"ServiceUnavailable"}`))
	}))
	defer srv.Close()
	d := lambdaReconcileDriver(t, srv)
	res := d.Reconcile("api", "prod", rc5Receipt("lambda"))
	if res.Status != "unknown" || res.ProviderID != lambdaReconcilePID() {
		t.Fatalf("a read error must stay unknown WITH the pid, got %+v", res)
	}
	if !strings.Contains(res.Reason, "GetFunction") || !strings.Contains(res.Reason, "HTTP 500") {
		t.Fatalf("read-error reason must NAME the op and status (D306), got %q", res.Reason)
	}
}

// A function present at our name but carrying FOREIGN tags -> unknown: refuse to
// attribute someone else's function to this create (D273).
func TestReconcileLambda_ForeignUnknown(t *testing.T) {
	srv := lambdaGetServer(t, `{"State":"Active","LastUpdateStatus":"Successful"}`, "someone-else")
	defer srv.Close()
	d := lambdaReconcileDriver(t, srv)
	res := d.Reconcile("api", "prod", rc5Receipt("lambda"))
	if res.Status != "unknown" || !strings.Contains(res.Reason, "ownership") {
		t.Fatalf("a foreign-tagged function must stay unknown, got %+v", res)
	}
}
