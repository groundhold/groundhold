package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// BATCH 2 reconcile tests (F19, D57): each service reconciles a pending create by
// RECOMPUTING its deterministic name and reading live state. Every test drives the
// dispatcher d.Reconcile with a minimal pending-create receipt (target/operation/
// generation), exactly as `resume` does. Per service: (a) a live+owned resource
// concludes succeeded with the recomputed pid; (b) a readable absence concludes
// failed (the pending intent clears so a re-plan recreates).

// ---- secretsmanager -------------------------------------------------------

func TestReconcileSecretsManager(t *testing.T) {
	srv := asmServer(t, "dbcreds", "") // DescribeSecret carries our owner tags
	defer srv.Close()
	d := asmDriver(t, srv)

	receipt := map[string]any{"target": "aws.secretsmanager/x", "operation": "create", "generation": 1}
	res := d.Reconcile("dbcreds", "prod", receipt)
	if res.Status != "succeeded" {
		t.Fatalf("live owned secret must reconcile succeeded, got %+v", res)
	}
	if want := asmProviderID("eu-central-1", ASMSecretName("prod", "dbcreds", 1)); res.ProviderID != want {
		t.Fatalf("providerId = %q, want the recomputed secret pid %q", res.ProviderID, want)
	}

	// a foreign secret (tags do not match) is not attributed to our create.
	fsrv := asmServer(t, "someone-else", "")
	defer fsrv.Close()
	if r := asmDriver(t, fsrv).Reconcile("dbcreds", "prod", receipt); r.Status != "unknown" {
		t.Fatalf("a secret without our tags must not be claimed, got %+v", r)
	}
}

func TestReconcileSecretsManager_Absent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException"}`))
	}))
	defer srv.Close()
	receipt := map[string]any{"target": "aws.secretsmanager/x", "operation": "create", "generation": 1}
	if r := asmDriver(t, srv).Reconcile("dbcreds", "prod", receipt); r.Status != "failed" {
		t.Fatalf("an absent secret must reconcile failed, got %+v", r)
	}
}

// ---- cwlogs ---------------------------------------------------------------

func TestReconcileCWLogs(t *testing.T) {
	name := CWLogGroupName("prod", "app-logs", 1)
	srv := cwLogsServer(t, name, "app-logs", 90, "")
	defer srv.Close()
	d := cwLogsDriver(t, srv)

	receipt := map[string]any{"target": "aws.cwlogs/x", "operation": "create", "generation": 1}
	res := d.Reconcile("app-logs", "prod", receipt)
	if res.Status != "succeeded" {
		t.Fatalf("live owned log group must reconcile succeeded, got %+v", res)
	}
	if want := cwLogsProviderID("eu-central-1", name); res.ProviderID != want {
		t.Fatalf("providerId = %q, want %q", res.ProviderID, want)
	}
}

func TestReconcileCWLogs_Absent(t *testing.T) {
	// DescribeLogGroups returns an empty list -> readable absence -> failed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"logGroups":[]}`))
	}))
	defer srv.Close()
	receipt := map[string]any{"target": "aws.cwlogs/x", "operation": "create", "generation": 1}
	if r := cwLogsDriver(t, srv).Reconcile("app-logs", "prod", receipt); r.Status != "failed" {
		t.Fatalf("an absent log group must reconcile failed, got %+v", r)
	}
}

// ---- cloudtrail -----------------------------------------------------------

func TestReconcileCloudTrail(t *testing.T) {
	name := CloudTrailName("prod", "audit", 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch cloudTrailAction(r) {
		case "GetTrail":
			_, _ = w.Write([]byte(`{"Trail":{"Name":"` + name + `","TrailARN":"` + cloudTrailArn(name) + `"}}`))
		case "ListTags":
			_, _ = w.Write([]byte(`{"ResourceTagList":[{"ResourceId":"` + cloudTrailArn(name) +
				`","TagsList":[{"Key":"groundhold-capability","Value":"audit"},{"Key":"groundhold-environment","Value":"prod"}]}]}`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := cloudTrailDriver(t, srv)

	receipt := map[string]any{"target": "aws.cloudtrail/x", "operation": "create", "generation": 1}
	res := d.Reconcile("audit", "prod", receipt)
	if res.Status != "succeeded" {
		t.Fatalf("live owned trail must reconcile succeeded, got %+v", res)
	}
	if want := cloudTrailProviderID("eu-central-1", name); res.ProviderID != want {
		t.Fatalf("providerId = %q, want %q", res.ProviderID, want)
	}
}

func TestReconcileCloudTrail_Absent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cloudTrailAction(r) == "GetTrail" {
			_, _ = w.Write([]byte(`{"__type":"TrailNotFoundException"}`))
			return
		}
		w.WriteHeader(400)
	}))
	defer srv.Close()
	receipt := map[string]any{"target": "aws.cloudtrail/x", "operation": "create", "generation": 1}
	if r := cloudTrailDriver(t, srv).Reconcile("audit", "prod", receipt); r.Status != "failed" {
		t.Fatalf("an absent trail must reconcile failed, got %+v", r)
	}
}

// ---- backupvault ----------------------------------------------------------

func TestReconcileBackupVault(t *testing.T) {
	srv := bkvServer(t, "archive", true, 90) // GET vault found, ListTags owner=archive
	defer srv.Close()
	d := bkvDriver(t, srv)

	receipt := map[string]any{"target": "aws.backupvault/x", "operation": "create", "generation": 1}
	res := d.Reconcile("archive", "prod", receipt)
	if res.Status != "succeeded" {
		t.Fatalf("live owned vault must reconcile succeeded, got %+v", res)
	}
	if want := bkvProviderID("eu-central-1", "000000000000", BackupVaultName("prod", "archive", 1)); res.ProviderID != want {
		t.Fatalf("providerId = %q, want %q", res.ProviderID, want)
	}
}

func TestReconcileBackupVault_Absent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException"}`))
	}))
	defer srv.Close()
	receipt := map[string]any{"target": "aws.backupvault/x", "operation": "create", "generation": 1}
	if r := bkvDriver(t, srv).Reconcile("archive", "prod", receipt); r.Status != "failed" {
		t.Fatalf("an absent vault must reconcile failed, got %+v", r)
	}
}

// ---- cwlogfilter ----------------------------------------------------------
// A metric filter has NO tags: identity + ownership are the deterministic filter name
// inside our metric namespace, and the log group is discovered from the live read
// (it is an impl operand, not recomputable).

func cwLogFilterDescribeServer(t *testing.T, filterName, logGroup, namespace string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		if target[strings.LastIndex(target, ".")+1:] != "DescribeMetricFilters" {
			w.WriteHeader(400)
			return
		}
		if filterName == "" {
			_, _ = w.Write([]byte(`{"metricFilters":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"metricFilters":[{"filterName":"` + filterName + `","logGroupName":"` + logGroup + `",` +
			`"metricTransformations":[{"metricName":"app_error_count","metricValue":"1","metricNamespace":"` + namespace + `"}]}]}`))
	}))
}

func TestReconcileCWLogFilter(t *testing.T) {
	name := logFilterName("prod", "errors", 1)
	srv := cwLogFilterDescribeServer(t, name, "/aws/lambda/app", logMetricNamespace)
	defer srv.Close()
	d := cwLogFilterDriver(t, srv)

	receipt := map[string]any{"target": "aws.cwlogfilter/x", "operation": "create", "generation": 1}
	res := d.Reconcile("errors", "prod", receipt)
	if res.Status != "succeeded" {
		t.Fatalf("live metric filter must reconcile succeeded, got %+v", res)
	}
	if want := cwLogFilterProviderID("eu-central-1", "/aws/lambda/app", name); res.ProviderID != want {
		t.Fatalf("providerId = %q, want the discovered-log-group pid %q", res.ProviderID, want)
	}

	// a name hit in a FOREIGN namespace is not ours -> unknown (never claimed).
	fsrv := cwLogFilterDescribeServer(t, name, "/aws/lambda/app", "someone/else")
	defer fsrv.Close()
	if r := cwLogFilterDriver(t, fsrv).Reconcile("errors", "prod", receipt); r.Status != "unknown" {
		t.Fatalf("a filter in a foreign namespace must not be claimed, got %+v", r)
	}
}

func TestReconcileCWLogFilter_Absent(t *testing.T) {
	srv := cwLogFilterDescribeServer(t, "", "", "") // empty metricFilters -> no match
	defer srv.Close()
	receipt := map[string]any{"target": "aws.cwlogfilter/x", "operation": "create", "generation": 1}
	if r := cwLogFilterDriver(t, srv).Reconcile("errors", "prod", receipt); r.Status != "failed" {
		t.Fatalf("an absent metric filter must reconcile failed, got %+v", r)
	}
}
