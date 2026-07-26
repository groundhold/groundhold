package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// BATCH 4 reconcile (F19, D57): the async DB/search family. Each service pins two
// verdicts through the public d.Reconcile entrypoint (dispatch on the receipt
// target): a ready+owned live resource concludes SUCCEEDED with the RECOMPUTED
// deterministic pid; a still-provisioning read stays UNKNOWN (pending, never
// guessed) and a readable absence concludes FAILED (the create did not land).

// ---- RDS ----

// rdsAvailableServer answers DescribeDBInstances with an available, owned instance
// (the rdsServer helper reports "creating" on the first describe, which is the
// still-provisioning path we want for the negative case).
func rdsAvailableServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		if strings.Contains(string(body), "Action=DescribeDBInstances") {
			_, _ = w.Write([]byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>` +
				`<DBInstanceIdentifier>db-x</DBInstanceIdentifier>` +
				`<DBInstanceStatus>available</DBInstanceStatus>` +
				`<TagList><Tag><Key>groundhold-capability</Key><Value>db</Value></Tag>` +
				`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag></TagList>` +
				`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
			return
		}
		w.WriteHeader(404)
	}))
}

func TestReconcileRDS(t *testing.T) {
	// available + owned -> succeeded WITH the recomputed pid.
	srv := rdsAvailableServer(t)
	defer srv.Close()
	d := rdsTestDriver(t, srv)
	receipt := map[string]any{"target": "aws.rds/x", "operation": "create", "generation": 1}
	res := d.Reconcile("db", "prod", receipt)
	wantPID := rdsProviderID("eu-central-1", DBIdentifier("000000000000", "prod", "db", 1))
	if res.Status != "succeeded" || res.ProviderID != wantPID {
		t.Fatalf("ready+owned reconcile = %+v, want succeeded with %s", res, wantPID)
	}

	// still creating -> unknown (rdsServer reports "creating" on the first describe).
	srv2 := rdsServer(t, "", "false")
	defer srv2.Close()
	d2 := rdsTestDriver(t, srv2)
	if u := d2.Reconcile("db", "prod", receipt); u.Status != "unknown" {
		t.Fatalf("still-creating reconcile = %+v, want unknown", u)
	}
}

// ---- Aurora ----

func TestReconcileAurora(t *testing.T) {
	// available cluster + owner tags -> succeeded WITH the recomputed pid.
	f := newFakeAurora()
	f.clusterExists = true
	f.clusterStatus = "available"
	f.tags = map[string]string{
		"groundhold-capability":  sanitizeTag("db"),
		"groundhold-environment": sanitizeTag("prod"),
	}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)
	receipt := map[string]any{"target": "aws.aurora/x", "operation": "create", "generation": 1}
	res := d.Reconcile("db", "prod", receipt)
	wantPID := auroraProviderID("eu-central-1", DBIdentifier("000000000000", "prod", "db", 1))
	if res.Status != "succeeded" || res.ProviderID != wantPID {
		t.Fatalf("ready+owned reconcile = %+v, want succeeded with %s", res, wantPID)
	}

	// no cluster (readable absence) -> failed.
	f2 := newFakeAurora()
	f2.clusterExists = false
	srv2 := f2.handler(t, nil)
	defer srv2.Close()
	d2 := auroraTestDriver(t, srv2)
	if fl := d2.Reconcile("db", "prod", receipt); fl.Status != "failed" {
		t.Fatalf("absent-cluster reconcile = %+v, want failed", fl)
	}
}

// ---- OpenSearch ----

func TestReconcileOpenSearch(t *testing.T) {
	// Processing==false + owner tags -> succeeded WITH the recomputed pid.
	srv := osServer(t, "catalog", true, true)
	defer srv.Close()
	d := osDriver(t, srv)
	receipt := map[string]any{"target": "aws.opensearch/x", "operation": "create", "generation": 1}
	res := d.Reconcile("catalog", "prod", receipt)
	wantPID := openSearchProviderID("eu-central-1", "000000000000", OpenSearchDomainName("prod", "catalog", 1))
	if res.Status != "succeeded" || res.ProviderID != wantPID {
		t.Fatalf("ready+owned reconcile = %+v, want succeeded with %s", res, wantPID)
	}

	// domain absent (ResourceNotFound) -> failed.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"ResourceNotFoundException"}`, http.StatusNotFound)
	}))
	defer srv2.Close()
	d2 := osDriver(t, srv2)
	if fl := d2.Reconcile("catalog", "prod", receipt); fl.Status != "failed" {
		t.Fatalf("absent-domain reconcile = %+v, want failed", fl)
	}
}

// ---- MSK ----

func TestReconcileMSK(t *testing.T) {
	// State==ACTIVE + owner tags -> succeeded WITH the recomputed pid.
	srv := mskServer(t, "bus", "3.5.1", false)
	defer srv.Close()
	d := mskDriver(t, srv)
	receipt := map[string]any{"target": "aws.msk/x", "operation": "create", "generation": 1}
	res := d.Reconcile("bus", "prod", receipt)
	wantPID := mskProviderID("eu-central-1", "000000000000", MSKClusterName("prod", "bus", 1))
	if res.Status != "succeeded" || res.ProviderID != wantPID {
		t.Fatalf("ready+owned reconcile = %+v, want succeeded with %s", res, wantPID)
	}

	// still CREATING -> unknown (found + owned, not yet ACTIVE).
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			name := r.URL.Query().Get("clusterNameFilter")
			_, _ = w.Write([]byte(`{"ClusterInfoList":[{"ClusterName":"` + name +
				`","State":"CREATING","Tags":{"groundhold-capability":"bus","groundhold-environment":"prod"}}]}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv2.Close()
	d2 := mskDriver(t, srv2)
	if u := d2.Reconcile("bus", "prod", receipt); u.Status != "unknown" {
		t.Fatalf("still-creating reconcile = %+v, want unknown", u)
	}
}

// ---- Redshift Serverless ----

func TestReconcileRedshiftServerless(t *testing.T) {
	// workgroup AVAILABLE + owner tags -> succeeded WITH the recomputed pid.
	srv := rssServer(t, "lake", false)
	defer srv.Close()
	d := rssDriver(t, srv)
	receipt := map[string]any{"target": "aws.redshiftserverless/x", "operation": "create", "generation": 1}
	res := d.Reconcile("lake", "prod", receipt)
	wantPID := rssProviderID("eu-central-1", RSSName("prod", "lake", 1))
	if res.Status != "succeeded" || res.ProviderID != wantPID {
		t.Fatalf("ready+owned reconcile = %+v, want succeeded with %s", res, wantPID)
	}

	// workgroup absent (ResourceNotFound) -> failed.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rssAction(r) == "GetWorkgroup" {
			http.Error(w, `{"__type":"ResourceNotFoundException"}`, http.StatusBadRequest)
			return
		}
		w.WriteHeader(400)
	}))
	defer srv2.Close()
	d2 := rssDriver(t, srv2)
	if fl := d2.Reconcile("lake", "prod", receipt); fl.Status != "failed" {
		t.Fatalf("absent-workgroup reconcile = %+v, want failed", fl)
	}
}
