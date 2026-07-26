package gcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Golden discovery tests for the second GCP service batch. Each fake endpoint
// asserts the bearer List request and that every item is run through the SAME
// reverse map its Observe uses (List -> providerId -> Observe -> attributes).
// Helpers obsByPath / requireBearer / testDriver are shared with
// discover_gcp_ext_test.go.

func TestDiscoverCloudRunJobs(t *testing.T) {
	var listed bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/locations/-/jobs":
				listed = true
				w.Write([]byte(`{"jobs":[
				  {"name":"projects/acme-prod/locations/europe-west1/jobs/nightly"},
				  {"name":"projects/acme-prod/locations/us-east1/jobs/faraway"}
				]}`))
			case "/projects/acme-prod/locations/europe-west1/jobs/nightly":
				w.Write([]byte(`{"template":{"template":{
				  "containers":[{"image":"gcr.io/acme/batch:1"}],"timeout":"600s"}}}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.RunBaseURL = srv.URL

	got, _, err := d.discoverCloudRunJobs("europe-west1")
	if err != nil {
		t.Fatal(err)
	}
	if !listed {
		t.Fatal("jobs.list was never called")
	}
	if len(got) != 1 || got[0].ResourceType != "capability.container.job" ||
		got[0].ProviderID != "gjob:acme-prod:europe-west1:nightly" {
		t.Fatalf("cloud run jobs discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["location.region"] != "europe-west1" || by["trigger.type"] != "manual" ||
		by["image"] != "gcr.io/acme/batch:1" || by["timeout"] != "600s" {
		t.Errorf("cloud run job observations: %v", by)
	}
}

func TestDiscoverFilestore(t *testing.T) {
	var listed bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/locations/-/instances":
				listed = true
				w.Write([]byte(`{"instances":[
				  {"name":"projects/acme-prod/locations/europe-west1/instances/shared"},
				  {"name":"projects/acme-prod/locations/us-east1/instances/faraway"}
				]}`))
			case "/projects/acme-prod/locations/europe-west1/instances/shared":
				w.Write([]byte(`{"tier":"ENTERPRISE","kmsKeyName":"projects/acme-prod/locations/europe-west1/keyRings/k/cryptoKeys/c"}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.FilestoreBaseURL = srv.URL

	got, _, err := d.discoverFilestore("europe-west1")
	if err != nil {
		t.Fatal(err)
	}
	if !listed {
		t.Fatal("instances.list was never called")
	}
	if len(got) != 1 || got[0].ResourceType != "capability.storage.filesystem" ||
		got[0].ProviderID != "filestore:acme-prod:europe-west1:shared" {
		t.Fatalf("filestore discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["location.region"] != "europe-west1" || by["availability.class"] != "regional" ||
		by["protocol"] != "nfs/4.1" || by["encryption.customerManagedKeys"] != true {
		t.Errorf("filestore observations: %v", by)
	}
}

func TestDiscoverManagedKafka(t *testing.T) {
	var listed bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/locations/-/clusters":
				listed = true
				w.Write([]byte(`{"clusters":[
				  {"name":"projects/acme-prod/locations/europe-west1/clusters/events"},
				  {"name":"projects/acme-prod/locations/us-east1/clusters/faraway"}
				]}`))
			case "/projects/acme-prod/locations/europe-west1/clusters/events":
				w.Write([]byte(`{"gcpConfig":{"kmsKey":"projects/acme-prod/locations/europe-west1/keyRings/k/cryptoKeys/c"}}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.ManagedKafkaBaseURL = srv.URL

	got, _, err := d.discoverManagedKafka("europe-west1")
	if err != nil {
		t.Fatal(err)
	}
	if !listed {
		t.Fatal("clusters.list was never called")
	}
	if len(got) != 1 || got[0].ResourceType != "capability.messaging.kafka" ||
		got[0].ProviderID != "gmkafka:acme-prod:europe-west1:events" {
		t.Fatalf("managed kafka discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["location.region"] != "europe-west1" || by["availability.class"] != "regional" ||
		by["engine.protocol"] != "kafka/3" || by["encryption.customerManagedKeys"] != true {
		t.Errorf("managed kafka observations: %v", by)
	}
}

func TestDiscoverDashboards(t *testing.T) {
	var listed bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/dashboards":
				listed = true
				w.Write([]byte(`{"dashboards":[{"name":"projects/acme-prod/dashboards/abc123"}]}`))
			case "/projects/acme-prod/dashboards/abc123":
				w.Write([]byte(`{"displayName":"ops","mosaicLayout":{"tiles":[
				  {"widget":{"xyChart":{"dataSets":[{"timeSeriesQuery":{"timeSeriesFilter":{
				    "filter":"metric.type=\"compute.googleapis.com/instance/cpu/utilization\""}}}]}}}
				]}}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.DashboardBaseURL = srv.URL

	got, _, err := d.discoverDashboards("")
	if err != nil {
		t.Fatal(err)
	}
	if !listed {
		t.Fatal("dashboards.list was never called")
	}
	if len(got) != 1 || got[0].ResourceType != "capability.monitoring.dashboard" ||
		got[0].ProviderID != "gdash:acme-prod:abc123" {
		t.Fatalf("dashboards discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["dashboard.widgetCount"] != float64(1) || by["service.managed"] != true {
		t.Errorf("dashboard observations: %v", by)
	}
	metrics, _ := by["dashboard.metrics"].([]string)
	if len(metrics) != 1 || metrics[0] != "compute.googleapis.com/instance/cpu/utilization" {
		t.Errorf("dashboard.metrics: %v", by["dashboard.metrics"])
	}
}

func TestDiscoverLogMetrics(t *testing.T) {
	var listed bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/metrics":
				listed = true
				w.Write([]byte(`{"metrics":[{"name":"error_count"}]}`))
			case "/projects/acme-prod/metrics/error_count":
				w.Write([]byte(`{"name":"error_count","filter":"severity>=ERROR"}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.LoggingBaseURL = srv.URL

	got, _, err := d.discoverLogMetrics("")
	if err != nil {
		t.Fatal(err)
	}
	if !listed {
		t.Fatal("metrics.list was never called")
	}
	if len(got) != 1 || got[0].ResourceType != "capability.monitoring.logmetric" ||
		got[0].ProviderID != "glogmetric:acme-prod:error_count" {
		t.Fatalf("log metrics discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["metric.name"] != "error_count" || by["metric.filter"] != "severity>=ERROR" ||
		by["metric.kind"] != "counter" {
		t.Errorf("log metric observations: %v", by)
	}
}

func TestDiscoverCloudScheduler(t *testing.T) {
	var listed bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/locations":
				w.Write([]byte(`{"locations":[{"locationId":"europe-west1"}]}`))
			case "/projects/acme-prod/locations/europe-west1/jobs":
				listed = true
				w.Write([]byte(`{"jobs":[{"name":"projects/acme-prod/locations/europe-west1/jobs/rollup"}]}`))
			case "/projects/acme-prod/locations/europe-west1/jobs/rollup":
				w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/jobs/rollup","state":"ENABLED"}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.SchedulerBaseURL = srv.URL

	// empty region enumerates locations first
	got, _, err := d.discoverCloudScheduler("")
	if err != nil {
		t.Fatal(err)
	}
	if !listed {
		t.Fatal("jobs.list was never called")
	}
	if len(got) != 1 || got[0].ResourceType != "capability.scheduler.cron" ||
		got[0].ProviderID != "gsched:acme-prod:europe-west1:rollup" {
		t.Fatalf("cloud scheduler discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["location.region"] != "europe-west1" || by["schedule.enabled"] != true {
		t.Errorf("cloud scheduler observations: %v", by)
	}
}

func TestDiscoverVPNGateways(t *testing.T) {
	var listed bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/aggregated/vpnGateways":
				listed = true
				w.Write([]byte(`{"items":{
				  "regions/europe-west1":{"vpnGateways":[{"name":"ha-gw"}]},
				  "regions/us-east1":{"vpnGateways":[{"name":"faraway"}]},
				  "regions/asia-east1":{"warning":{"code":"NO_RESULTS_ON_PAGE"}}
				}}`))
			case "/projects/acme-prod/regions/europe-west1/vpnGateways/ha-gw":
				w.Write([]byte(`{"stackType":"IPV4_IPV6"}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.ComputeBaseURL = srv.URL

	got, _, err := d.discoverVPNGateways("europe-west1")
	if err != nil {
		t.Fatal(err)
	}
	if !listed {
		t.Fatal("vpnGateways.aggregatedList was never called")
	}
	if len(got) != 1 || got[0].ResourceType != "capability.vpn.gateway" ||
		got[0].ProviderID != "gvpn:acme-prod:europe-west1:ha-gw" {
		t.Fatalf("vpn gateways discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["location.region"] != "europe-west1" || by["service.managed"] != true ||
		by["ip.stack"] != "dual-stack" {
		t.Errorf("vpn gateway observations: %v", by)
	}
}
