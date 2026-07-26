package gcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Golden discovery tests for gap batch A. Each mirrors discover_gcp_ext_test.go:
// a fake bearer-authenticated GCP endpoint serves a canned List (+ observe)
// payload, asserts the List path was hit, and asserts each item is run through
// the SAME reverse map its Observe uses. Each discoverer is swept in isolation.

func TestDiscoverBigQuery(t *testing.T) {
	var listed bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/datasets":
				listed = true
				w.Write([]byte(`{"datasets":[
				  {"datasetReference":{"datasetId":"analytics"},"location":"europe-west1"},
				  {"datasetReference":{"datasetId":"faraway"},"location":"us-east1"}
				]}`))
			case "/projects/acme-prod/datasets/analytics":
				w.Write([]byte(`{"datasetReference":{"datasetId":"analytics","projectId":"acme-prod"},
				  "location":"europe-west1"}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.BQBaseURL = srv.URL

	got, _, err := d.discoverBigQuery("europe-west1")
	if err != nil {
		t.Fatal(err)
	}
	if !listed {
		t.Fatal("datasets.list was never called")
	}
	if len(got) != 1 || got[0].ResourceType != "capability.warehouse.analytics" ||
		got[0].ProviderID != "bqds:acme-prod:analytics" {
		t.Fatalf("bigquery discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["location.region"] != "europe-west1" || by["encryption.atRest"] != true ||
		by["service.managed"] != true {
		t.Errorf("bigquery observations: %v", by)
	}
}

func TestDiscoverCloudArmor(t *testing.T) {
	var listed bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/global/securityPolicies":
				listed = true
				w.Write([]byte(`{"items":[{"name":"edge-waf"}]}`))
			case "/projects/acme-prod/global/securityPolicies/edge-waf":
				w.Write([]byte(`{"rules":[{"action":"deny(403)","preview":false,
				  "match":{"expr":{"expression":"evaluatePreconfiguredWaf('sqli-v33-stable')"}}}],
				  "adaptiveProtectionConfig":{"layer7DdosDefenseConfig":{"enable":true}}}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.ComputeBaseURL = srv.URL

	got, _, err := d.discoverCloudArmor("europe-west1")
	if err != nil {
		t.Fatal(err)
	}
	if !listed {
		t.Fatal("securityPolicies.list was never called")
	}
	if len(got) != 1 || got[0].ResourceType != "capability.security.waf" ||
		got[0].ProviderID != "armor:acme-prod:edge-waf" {
		t.Fatalf("cloud armor discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["service.managed"] != true || by["policy.mode"] != "prevention" ||
		by["managed.ruleset"] != true || by["bot.protection"] != true {
		t.Errorf("cloud armor observations: %v", by)
	}
}

func TestDiscoverCloudDNS(t *testing.T) {
	var listed bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/managedZones":
				listed = true
				w.Write([]byte(`{"managedZones":[{"name":"prod-zone"}]}`))
			case "/projects/acme-prod/managedZones/prod-zone":
				w.Write([]byte(`{"name":"prod-zone","dnsName":"example.com.",
				  "visibility":"public","dnssecConfig":{"state":"on"}}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.DNSBaseURL = srv.URL

	got, _, err := d.discoverCloudDNS("")
	if err != nil {
		t.Fatal(err)
	}
	if !listed {
		t.Fatal("managedZones.list was never called")
	}
	if len(got) != 1 || got[0].ResourceType != "capability.dns.zone" ||
		got[0].ProviderID != "gdns:acme-prod:prod-zone" {
		t.Fatalf("cloud dns discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["service.managed"] != true || by["zone.domain"] != "example.com" ||
		by["network.publicExposure"] != true || by["dnssec.enabled"] != true {
		t.Errorf("cloud dns observations: %v", by)
	}
}

func TestDiscoverCloudFunctions(t *testing.T) {
	var listed bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/locations/-/functions":
				listed = true
				w.Write([]byte(`{"functions":[
				  {"name":"projects/acme-prod/locations/europe-west1/functions/handler"},
				  {"name":"projects/acme-prod/locations/us-east1/functions/faraway"}
				]}`))
			case "/projects/acme-prod/locations/europe-west1/functions/handler":
				// ALLOW_INTERNAL_ONLY: publicExposure resolves false without any
				// backing-service IAM read.
				w.Write([]byte(`{"serviceConfig":{"ingressSettings":"ALLOW_INTERNAL_ONLY",
				  "minInstanceCount":1}}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.CfBaseURL = srv.URL

	got, _, err := d.discoverCloudFunctions("europe-west1")
	if err != nil {
		t.Fatal(err)
	}
	if !listed {
		t.Fatal("functions.list was never called")
	}
	if len(got) != 1 || got[0].ResourceType != "capability.workload.container" ||
		got[0].ProviderID != "cloudfunctions:acme-prod:europe-west1:handler" {
		t.Fatalf("cloud functions discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["location.region"] != "europe-west1" || by["service.managed"] != true ||
		by["network.publicExposure"] != false {
		t.Errorf("cloud functions observations: %v", by)
	}
}

func TestDiscoverCertManager(t *testing.T) {
	var listed bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/locations":
				w.Write([]byte(`{"locations":[{"locationId":"global"}]}`))
			case "/projects/acme-prod/locations/global/certificates":
				listed = true
				w.Write([]byte(`{"certificates":[
				  {"name":"projects/acme-prod/locations/global/certificates/site-cert"}
				]}`))
			case "/projects/acme-prod/locations/global/certificates/site-cert":
				w.Write([]byte(`{"name":"projects/acme-prod/locations/global/certificates/site-cert",
				  "managed":{"domains":["example.com"],"state":"ACTIVE"}}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.CertManagerBaseURL = srv.URL

	// empty region enumerates locations first
	got, _, err := d.discoverCertManager("")
	if err != nil {
		t.Fatal(err)
	}
	if !listed {
		t.Fatal("certificates.list was never called")
	}
	if len(got) != 1 || got[0].ResourceType != "capability.certificate.tls" ||
		got[0].ProviderID != "gcert:acme-prod:global:site-cert" {
		t.Fatalf("cert manager discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["location.region"] != "global" || by["service.managed"] != true ||
		by["domain"] != "example.com" || by["validation.method"] != "dns" {
		t.Errorf("cert manager observations: %v", by)
	}
}

func TestDiscoverBackupVault(t *testing.T) {
	var listed bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/locations/europe-west1/backupVaults":
				listed = true
				w.Write([]byte(`{"backupVaults":[
				  {"name":"projects/acme-prod/locations/europe-west1/backupVaults/nightly"}
				]}`))
			case "/projects/acme-prod/locations/europe-west1/backupVaults/nightly":
				w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/backupVaults/nightly",
				  "backupMinimumEnforcedRetentionDuration":"2592000s"}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.BackupDRBaseURL = srv.URL

	// a given region is swept directly (no locations enumeration)
	got, _, err := d.discoverBackupVault("europe-west1")
	if err != nil {
		t.Fatal(err)
	}
	if !listed {
		t.Fatal("backupVaults.list was never called")
	}
	if len(got) != 1 || got[0].ResourceType != "capability.backup.vault" ||
		got[0].ProviderID != "gbkv:acme-prod:europe-west1:nightly" {
		t.Fatalf("backup vault discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["location.region"] != "europe-west1" || by["service.managed"] != true ||
		by["retention.lockMode"] != "compliance" || by["retention.minimum"] != "2592000s" {
		t.Errorf("backup vault observations: %v", by)
	}
}

func TestDiscoverCloudKMS(t *testing.T) {
	var ringsListed, keysListed bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/locations/europe-west1/keyRings":
				ringsListed = true
				w.Write([]byte(`{"keyRings":[
				  {"name":"projects/acme-prod/locations/europe-west1/keyRings/app-ring"}
				]}`))
			case "/projects/acme-prod/locations/europe-west1/keyRings/app-ring/cryptoKeys":
				keysListed = true
				w.Write([]byte(`{"cryptoKeys":[
				  {"name":"projects/acme-prod/locations/europe-west1/keyRings/app-ring/cryptoKeys/data-key"}
				]}`))
			case "/projects/acme-prod/locations/europe-west1/keyRings/app-ring/cryptoKeys/data-key":
				w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/keyRings/app-ring/cryptoKeys/data-key",
				  "rotationPeriod":"2592000s","versionTemplate":{"protectionLevel":"HSM"}}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.KMSBaseURL = srv.URL

	// a given region is swept directly (no locations enumeration)
	got, _, err := d.discoverCloudKMS("europe-west1")
	if err != nil {
		t.Fatal(err)
	}
	if !ringsListed || !keysListed {
		t.Fatalf("keyRings.list=%v cryptoKeys.list=%v — both must be called", ringsListed, keysListed)
	}
	if len(got) != 1 || got[0].ResourceType != "capability.key.encryption" ||
		got[0].ProviderID != "gkms:acme-prod:europe-west1:app-ring:data-key" {
		t.Fatalf("cloud kms discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["location.region"] != "europe-west1" || by["service.managed"] != true ||
		by["rotation.period"] != "2592000s" || by["protection.level"] != "hsm" {
		t.Errorf("cloud kms observations: %v", by)
	}
}
