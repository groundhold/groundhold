package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// These golden discovery tests mirror TestListDiscoversExistingInstances: a
// fake GCP endpoint asserts the bearer List request and that each item is run
// through the SAME reverse map its Observe uses. Each discoverer is swept in
// isolation so a single service's shape is pinned on its own.

// obsByPath flattens Discovered observations to a path->value map.
func obsByPath(d provider.Discovered) map[string]any {
	m := map[string]any{}
	for _, o := range d.Observations {
		m[o.Path] = o.Value
	}
	return m
}

func requireBearer(t *testing.T, r *http.Request) {
	t.Helper()
	if r.Header.Get("Authorization") != "Bearer test-token" {
		t.Errorf("missing/wrong bearer on %s %s: %q", r.Method, r.URL.Path,
			r.Header.Get("Authorization"))
	}
}

func TestDiscoverCloudRun(t *testing.T) {
	var listed bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch {
			case r.URL.Path == "/projects/acme-prod/locations/-/services":
				listed = true
				w.Write([]byte(`{"services":[
				  {"name":"projects/acme-prod/locations/europe-west1/services/api"},
				  {"name":"projects/acme-prod/locations/us-east1/services/far"}
				]}`))
			case r.URL.Path == "/projects/acme-prod/locations/europe-west1/services/api":
				w.Write([]byte(`{"ingress":"INGRESS_TRAFFIC_INTERNAL_ONLY",
				  "invokerIamDisabled":true,
				  "template":{"scaling":{"minInstanceCount":2}}}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.RunBaseURL = srv.URL

	got, _, err := d.discoverCloudRun("europe-west1")
	if err != nil {
		t.Fatal(err)
	}
	if !listed {
		t.Fatal("services.list was never called")
	}
	if len(got) != 1 || got[0].ResourceType != "capability.workload.container" ||
		got[0].ProviderID != "cloudrun:acme-prod:europe-west1:api" {
		t.Fatalf("cloudrun discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["location.region"] != "europe-west1" || by["network.publicExposure"] != false {
		t.Errorf("cloudrun observations: %v", by)
	}
}

func TestDiscoverServiceAccounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/serviceAccounts":
				w.Write([]byte(`{"accounts":[
				  {"email":"app-runner@acme-prod.iam.gserviceaccount.com"},
				  {"email":"12345-compute@developer.gserviceaccount.com"}
				]}`))
			case "/projects/acme-prod/serviceAccounts/app-runner@acme-prod.iam.gserviceaccount.com":
				w.Write([]byte(`{"email":"app-runner@acme-prod.iam.gserviceaccount.com","displayName":"App SA"}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.IAMBaseURL = srv.URL

	got, _, err := d.discoverServiceAccounts("europe-west1")
	if err != nil {
		t.Fatal(err)
	}
	// only the project-domain account is addressable; the default-compute one is skipped
	if len(got) != 1 || got[0].ResourceType != "capability.identity.serviceaccount" ||
		got[0].ProviderID != "gsa:acme-prod:app-runner" {
		t.Fatalf("service accounts discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["service.managed"] != true || by["key.exportable"] != false || by["display.name"] != "App SA" {
		t.Errorf("service account observations: %v", by)
	}
}

func TestDiscoverCustomRoles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/roles":
				w.Write([]byte(`{"roles":[{"name":"projects/acme-prod/roles/appRole"}]}`))
			case "/projects/acme-prod/roles/appRole":
				w.Write([]byte(`{"name":"projects/acme-prod/roles/appRole",
				  "includedPermissions":["storage.objects.get"]}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.IAMBaseURL = srv.URL

	got, _, err := d.discoverCustomRoles("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ResourceType != "capability.authorization.role" ||
		got[0].ProviderID != "gcrole:acme-prod:appRole" {
		t.Fatalf("custom roles discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["service.managed"] != true {
		t.Errorf("custom role observations: %v", by)
	}
	perms, _ := by["role.permissions"].([]string)
	if len(perms) != 1 || perms[0] != "storage.objects.get" {
		t.Errorf("role.permissions: %v", by["role.permissions"])
	}
}

func TestDiscoverIAMBindings(t *testing.T) {
	policy := `{"bindings":[{"role":"roles/viewer","members":["user:alice@example.com","allUsers"]}]}`
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			if r.URL.Path == "/projects/acme-prod:getIamPolicy" && r.Method == "POST" {
				w.Write([]byte(policy))
				return
			}
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.CRMBaseURL = srv.URL

	got, diags, err := d.discoverIAMBindings("")
	if err != nil {
		t.Fatal(err)
	}
	// the parseable member is discovered; "allUsers" (no memberType:id form) is a diagnostic
	if len(got) != 1 || got[0].ResourceType != "capability.authorization.grant" ||
		got[0].ProviderID != "gauth:acme-prod:roles/viewer:user:alice@example.com" {
		t.Fatalf("iam bindings discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["grant.role"] != "roles/viewer" || by["grant.principal"] != "user:alice@example.com" {
		t.Errorf("iam binding observations: %v", by)
	}
	foundAllUsersDiag := false
	for _, dg := range diags {
		if strings.Contains(dg, "allUsers") {
			foundAllUsersDiag = true
		}
	}
	if !foundAllUsersDiag {
		t.Errorf("unparseable member should be a diagnostic, got: %v", diags)
	}
}

// D53 ABSOLUTE: secret discovery reads existence + metadata only. A request to
// any accessSecretVersion path FAILS the test — the value is never read.
func TestDiscoverSecretsMetadataOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			if strings.Contains(r.URL.Path, ":access") || strings.Contains(r.URL.Path, "/versions/") {
				t.Fatalf("D53 VIOLATION: discovery read a secret value: %s %s", r.Method, r.URL.Path)
			}
			switch {
			case r.URL.Path == "/projects/acme-prod/secrets":
				w.Write([]byte(`{"secrets":[{"name":"projects/acme-prod/secrets/db-password"}]}`))
			case r.URL.Path == "/projects/acme-prod/secrets/db-password":
				w.Write([]byte(`{"name":"projects/acme-prod/secrets/db-password",
				  "replication":{"userManaged":{"replicas":[{"location":"europe-west1"}]}}}`))
			case strings.HasSuffix(r.URL.Path, "/secrets/db-password:getIamPolicy"):
				w.Write([]byte(`{"bindings":[]}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.SecretBaseURL = srv.URL

	got, _, err := d.discoverSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ResourceType != "capability.secret" ||
		got[0].ProviderID != "gsecret:acme-prod:db-password" {
		t.Fatalf("secrets discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["service.managed"] != true || by["location.region"] != "europe-west1" ||
		by["network.publicExposure"] != false {
		t.Errorf("secret observations: %v", by)
	}
}

func TestDiscoverAlertPolicies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/alertPolicies":
				w.Write([]byte(`{"alertPolicies":[{"name":"projects/acme-prod/alertPolicies/1234"}]}`))
			case "/projects/acme-prod/alertPolicies/1234":
				w.Write([]byte(`{"conditions":[{"conditionThreshold":{
				  "filter":"metric.type=\"compute.googleapis.com/instance/cpu/utilization\"",
				  "comparison":"COMPARISON_GT","thresholdValue":0.8}}],
				  "notificationChannels":["projects/acme-prod/notificationChannels/x"]}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.MonitoringBaseURL = srv.URL

	got, _, err := d.discoverAlertPolicies("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ResourceType != "capability.monitoring.alert" ||
		got[0].ProviderID != "galert:acme-prod:1234" {
		t.Fatalf("alert policies discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["alert.threshold"] != 0.8 || by["alert.notify"] != true ||
		by["alert.comparison"] != "greater-than" {
		t.Errorf("alert policy observations: %v", by)
	}
}

func TestDiscoverUptimeChecks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch r.URL.Path {
			case "/projects/acme-prod/uptimeCheckConfigs":
				w.Write([]byte(`{"uptimeCheckConfigs":[{"name":"projects/acme-prod/uptimeCheckConfigs/home"}]}`))
			case "/projects/acme-prod/uptimeCheckConfigs/home":
				w.Write([]byte(`{"period":"60s",
				  "monitoredResource":{"labels":{"host":"example.com"}},
				  "httpCheck":{"path":"/health","useSsl":true}}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.UptimeBaseURL = srv.URL

	got, _, err := d.discoverUptimeChecks("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ResourceType != "capability.monitoring.uptime" ||
		got[0].ProviderID != "guptime:acme-prod:home" {
		t.Fatalf("uptime checks discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["check.target"] != "example.com" || by["check.protocol"] != "https" ||
		by["check.path"] != "/health" || by["check.period"] != "60s" {
		t.Errorf("uptime observations: %v", by)
	}
}

func TestDiscoverArtifactRegistries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch {
			case r.URL.Path == "/projects/acme-prod/locations":
				w.Write([]byte(`{"locations":[{"locationId":"europe-west1"}]}`))
			case r.URL.Path == "/projects/acme-prod/locations/europe-west1/repositories":
				w.Write([]byte(`{"repositories":[{"name":"projects/acme-prod/locations/europe-west1/repositories/images"}]}`))
			case r.URL.Path == "/projects/acme-prod/locations/europe-west1/repositories/images":
				w.Write([]byte(`{"format":"DOCKER","dockerConfig":{"immutableTags":true}}`))
			case strings.HasSuffix(r.URL.Path, "/repositories/images:getIamPolicy"):
				w.Write([]byte(`{"bindings":[]}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.ARBaseURL = srv.URL

	// empty region enumerates locations first
	got, _, err := d.discoverArtifactRegistries("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ResourceType != "capability.registry.image" ||
		got[0].ProviderID != "gar:acme-prod:europe-west1:images" {
		t.Fatalf("artifact registries discovered: %+v", got)
	}
	by := obsByPath(got[0])
	if by["location.region"] != "europe-west1" || by["immutable.tags"] != true ||
		by["network.publicExposure"] != false {
		t.Errorf("registry observations: %v", by)
	}
}

func TestDiscoverVPC(t *testing.T) {
	link := "https://www.googleapis.com/compute/v1/projects/acme-prod/regions/europe-west1/subnetworks/prod-subnet"
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			switch {
			case r.URL.Path == "/projects/acme-prod/global/networks":
				w.Write([]byte(`{"items":[{"name":"prod-vpc","subnetworks":["` + link + `"]}]}`))
			case r.URL.Path == "/projects/acme-prod/global/networks/prod-vpc":
				w.Write([]byte(`{"subnetworks":["` + link + `"]}`))
			case r.URL.Path == "/projects/acme-prod/regions/europe-west1/subnetworks/prod-subnet":
				w.Write([]byte(`{"description":"","logConfig":{"enable":true}}`))
			case r.URL.Path == "/projects/acme-prod/global/firewalls":
				w.Write([]byte(`{"items":[]}`))
			case r.URL.Path == "/projects/acme-prod/regions/europe-west1/routers":
				// observe reads the egress ROAD (egress.internet) from the regional
				// Cloud Routers — none here, so the road derives to "none".
				w.Write([]byte(`{"items":[]}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.ComputeBaseURL = srv.URL

	got, _, err := d.discoverVPC("europe-west1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ResourceType != "capability.network.private" ||
		got[0].ProviderID != "vpc:acme-prod:europe-west1:prod-vpc" {
		t.Fatalf("vpc discovered: %+v", got)
	}
	by := obsByPath(got[0])
	// firewall-derived posture is capability-independent, so it is measured
	// even without an ownership marker; egress/ingress both closed here.
	if by["service.managed"] != true || by["egress.restricted"] != false ||
		by["ingress.public"] != false {
		t.Errorf("vpc observations: %v", by)
	}
}
