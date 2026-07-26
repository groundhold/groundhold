package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func flexAttrs() map[string]any {
	return map[string]any{
		"engine.protocol":        "postgresql/16",
		"location.region":        "eastus",
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"encryption.inTransit":   true,
		"recovery.rpo":           "7d",
		"availability.class":     "regional",
		"service.managed":        true,
	}
}

func flexImpl() map[string]any {
	return map[string]any{"admin_username": "pgadmin", "admin_password": "S3cret!pw", "resource_group": "rg1"}
}

func TestBuildFlexServerHonors(t *testing.T) {
	p, err := BuildFlexServer("prod", "db", flexAttrs(), flexImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != "16" || p.PublicAccess || !p.ZoneRedundant || p.BackupRetentionDays != 7 {
		t.Fatalf("plan = %+v", p)
	}
	if p.AdminUser != "pgadmin" {
		t.Fatalf("admin = %+v", p)
	}
}

func TestBuildFlexServerRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"engine.protocol": "postgresql/16", "location.region": "eastus", "service.managed": true}
	}
	// admin missing
	if _, err := BuildFlexServer("prod", "db", base(), map[string]any{"resource_group": "rg1"}, 1); err == nil {
		t.Error("missing admin creds must refuse")
	}
	cases := map[string]map[string]any{
		"mysql":           {"engine.protocol": "mysql/8.0"},
		"atRest-false":    {"encryption.atRest": false},
		"inTransit-false": {"encryption.inTransit": false},
		"rpo-too-long":    {"recovery.rpo": "60d"},
		"multi-regional":  {"availability.class": "multi-regional"},
		"unknown":         {"versioning.enabled": true},
	}
	for name, extra := range cases {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildFlexServer("prod", "db", a, flexImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// CMK without keys
	cmk := base()
	cmk["encryption.customerManagedKeys"] = true
	if _, err := BuildFlexServer("prod", "db", cmk, flexImpl(), 1); err == nil {
		t.Error("CMK without keys must refuse")
	}
	// missing engine
	if _, err := BuildFlexServer("prod", "db", map[string]any{"location.region": "eastus", "service.managed": true}, flexImpl(), 1); err == nil {
		t.Error("missing engine.protocol must refuse")
	}
}

func flexArmFake(t *testing.T, tagCap string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(202)
				_, _ = w.Write([]byte(`{"properties":{"state":"Creating"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"properties":{"state":"Ready","version":"16",` +
					`"network":{"publicNetworkAccess":"Disabled"},` +
					`"backup":{"backupRetentionDays":7},"highAvailability":{"mode":"ZoneRedundant"}}}`))
			case "DELETE":
				w.WriteHeader(202)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestCreateObserveDeleteFlexServer(t *testing.T) {
	srv := flexArmFake(t, "db")
	defer srv.Close()
	d := vnetTestDriver(t, srv)

	res := d.createFlexServer("prod", "db", flexAttrs(), flexImpl(), 1)
	if res.Status != "succeeded" || res.ProviderID == "" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeFlexServer("db", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["engine.protocol"] != "postgresql/16" || got["network.publicExposure"] != false ||
		got["availability.class"] != "regional" || got["encryption.inTransit"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteFlexServer("db", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteFlexServerForeignRefused(t *testing.T) {
	srv := flexArmFake(t, "someone-else")
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	pid := flexProviderID(testSub, "rg1", flexServerName("prod", "db", 1))
	res := d.deleteFlexServer("db", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign server must refuse delete, got %+v", res)
	}
}

// TestCreateFlexServerAdoptsExistingSkipsPUT pins D256: an existing OURS flexible
// server is ADOPTED (bound) without a re-PUT — the create body carries the admin
// password, so a re-PUT on a lost-ledger self-adopt would RESET it. Any mutation
// is a test failure.
func TestCreateFlexServerAdoptsExistingSkipsPUT(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"location":"eastus","tags":{"groundhold-capability":"db","groundhold-environment":"prod"},"properties":{"state":"Ready"}}`))
			return
		}
		t.Errorf("adopt must not %s — bind the existing server without re-PUTting (a re-PUT resets the admin password)", r.Method)
		w.WriteHeader(400)
	}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	res := d.createFlexServer("prod", "db", flexAttrs(), flexImpl(), 1)
	want := flexProviderID(testSub, "rg1", flexServerName("prod", "db", 1))
	if res.Status != "succeeded" || res.ProviderID != want {
		t.Fatalf("must adopt the existing owned server (no PUT), got %+v", res)
	}
}
