package gcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fsAttrs() map[string]any {
	return map[string]any{
		"location.region":                "europe-west1",
		"protocol":                       "nfs/4.1",
		"availability.class":             "regional",
		"encryption.atRest":              true,
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	}
}

func fsImpl() map[string]any {
	return map[string]any{
		"network":      "prod-vpc",
		"kms_key_name": "projects/acme-prod/locations/europe-west1/keyRings/r/cryptoKeys/k",
		"capacity_gb":  2048,
	}
}

func TestBuildFilestoreHonors(t *testing.T) {
	p, err := BuildFilestoreCreate("acme-prod", "prod", "shared", fsAttrs(), fsImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Tier != "ENTERPRISE" || p.KmsKey == "" || p.Network != "prod-vpc" || p.CapacityGb != 2048 {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("shared", "prod")
	if body["tier"] != "ENTERPRISE" || body["kmsKeyName"] == nil {
		t.Fatalf("body = %+v", body)
	}
	shares, _ := body["fileShares"].([]any)
	if len(shares) != 1 {
		t.Fatalf("fileShares = %+v", body["fileShares"])
	}
}

func TestBuildFilestoreDefaults(t *testing.T) {
	a := map[string]any{
		"location.region": "europe-west1",
		"protocol":        "nfs/3",
		"service.managed": true,
	}
	p, err := BuildFilestoreCreate("acme-prod", "prod", "shared", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Tier != "BASIC_HDD" || p.Network != "default" || p.CapacityGb != 1024 {
		t.Fatalf("defaults = %+v", p)
	}
}

func TestBuildFilestoreRefusals(t *testing.T) {
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"smb-refused":  {map[string]any{"protocol": "smb/3"}, fsImpl()},        // no managed GCP SMB
		"atrest-false": {map[string]any{"encryption.atRest": false}, fsImpl()}, // always encrypted
		"cmek-no-key":  {map[string]any{"encryption.customerManagedKeys": true}, map[string]any{"network": "v"}},
		"unmanaged":    {map[string]any{"service.managed": false}, fsImpl()},
		"bad-avail":    {map[string]any{"availability.class": "planetary"}, fsImpl()},
		"unknown-attr": {map[string]any{"filesystem.tier": "x"}, fsImpl()},
		"bad-location": {map[string]any{"location.region": "Europe_West"}, fsImpl()},
	}
	for name, c := range cases {
		a := fsAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildFilestoreCreate("acme-prod", "prod", "shared", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := fsAttrs()
	delete(a, "location.region")
	if _, err := BuildFilestoreCreate("acme-prod", "prod", "shared", a, fsImpl(), 1); err == nil {
		t.Error("missing location.region must refuse")
	}
}

// filestoreServer is a stateless happy server: create/delete LRO, GET reflects a
// fixed owned instance.
func filestoreServer(t *testing.T, capLabel, tier, kms string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "instanceId="):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op1"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/opdel"}`))
			case r.Method == "GET":
				out := map[string]any{
					"name":   "projects/acme-prod/locations/europe-west1/instances/x",
					"labels": map[string]any{"groundhold-capability": capLabel, "groundhold-environment": "prod"},
					"tier":   tier,
				}
				if kms != "" {
					out["kmsKeyName"] = kms
				}
				b, _ := json.Marshal(out)
				_, _ = w.Write(b)
			default:
				w.WriteHeader(404)
			}
		}))
}

func filestoreDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.FilestoreBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteFilestore(t *testing.T) {
	srv := filestoreServer(t, "shared", "ENTERPRISE", "projects/acme-prod/locations/europe-west1/keyRings/r/cryptoKeys/k")
	defer srv.Close()
	d := filestoreDriver(t, srv)
	res := d.createFilestore("prod", "shared", fsAttrs(), fsImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "filestore:acme-prod:europe-west1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeFilestore("shared", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "europe-west1" || got["availability.class"] != "regional" ||
		got["encryption.customerManagedKeys"] != true || got["protocol"] != "nfs/4.1" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteFilestore("shared", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteFilestoreForeignRefused(t *testing.T) {
	srv := filestoreServer(t, "someone-else", "BASIC_HDD", "")
	defer srv.Close()
	d := filestoreDriver(t, srv)
	res := d.deleteFilestore("shared", "prod",
		filestoreProviderID("acme-prod", "europe-west1", resourceName("acme-prod", "prod", "shared", 1, 63)))
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign instance must refuse delete, got %+v", res)
	}
}
