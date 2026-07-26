package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func secretAttrs() map[string]any {
	return map[string]any{
		"location.region":                "europe-west1",
		"network.publicExposure":         false,
		"encryption.atRest":              true,
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	}
}

func secretImpl() map[string]any {
	return map[string]any{"kms_key_name": "projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k"}
}

func TestBuildSecretHonors(t *testing.T) {
	p, err := BuildSecretCreate("acme-prod", "prod", "dbcreds", secretAttrs(), secretImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Region != "europe-west1" || p.KmsKeyName == "" || p.Public {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("dbcreds", "prod")
	um := body["replication"].(map[string]any)["userManaged"].(map[string]any)
	if um["replicas"].([]any)[0].(map[string]any)["location"] != "europe-west1" {
		t.Fatalf("replica not pinned to region: %+v", um)
	}
}

func TestBuildSecretRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"location.region": "europe-west1", "encryption.atRest": true, "service.managed": true}
	}
	cases := map[string]map[string]any{
		"atRest-false": {"encryption.atRest": false},
		"unmanaged":    {"service.managed": false},
		"rotation":     {"rotation.enabled": true}, // refused: unknown attr (producer's job)
		"expiry":       {"expiry.after": "30d"},    // refused
		"value":        {"value": "hunter2"},       // refused: the value is data
	}
	for name, extra := range cases {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildSecretCreate("acme-prod", "prod", "dbcreds", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// CMK without key
	cmk := base()
	cmk["encryption.customerManagedKeys"] = true
	if _, err := BuildSecretCreate("acme-prod", "prod", "dbcreds", cmk, nil, 1); err == nil {
		t.Error("CMK without kms_key_name must refuse")
	}
	// missing region
	if _, err := BuildSecretCreate("acme-prod", "prod", "dbcreds", map[string]any{"encryption.atRest": true, "service.managed": true}, nil, 1); err == nil {
		t.Error("missing region must refuse (automatic replication is global)")
	}
}

func secretServer(t *testing.T, tagCap, replication string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "secretId="):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/secrets/x"}`))
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
				_, _ = w.Write([]byte(`{"etag":"abc","bindings":[]}`)) // not public
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/secrets/x",` +
					`"labels":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"replication":` + replication + `}`))
			case r.Method == "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func secretDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.SecretBaseURL = srv.URL
	return d
}

const umReplica = `{"userManaged":{"replicas":[{"location":"europe-west1","customerManagedEncryption":{"kmsKeyName":"projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k"}}]}}`

func TestCreateObserveDeleteSecret(t *testing.T) {
	srv := secretServer(t, "dbcreds", umReplica)
	defer srv.Close()
	d := secretDriver(t, srv)
	res := d.createSecret("dbcreds", "prod", secretAttrs(), secretImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "gsecret:acme-prod:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeSecret("dbcreds", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "europe-west1" || got["encryption.customerManagedKeys"] != true ||
		got["network.publicExposure"] != false {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteSecret("dbcreds", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestObserveSecretAutomaticReplicationRefusesRegion(t *testing.T) {
	srv := secretServer(t, "dbcreds", `{"automatic":{}}`)
	defer srv.Close()
	d := secretDriver(t, srv)
	obs, diags, err := d.observeSecret("dbcreds", "gsecret:acme-prod:x")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "location.region" {
			t.Fatalf("automatic replication must NOT report a region (residency lie): %+v", o)
		}
	}
	if len(diags) == 0 || !strings.Contains(strings.Join(diags, " "), "residency") {
		t.Fatalf("expected a residency diagnostic, got %v", diags)
	}
}

func TestDeleteSecretForeignRefused(t *testing.T) {
	srv := secretServer(t, "someone-else", umReplica)
	defer srv.Close()
	d := secretDriver(t, srv)
	res := d.deleteSecret("dbcreds", "prod", "gsecret:acme-prod:x")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign secret must refuse delete, got %+v", res)
	}
}
