package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
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

// umReplicaNoCMK is a single-region user-managed replica WITHOUT a customer key — a
// measured CMEK false, the dangerous direction for a CMEK-declaring candidate (D1062).
const umReplicaNoCMK = `{"userManaged":{"replicas":[{"location":"europe-west1"}]}}`

// gsecretAdoptServer serves an already-ours secret: secrets.create answers 409, the GET
// reports the given replication policy (CMEK on/off, region), and getIamPolicy reports a
// public allUsers grant iff public. Read-only past the refused create (D1062).
func gsecretAdoptServer(replica string, public bool) func() *httptest.Server {
	return func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "secretId="):
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":{"code":409,"message":"already exists"}}`))
				// readSecretPublic issues a GET on :getIamPolicy — match it BEFORE the
				// generic GET, or the secret doc is parsed as a policy (no bindings = false).
				case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
					if public {
						_, _ = w.Write([]byte(`{"etag":"abc","bindings":[{"role":"roles/secretmanager.secretAccessor","members":["allUsers"]}]}`))
					} else {
						_, _ = w.Write([]byte(`{"etag":"abc","bindings":[]}`))
					}
				case r.Method == "GET":
					_, _ = w.Write([]byte(`{"name":"projects/acme-prod/secrets/x",` +
						`"labels":{"groundhold-capability":"dbcreds","groundhold-environment":"prod"},` +
						`"replication":` + replica + `}`))
				default:
					w.WriteHeader(404)
				}
			}))
	}
}

// TestAdoptsExistingSecret enrols secretmanager in the D391/D413 gate. A secret id is
// deterministic; a re-converge against one that already exists must bind it rather than
// fail, and the labels are what license the binding. Nothing here reads or writes the
// secret VALUE — adoption binds the container, which is the whole point of keeping the
// payload out of this driver's create path.
func TestAdoptsExistingSecret(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ExistingProbe{
		Name:           "gcp/secretmanager",
		Classify:       gcpRESTRole,
		ExistingServer: gsecretAdoptServer(umReplica, false), // CMEK + private — matches secretAttrs
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.SecretBaseURL = happyURL
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("secretmanager", "dbcreds", "prod", secretAttrs(), secretImpl(), "k", 1)
		},
		AllowedMutations: 2, // the refused create + the IAM posture read/assert
		// D1062: CMEK lives in the immutable replication policy (a miss FAILS); public
		// exposure is re-assertable (a miss is unknown+bound, converge re-scopes it).
		AdoptControls: gsecretAdoptControls,
		MissingControl: []certifynet.ControlCase{
			// live secret is on a Google-managed key though we declared CMEK.
			{Path: "encryption.customerManagedKeys", Server: gsecretAdoptServer(umReplicaNoCMK, false),
				WantStatus: "failed", WantMutations: 2},
			// live secret is granted to allUsers though we declared private.
			{Path: "network.publicExposure", Server: gsecretAdoptServer(umReplica, true),
				WantStatus: "unknown", WantMutations: 2},
		},
		MoreSecure: gsecretAdoptServer(umReplica, false), // CMEK + private — adopts clean
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
