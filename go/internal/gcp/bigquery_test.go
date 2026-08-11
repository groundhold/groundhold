package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func bqReadBody(r *http.Request) map[string]any {
	b, _ := io.ReadAll(r.Body)
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

func bqAttrs() map[string]any {
	return map[string]any{
		"location.region":   "US",
		"encryption.atRest": true,
		"service.managed":   true,
	}
}

func TestBuildBigQueryHonors(t *testing.T) {
	p, err := BuildBigQueryDataset("acme-prod", "prod", "lake", bqAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bqDatasetIDOK.MatchString(p.DatasetID) || !strings.HasPrefix(p.DatasetID, "pv_lake_prod_") {
		t.Fatalf("dataset id = %q", p.DatasetID)
	}
	if p.Location != "US" || p.Labels["groundhold-capability"] != "lake" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.insertBody("acme-prod")
	if _, has := body["defaultEncryptionConfiguration"]; has {
		t.Fatalf("no CMK requested but encryption config present: %+v", body)
	}
}

func TestBuildBigQueryCMKRequiresKey(t *testing.T) {
	a := bqAttrs()
	a["encryption.customerManagedKeys"] = true
	if _, err := BuildBigQueryDataset("acme-prod", "prod", "lake", a, nil, 1); err == nil {
		t.Fatal("cmk without impl.kms_key_name must refuse")
	}
	p, err := BuildBigQueryDataset("acme-prod", "prod", "lake", a,
		map[string]any{"kms_key_name": "projects/p/locations/us/keyRings/r/cryptoKeys/k"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.KmsKeyName == "" {
		t.Fatal("cmk key not carried into plan")
	}
}

func TestBuildBigQueryRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"public-refused": {"network.publicExposure": true}, // honest gap: no network boundary
		"no-at-rest":     {"encryption.atRest": false},
		"unmanaged":      {"service.managed": false},
		"unknown-attr":   {"warehouse.tier": "x"},
	}
	for name, extra := range cases {
		a := bqAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildBigQueryDataset("acme-prod", "prod", "lake", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// location is mandatory
	if _, err := BuildBigQueryDataset("acme-prod", "prod", "lake",
		map[string]any{"service.managed": true}, nil, 1); err == nil {
		t.Error("missing location must refuse")
	}
}

func bqServer(t *testing.T, capLabel, location, kmsKey string) *httptest.Server {
	t.Helper()
	enc := ""
	if kmsKey != "" {
		enc = `,"defaultEncryptionConfiguration":{"kmsKeyName":"` + kmsKey + `"}`
	}
	doc := `{"datasetReference":{"datasetId":"pv_lake_prod_x","projectId":"acme-prod"},` +
		`"location":"` + location + `","labels":{"groundhold-capability":"` + capLabel +
		`","groundhold-environment":"prod"}` + enc + `}`
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/datasets"):
				_, _ = w.Write([]byte(doc))
			case r.Method == "GET":
				_, _ = w.Write([]byte(doc))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func bqDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.BQBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteBigQuery(t *testing.T) {
	srv := bqServer(t, "lake", "US", "projects/p/locations/us/keyRings/r/cryptoKeys/k")
	defer srv.Close()
	d := bqDriver(t, srv)
	a := bqAttrs()
	a["encryption.customerManagedKeys"] = true
	res := d.Create("bigquery", "lake", "prod", a,
		map[string]any{"kms_key_name": "projects/p/locations/us/keyRings/r/cryptoKeys/k"}, "k", 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "bqds:acme-prod:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeBigQuery("lake", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "us" || got["encryption.customerManagedKeys"] != true ||
		got["encryption.atRest"] != true || got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.Delete("bigquery", "lake", "prod", res.ProviderID, "k"); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteBigQueryForeignRefused(t *testing.T) {
	srv := bqServer(t, "someone-else", "US", "")
	defer srv.Close()
	d := bqDriver(t, srv)
	pid := bqProviderID("acme-prod", BQDatasetID("acme-prod", "prod", "lake", 1))
	res := d.Delete("bigquery", "lake", "prod", pid, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign dataset must refuse delete, got %+v", res)
	}
}

// Weapon 2 (D87): the metamorphic write/read round-trip for the warehouse location.
// A STATEFUL fake records the location the insert writes and reflects it on read.
func TestMetamorphicBigQueryRoundTrip(t *testing.T) {
	for _, loc := range []string{"US", "EU", "asia-northeast1"} {
		t.Run(loc, func(t *testing.T) {
			var location string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/datasets"):
						body := bqReadBody(r)
						location, _ = body["location"].(string)
						_, _ = w.Write([]byte(`{"datasetReference":{"datasetId":"pv_lake_prod_x","projectId":"acme-prod"},` +
							`"location":"` + location + `","labels":{"groundhold-capability":"lake","groundhold-environment":"prod"}}`))
					case r.Method == "GET":
						_, _ = w.Write([]byte(`{"datasetReference":{"datasetId":"pv_lake_prod_x","projectId":"acme-prod"},` +
							`"location":"` + location + `","labels":{"groundhold-capability":"lake","groundhold-environment":"prod"}}`))
					default:
						_, _ = w.Write([]byte(`{}`))
					}
				}))
			defer srv.Close()
			d := bqDriver(t, srv)
			a := bqAttrs()
			a["location.region"] = loc
			res := d.Create("bigquery", "lake", "prod", a, nil, "k", 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeBigQuery("lake", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["location.region"] != strings.ToLower(loc) {
				t.Errorf("location round-trip: want %q got %v", strings.ToLower(loc), got["location.region"])
			}
		})
	}
}

func gcpRESTRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingBigQuery enrols bigquery in the D391/D413 gate. A dataset id is
// deterministic, so a re-converge meets a 409 and the driver must recognise its own
// labels and bind rather than fail against an estate that is already correct.
func TestAdoptsExistingBigQuery(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	doc := `{"datasetReference":{"datasetId":"pv_lake_prod_x","projectId":"acme-prod"},` +
		`"location":"US","labels":{"groundhold-capability":"lake","groundhold-environment":"prod"}}`
	p := &certifynet.ExistingProbe{
		Name:     "gcp/bigquery",
		Classify: gcpRESTRole,
		ExistingServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/datasets"):
						w.WriteHeader(http.StatusConflict)
						_, _ = w.Write([]byte(`{"error":{"code":409,"message":"Already Exists"}}`))
					case r.Method == "GET":
						_, _ = w.Write([]byte(doc))
					default:
						w.WriteHeader(404)
					}
				}))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.BQBaseURL = happyURL
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("bigquery", "lake", "prod", bqAttrs(), nil, "k", 1)
		},
		AllowedMutations: 1, // the refused create
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
