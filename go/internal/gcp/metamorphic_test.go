package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Weapon 2 (D87) for the GCP drivers — the metamorphic write/read round-trip,
// the DERIVED oracle for the class fault injection is blind to: semantic field
// mis-mapping and silent field drops. Each stateful fake records what Create
// WRITES (the insert body) and reflects it on the Observe reads; the test
// asserts Observe reverse-maps the SAME semantic attributes Create was given. A
// driver that reads availabilityType from the wrong element, inverts exposure,
// or drops versioning fails here without any fault injected.

// ---------------------------------------------------------------------------
// Cloud SQL (capability.database.relational)
// ---------------------------------------------------------------------------

// metamorphicCloudSQLServer records the instances.insert body and reflects it on
// instances.get, synthesizing ipAddresses evidence consistent with the recorded
// ipv4Enabled so observeExposure has the state surface it demands.
func metamorphicCloudSQLServer(t *testing.T) *httptest.Server {
	t.Helper()
	var inserted map[string]any
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case r.Method == "POST" && strings.HasSuffix(p, "/instances"):
				raw, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(raw, &inserted)
				_, _ = w.Write([]byte(`{"name":"op1"}`))
			case r.Method == "GET" && strings.Contains(p, "/operations/"):
				_, _ = w.Write([]byte(`{"status":"DONE"}`))
			case r.Method == "GET" && strings.Contains(p, "/instances/"):
				resp := map[string]any{}
				for k, v := range inserted {
					resp[k] = v
				}
				settings, _ := inserted["settings"].(map[string]any)
				ipc, _ := settings["ipConfiguration"].(map[string]any)
				ipv4, _ := ipc["ipv4Enabled"].(bool)
				if ipv4 {
					resp["ipAddresses"] = []any{map[string]any{"type": "PRIMARY", "ipAddress": "34.1.2.3"}}
				} else {
					resp["ipAddresses"] = []any{map[string]any{"type": "PRIVATE", "ipAddress": "10.1.2.3"}}
				}
				_ = json.NewEncoder(w).Encode(resp)
			default:
				w.WriteHeader(500)
			}
		}))
}

func TestMetamorphicCloudSQLRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		public bool
		class  string // "zonal" | "regional"
		proto  string
		region string
	}{
		{"public-regional-postgres", true, "regional", "postgresql/16", "europe-west1"},
		{"private-zonal-mysql", false, "zonal", "mysql/8.0", "us-east1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicCloudSQLServer(t)
			defer srv.Close()
			t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
			d := NewDriver("acme-prod")
			d.BaseURL = srv.URL
			d.PollInterval = 0

			attrs := map[string]any{
				"engine.protocol":        c.proto,
				"location.region":        c.region,
				"network.publicExposure": c.public,
				"availability.class":     c.class,
				"encryption.atRest":      true,
				"service.managed":        true,
			}
			impl := map[string]any{"tier": "db-custom-2-8192"}
			if !c.public {
				impl["network"] = map[string]any{
					"privateNetwork": "projects/acme-prod/global/networks/vpc"}
			}
			res := d.Create("cloudsql", "orders", "prod", attrs, impl, "", 1)
			if res.Status != "succeeded" {
				t.Fatalf("create failed: %+v", res)
			}
			obs, _, err := d.Observe("cloudsql", "orders", res.ProviderID)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["network.publicExposure"] != c.public {
				t.Errorf("public-exposure round-trip broke: wrote %v, observed %v", c.public, got["network.publicExposure"])
			}
			if got["availability.class"] != c.class {
				t.Errorf("availability.class round-trip broke: wrote %v, observed %v", c.class, got["availability.class"])
			}
			if got["engine.protocol"] != c.proto {
				t.Errorf("engine.protocol round-trip broke: wrote %v, observed %v", c.proto, got["engine.protocol"])
			}
			if got["location.region"] != c.region {
				t.Errorf("region round-trip broke: wrote %v, observed %v", c.region, got["location.region"])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GCS (capability.storage.object)
// ---------------------------------------------------------------------------

// metamorphicGCSServer records the bucket-insert body and reflects it on
// buckets.get; IAM is stateful (an allUsers objectViewer binding appears only
// after the PUT) so a public create's grant-and-confirm runs end to end.
func metamorphicGCSServer(t *testing.T) *httptest.Server {
	t.Helper()
	var inserted map[string]any
	granted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case strings.HasSuffix(p, "/iam") && r.Method == "GET":
				if granted {
					_, _ = w.Write([]byte(`{"etag":"e1","version":3,"bindings":[` +
						`{"role":"roles/storage.objectViewer","members":["allUsers"]}]}`))
				} else {
					_, _ = w.Write([]byte(`{"etag":"e1","version":3,"bindings":[]}`))
				}
			case strings.HasSuffix(p, "/iam") && r.Method == "PUT":
				granted = true
				_, _ = w.Write([]byte(`{"etag":"e2"}`))
			case r.Method == "POST" && strings.HasSuffix(p, "/b"):
				raw, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(raw, &inserted)
				name, _ := inserted["name"].(string)
				_ = json.NewEncoder(w).Encode(map[string]any{"name": name})
			case r.Method == "GET": // buckets.get
				resp := map[string]any{"projectNumber": "111", "metageneration": "1"}
				for k, v := range inserted {
					resp[k] = v
				}
				_ = json.NewEncoder(w).Encode(resp)
			default:
				w.WriteHeader(500)
			}
		}))
}

func TestMetamorphicGCSRoundTrip(t *testing.T) {
	cases := []struct {
		name       string
		public     bool
		versioning bool
		region     string
	}{
		{"public-versioned", true, true, "europe-central2"},
		{"private-unversioned", false, false, "us-central1"},
		{"private-versioned", false, true, "asia-east1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicGCSServer(t)
			defer srv.Close()
			t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
			d := NewDriver("acme-prod")
			d.GcsBaseURL = srv.URL
			d.ProjNumber = "111"

			attrs := map[string]any{
				"location.region":        c.region,
				"network.publicExposure": c.public,
				"versioning.enabled":     c.versioning,
				"encryption.atRest":      true,
				"service.managed":        true,
			}
			res := d.Create("gcs", "assets", "prod", attrs, nil, "", 1)
			if res.Status != "succeeded" {
				t.Fatalf("create failed: %+v", res)
			}
			obs, diags, err := d.Observe("gcs", "assets", res.ProviderID)
			if err != nil {
				t.Fatalf("observe: %v (diags %v)", err, diags)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["network.publicExposure"] != c.public {
				t.Errorf("public-exposure round-trip broke: wrote %v, observed %v (diags %v)", c.public, got["network.publicExposure"], diags)
			}
			if got["versioning.enabled"] != c.versioning {
				t.Errorf("versioning round-trip broke: wrote %v, observed %v", c.versioning, got["versioning.enabled"])
			}
			if got["location.region"] != c.region {
				t.Errorf("region round-trip broke: wrote %v, observed %v", c.region, got["location.region"])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cloud Run (capability.workload.container)
// ---------------------------------------------------------------------------

// metamorphicCloudRunServer records the services.create body's ingress and
// reflects it on services.get; IAM is stateful so a public service's allUsers
// invoker grant-and-confirm runs end to end.
func metamorphicCloudRunServer(t *testing.T) *httptest.Server {
	t.Helper()
	var inserted map[string]any
	granted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case strings.HasSuffix(p, ":getIamPolicy"):
				if granted {
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[` +
						`{"role":"roles/run.invoker","members":["allUsers"]}]}`))
				} else {
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[]}`))
				}
			case strings.HasSuffix(p, ":setIamPolicy"):
				granted = true
				_, _ = w.Write([]byte(`{"etag":"e2"}`))
			case r.Method == "POST" && strings.HasSuffix(p, "/services"):
				raw, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(raw, &inserted)
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-central2/operations/op1"}`))
			case strings.Contains(p, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "GET": // services.get
				resp := map[string]any{"uri": "https://svc-fake.a.run.app"}
				for k, v := range inserted {
					resp[k] = v
				}
				_ = json.NewEncoder(w).Encode(resp)
			default:
				w.WriteHeader(500)
			}
		}))
}

func TestMetamorphicCloudRunRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		public bool
	}{
		{"public", true},
		{"private", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicCloudRunServer(t)
			defer srv.Close()
			t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
			d := NewDriver("acme-prod")
			d.RunBaseURL = srv.URL
			d.PollInterval = 0

			attrs := map[string]any{
				"location.region":        "europe-central2",
				"network.publicExposure": c.public,
				"availability.class":     "regional",
				"service.managed":        true,
			}
			impl := map[string]any{"image": "gcr.io/x/img@sha256:abc"}
			res := d.Create("cloudrun", "be", "prod", attrs, impl, "", 1)
			if res.Status != "succeeded" {
				t.Fatalf("create failed: %+v", res)
			}
			obs, diags, err := d.Observe("cloudrun", "be", res.ProviderID)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["network.publicExposure"] != c.public {
				t.Errorf("public-exposure round-trip broke: wrote %v, observed %v (diags %v)", c.public, got["network.publicExposure"], diags)
			}
			if got["location.region"] != "europe-central2" {
				t.Errorf("region round-trip broke: observed %v", got["location.region"])
			}
			// availability.class is regional-by-construction (create refuses any
			// other value); assert it, but it is a constant, not a round-tripper.
			if got["availability.class"] != "regional" {
				t.Errorf("availability.class must observe regional, got %v", got["availability.class"])
			}
		})
	}
}
