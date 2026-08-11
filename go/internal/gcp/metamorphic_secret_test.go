package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for capability.secret on
// GCP Secret Manager. A STATEFUL fake records what createSecret writes (the
// userManaged replica region + CMEK, and the public IAM grant) and reflects it on
// the observe reads; the test varies (public, cmek) and asserts observeSecret
// returns the same semantic attributes create was given. A driver that read the
// region from the wrong replica element, inverted public exposure, or dropped CMEK
// fails here with no fault injected. Residency is the crown: an automatic-
// replication secret carries NO region, so this slice fixes userManaged and proves
// the region survives the round-trip.
func metamorphicSecretServer(t *testing.T) *httptest.Server {
	t.Helper()
	var region, kms string
	public := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch {
			// ---- create: record the replication (region + CMEK) ----
			case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "secretId="):
				var doc struct {
					Replication struct {
						UserManaged struct {
							Replicas []struct {
								Location                  string `json:"location"`
								CustomerManagedEncryption *struct {
									KmsKeyName string `json:"kmsKeyName"`
								} `json:"customerManagedEncryption"`
							} `json:"replicas"`
						} `json:"userManaged"`
					} `json:"replication"`
				}
				_ = json.Unmarshal(body, &doc)
				if len(doc.Replication.UserManaged.Replicas) == 1 {
					region = doc.Replication.UserManaged.Replicas[0].Location
					if e := doc.Replication.UserManaged.Replicas[0].CustomerManagedEncryption; e != nil {
						kms = e.KmsKeyName
					}
				}
				_, _ = w.Write([]byte(`{"name":"projects/acme/secrets/x"}`))
			// ---- setIamPolicy: record public if allUsers appears ----
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
				if strings.Contains(string(body), "allUsers") {
					public = true
				}
				_, _ = w.Write([]byte(`{"etag":"e"}`))
			// ---- getIamPolicy: reflect the recorded public state ----
			// D718: GET, the method Google routes. This case read POST, so the fixture
			// was a double for a cloud that does not exist: measured against the real
			// endpoint, POST on this path is a 404 and only GET is a route.
			case r.Method == "GET" && strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
				if public {
					_, _ = w.Write([]byte(`{"etag":"e","bindings":[{"role":"roles/secretmanager.secretAccessor","members":["allUsers"]}]}`))
				} else {
					_, _ = w.Write([]byte(`{"etag":"e","bindings":[]}`))
				}
			// ---- get: reflect the recorded replication ----
			case r.Method == "GET":
				replica := `{"location":"` + region + `"`
				if kms != "" {
					replica += `,"customerManagedEncryption":{"kmsKeyName":"` + kms + `"}`
				}
				replica += `}`
				_, _ = w.Write([]byte(`{"name":"projects/acme/secrets/x",` +
					`"labels":{"groundhold-capability":"dbcreds","groundhold-environment":"prod"},` +
					`"replication":{"userManaged":{"replicas":[` + replica + `]}}}`))
			default:
				t.Errorf("fixture asked for %s %s — Secret Manager has no such route, or "+
					"the test has outgrown the fixture", r.Method, r.URL.EscapedPath())
				w.WriteHeader(404)
			}
		}))
}

func TestMetamorphicSecretRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		public bool
		cmek   bool
	}{
		{"private-nocmek", false, false},
		{"public-nocmek", true, false},
		{"private-cmek", false, true},
		{"public-cmek", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicSecretServer(t)
			defer srv.Close()
			d := secretDriver(t, srv)
			attrs := map[string]any{
				"location.region":                "europe-west1",
				"network.publicExposure":         c.public,
				"encryption.atRest":              true,
				"encryption.customerManagedKeys": c.cmek,
				"service.managed":                true,
			}
			var impl map[string]any
			if c.cmek {
				impl = secretImpl()
			}
			res := d.createSecret("dbcreds", "prod", attrs, impl, 1)
			if res.Status != "succeeded" {
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
			if got["location.region"] != "europe-west1" {
				t.Errorf("region did not survive round-trip: %+v", got)
			}
			if got["network.publicExposure"] != c.public {
				t.Errorf("public exposure %v not reflected: %+v", c.public, got)
			}
			// D1003: on a single-replica user-managed secret CMK is measured, so no
			// key is a measured false (not an absence).
			if got["encryption.customerManagedKeys"] != c.cmek {
				t.Errorf("CMEK %v not reflected: %+v", c.cmek, got)
			}
		})
	}
}
