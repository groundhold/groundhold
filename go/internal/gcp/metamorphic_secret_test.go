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
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
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
			// CMEK is observed only when present (absent-key emits no false claim).
			if c.cmek && got["encryption.customerManagedKeys"] != true {
				t.Errorf("CMEK true not reflected: %+v", got)
			}
			if !c.cmek {
				if _, claimed := got["encryption.customerManagedKeys"]; claimed {
					t.Errorf("CMEK false must not be claimed: %+v", got)
				}
			}
		})
	}
}
