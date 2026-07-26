package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.storage.filesystem on GCP Filestore. A STATEFUL fake records the
// tier and kmsKeyName createFilestore writes and reflects them on the observe
// read; the test varies (availability, cmek) and asserts observe reverse-maps
// what create was given — availability.class from the tier, CMEK from the key,
// and the NFS version derived from the tier. A driver that read the tier from
// the wrong field or inverted the CMEK flag fails here with no fault injected.
func metamorphicFilestoreServer(t *testing.T) *httptest.Server {
	t.Helper()
	var tier, kms string
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "instanceId="):
				body, _ := io.ReadAll(r.Body)
				var doc struct {
					Tier       string `json:"tier"`
					KmsKeyName string `json:"kmsKeyName"`
				}
				_ = json.Unmarshal(body, &doc)
				tier, kms = doc.Tier, doc.KmsKeyName
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op1"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "GET":
				out := map[string]any{
					"name":   "projects/acme-prod/locations/europe-west1/instances/x",
					"labels": map[string]any{"groundhold-capability": "shared", "groundhold-environment": "prod"},
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

func TestMetamorphicFilestoreRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		avail     string
		cmek      bool
		wantAvail string
		wantProto string
	}{
		{"zonal-nocmek", "zonal", false, "zonal", "nfs/3"},
		{"regional-cmek", "regional", true, "regional", "nfs/4.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicFilestoreServer(t)
			defer srv.Close()
			d := filestoreDriver(t, srv)
			a := map[string]any{
				"location.region":                "europe-west1",
				"protocol":                       "nfs/4.1",
				"availability.class":             c.avail,
				"encryption.atRest":              true,
				"encryption.customerManagedKeys": c.cmek,
				"service.managed":                true,
			}
			impl := map[string]any{}
			if c.cmek {
				impl["kms_key_name"] = "projects/acme-prod/locations/europe-west1/keyRings/r/cryptoKeys/k"
			}
			res := d.createFilestore("prod", "shared", a, impl, 1)
			if res.Status != "succeeded" {
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
			if got["availability.class"] != c.wantAvail {
				t.Errorf("availability round-trip: want %q got %v", c.wantAvail, got["availability.class"])
			}
			if got["protocol"] != c.wantProto {
				t.Errorf("protocol derivation: want %q got %v", c.wantProto, got["protocol"])
			}
			if _, has := got["encryption.customerManagedKeys"]; has != c.cmek {
				t.Errorf("cmek round-trip: want present=%v got %v", c.cmek, got["encryption.customerManagedKeys"])
			}
		})
	}
}
