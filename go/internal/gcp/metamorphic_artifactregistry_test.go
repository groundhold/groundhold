package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for capability.registry.image on
// GCP Artifact Registry. A stateful fake records immutableTags + kmsKeyName the create
// writes and reflects them on observe; the test varies immutability and CMEK and asserts
// observe reverse-maps them. A driver that dropped immutableTags or inverted the CMEK bit
// fails here with no fault injected.
func metamorphicARServer(t *testing.T) *httptest.Server {
	t.Helper()
	var immutable bool
	var kms string
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/repositories"):
				body, _ := io.ReadAll(r.Body)
				var doc struct {
					KmsKeyName   string `json:"kmsKeyName"`
					DockerConfig struct {
						ImmutableTags bool `json:"immutableTags"`
					} `json:"dockerConfig"`
				}
				_ = json.Unmarshal(body, &doc)
				immutable, kms = doc.DockerConfig.ImmutableTags, doc.KmsKeyName
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op1"}`))
			case strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "GET":
				b, _ := json.Marshal(map[string]any{
					"format": "DOCKER", "kmsKeyName": kms,
					"dockerConfig": map[string]any{"immutableTags": immutable},
					"labels":       map[string]any{"groundhold-capability": "images", "groundhold-environment": "prod"},
				})
				_, _ = w.Write(b)
			default:
				_, _ = w.Write([]byte(`{}`))
			}
		}))
}

func TestMetamorphicARRepoRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		immutable bool
		cmek      bool
	}{
		{"immutable-cmek", true, true},
		{"mutable-nocmek", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicARServer(t)
			defer srv.Close()
			d := arDriver(t, srv)
			attrs := map[string]any{
				"location.region":                "europe-west1",
				"network.publicExposure":         false,
				"encryption.customerManagedKeys": c.cmek,
				"immutable.tags":                 c.immutable,
				"service.managed":                true,
			}
			impl := map[string]any(nil)
			if c.cmek {
				impl = arImpl()
			}
			res := d.createARRepo("images", "prod", attrs, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeARRepo("images", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["immutable.tags"] != c.immutable {
				t.Errorf("immutable.tags not reflected: %+v", got)
			}
			if got["encryption.customerManagedKeys"] != c.cmek {
				t.Errorf("cmek %v not reflected: %+v", c.cmek, got)
			}
		})
	}
}
