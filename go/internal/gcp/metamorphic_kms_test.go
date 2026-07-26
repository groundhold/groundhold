package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for capability.key.encryption
// on GCP Cloud KMS. A STATEFUL fake records what createKMS writes (the cryptoKey
// protectionLevel and rotationPeriod) and reflects it on observe; the test varies
// (protection, rotation) and asserts observe reverse-maps what create was given. A
// driver that read the protection level from the wrong field or dropped the
// rotation period fails here with no fault injected.
func metamorphicKMSServer(t *testing.T) *httptest.Server {
	t.Helper()
	var protection, rotation string
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "keyRingId="):
				_, _ = w.Write([]byte(`{"name":"ring"}`))
			case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "cryptoKeyId="):
				body, _ := io.ReadAll(r.Body)
				var doc struct {
					RotationPeriod  string `json:"rotationPeriod"`
					VersionTemplate struct {
						ProtectionLevel string `json:"protectionLevel"`
					} `json:"versionTemplate"`
				}
				_ = json.Unmarshal(body, &doc)
				protection, rotation = doc.VersionTemplate.ProtectionLevel, doc.RotationPeriod
				_, _ = w.Write([]byte(`{"name":"key"}`))
			case r.Method == "GET":
				out := map[string]any{
					"name":            "projects/acme-prod/locations/europe-west1/keyRings/groundhold-prod/cryptoKeys/x",
					"labels":          map[string]any{"groundhold-capability": "datakey", "groundhold-environment": "prod"},
					"versionTemplate": map[string]any{"protectionLevel": protection},
				}
				if rotation != "" {
					out["rotationPeriod"] = rotation
				}
				b, _ := json.Marshal(out)
				_, _ = w.Write(b)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestMetamorphicKMSRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		prot      string
		wantProt  string
		rotation  string
		wantRotOK bool
	}{
		{"hsm-rotating", "hsm", "hsm", "30d", true},
		{"software-manual", "software", "software", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicKMSServer(t)
			defer srv.Close()
			d := kmsDriver(t, srv)
			attrs := map[string]any{
				"location.region":  "europe-west1",
				"protection.level": c.prot,
				"service.managed":  true,
			}
			if c.rotation != "" {
				attrs["rotation.period"] = c.rotation
			}
			res := d.createKMS("prod", "datakey", attrs, nil, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeKMS("datakey", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["protection.level"] != c.wantProt {
				t.Errorf("protection %q not reflected: %+v", c.wantProt, got)
			}
			_, hasRot := got["rotation.period"]
			if hasRot != c.wantRotOK {
				t.Errorf("rotation presence %v not reflected: %+v", c.wantRotOK, got)
			}
		})
	}
}
