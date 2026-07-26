package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for capability.secret on
// Azure Key Vault. A STATEFUL fake records what createKeyVault writes (the
// publicNetworkAccess and location from the vault PUT) and reflects it on the GET;
// the test varies public exposure and asserts observeKeyVault returns what create
// was given. A driver that inverted publicNetworkAccess (Enabled/Disabled) or
// dropped the region fails here with no fault injected. CMEK is not a dimension —
// it is an honest one-cloud refusal on an Azure secret.
func metamorphicKeyVaultServer(t *testing.T) *httptest.Server {
	t.Helper()
	var location, publicAccess string
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				body, _ := io.ReadAll(r.Body)
				var doc struct {
					Location   string `json:"location"`
					Properties struct {
						PublicNetworkAccess string `json:"publicNetworkAccess"`
					} `json:"properties"`
				}
				_ = json.Unmarshal(body, &doc)
				location = doc.Location
				publicAccess = doc.Properties.PublicNetworkAccess
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"` + location + `",` +
					`"tags":{"groundhold-capability":"dbcreds","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","publicNetworkAccess":"` + publicAccess + `"}}`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestMetamorphicKeyVaultRoundTrip(t *testing.T) {
	for _, public := range []bool{false, true} {
		name := "private"
		if public {
			name = "public"
		}
		t.Run(name, func(t *testing.T) {
			srv := metamorphicKeyVaultServer(t)
			defer srv.Close()
			d := NewDriver(testSub)
			d.BaseURL = srv.URL
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			attrs := map[string]any{
				"location.region":        "eastus",
				"network.publicExposure": public,
				"encryption.atRest":      true,
				"service.managed":        true,
			}
			res := d.createKeyVault("prod", "dbcreds", attrs, kvImpl(), 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeKeyVault("dbcreds", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["location.region"] != "eastus" {
				t.Errorf("region did not survive round-trip: %+v", got)
			}
			if got["network.publicExposure"] != public {
				t.Errorf("public exposure %v not reflected: %+v", public, got)
			}
		})
	}
}
