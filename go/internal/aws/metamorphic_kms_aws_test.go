package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for capability.key.encryption
// on AWS KMS. A STATEFUL fake records the EnableKeyRotation period create wrote and
// reflects it on GetKeyRotationStatus; the test varies rotation on/off and asserts
// observe reverse-maps what create was given. protection.level is const hsm on AWS,
// so the round-trip that matters is the rotation state.
func metamorphicAWSKMSServer(t *testing.T) *httptest.Server {
	t.Helper()
	rotating := false
	days := 0
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			action := r.Header.Get("X-Amz-Target")
			action = action[strings.LastIndex(action, ".")+1:]
			switch action {
			case "CreateKey":
				_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyId":"` + testKeyID + `"}}`))
			case "EnableKeyRotation":
				body, _ := io.ReadAll(r.Body)
				var d struct {
					RotationPeriodInDays int `json:"RotationPeriodInDays"`
				}
				_ = json.Unmarshal(body, &d)
				rotating = true
				days = d.RotationPeriodInDays
				_, _ = w.Write([]byte(`{}`))
			case "GetKeyRotationStatus":
				if rotating {
					b, _ := json.Marshal(map[string]any{"KeyRotationEnabled": true, "RotationPeriodInDays": days})
					_, _ = w.Write(b)
				} else {
					_, _ = w.Write([]byte(`{"KeyRotationEnabled":false}`))
				}
			case "DescribeKey":
				_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyId":"` + testKeyID + `","Origin":"AWS_KMS"}}`))
			default:
				_, _ = w.Write([]byte(`{}`))
			}
		}))
}

func TestMetamorphicAWSKMSRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		rotation string
		wantRot  string // "" = absent
	}{
		{"rotating-90d", "90d", "90d"},
		{"manual", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicAWSKMSServer(t)
			defer srv.Close()
			d := awsKMSDriver(t, srv)
			attrs := map[string]any{
				"location.region":  "eu-central-1",
				"protection.level": "hsm",
				"service.managed":  true,
			}
			if c.rotation != "" {
				attrs["rotation.period"] = c.rotation
			}
			res := d.createAWSKMS("eu-central-1", "prod", "datakey", attrs, nil, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeAWSKMS("datakey", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["protection.level"] != "hsm" {
				t.Errorf("protection.level must be hsm: %+v", got)
			}
			if c.wantRot == "" {
				if _, has := got["rotation.period"]; has {
					t.Errorf("manual key must not report a rotation period: %+v", got)
				}
			} else if got["rotation.period"] != c.wantRot {
				t.Errorf("rotation %q not reflected: %+v", c.wantRot, got)
			}
		})
	}
}
