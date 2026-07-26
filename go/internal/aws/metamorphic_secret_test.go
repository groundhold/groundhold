package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for capability.secret on
// AWS Secrets Manager. A STATEFUL fake records what createASM writes (the
// CreateSecret KmsKeyId and the PutResourcePolicy) and reflects it on the
// DescribeSecret / GetResourcePolicy reads; the test varies (public, cmek) and
// asserts observeASM returns the same semantic attributes create was given. A
// driver that inverted public exposure or misread the CMEK key fails here with no
// fault injected. Residency is honest by construction (regional), so the region is
// asserted directly from the pid.
func metamorphicASMServer(t *testing.T) *httptest.Server {
	t.Helper()
	var kms string
	public := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			action := r.Header.Get("X-Amz-Target")
			action = action[strings.LastIndex(action, ".")+1:]
			body, _ := io.ReadAll(r.Body)
			switch action {
			case "CreateSecret":
				var doc struct {
					KmsKeyId string `json:"KmsKeyId"`
				}
				_ = json.Unmarshal(body, &doc)
				kms = doc.KmsKeyId
				_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf","Name":"x"}`))
			case "PutResourcePolicy":
				public = true
				_, _ = w.Write([]byte(`{"Name":"x"}`))
			case "DeleteResourcePolicy":
				public = false
				_, _ = w.Write([]byte(`{"Name":"x"}`))
			case "DescribeSecret":
				out := `{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf","Name":"x",` +
					`"Tags":[{"Key":"groundhold-capability","Value":"dbcreds"},{"Key":"groundhold-environment","Value":"prod"}]`
				if kms != "" {
					out += `,"KmsKeyId":"` + kms + `"`
				}
				out += `}`
				_, _ = w.Write([]byte(out))
			case "GetResourcePolicy":
				if public {
					enc, _ := json.Marshal(asmPublicPolicy(""))
					_, _ = w.Write([]byte(`{"Name":"x","ResourcePolicy":` + string(enc) + `}`))
				} else {
					_, _ = w.Write([]byte(`{"Name":"x"}`))
				}
			default:
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"UnknownOperation"}`))
			}
		}))
}

func TestMetamorphicASMRoundTrip(t *testing.T) {
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
			srv := metamorphicASMServer(t)
			defer srv.Close()
			d := asmDriver(t, srv)
			attrs := map[string]any{
				"location.region":                "eu-central-1",
				"network.publicExposure":         c.public,
				"encryption.atRest":              true,
				"encryption.customerManagedKeys": c.cmek,
				"service.managed":                true,
			}
			var impl map[string]any
			if c.cmek {
				impl = asmImpl()
			}
			res := d.createASM("eu-central-1", "prod", "dbcreds", attrs, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeASM("dbcreds", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["location.region"] != "eu-central-1" {
				t.Errorf("region did not survive round-trip: %+v", got)
			}
			if got["network.publicExposure"] != c.public {
				t.Errorf("public exposure %v not reflected: %+v", c.public, got)
			}
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
