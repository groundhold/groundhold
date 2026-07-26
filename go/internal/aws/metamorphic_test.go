package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip — the DERIVED oracle for
// the class fault injection is structurally blind to: semantic field mis-mapping
// and silent field drops. The fault harness proves the driver does not lie about
// an ambiguous WIRE outcome; this proves Observe reverse-maps what Create forward-
// maps. Method: a STATEFUL fake records what Create writes (versioning, public
// policy, tags) and reflects it on the Observe reads; the test asserts Observe
// returns the same semantic attributes Create was given. A driver that reads
// versioning from the wrong element, inverts public exposure, or drops an
// attribute fails here without any fault being injected.
//
// This is the S3 vertical slice (D10) establishing the pattern; each driver needs
// its own stateful reflector (envelope renaming, not semantics). Rolling it out to
// RDS/ECS/VPC and the GCP drivers is the documented next step.
func metamorphicS3Server(t *testing.T) *httptest.Server {
	t.Helper()
	versioning := false
	public := false
	tagged := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.RawQuery
			body := make([]byte, r.ContentLength)
			if r.Body != nil {
				r.Body.Read(body)
			}
			switch {
			// ---- Create writes ----
			case r.Method == "PUT" && q == "":
				w.WriteHeader(200) // create bucket
			case r.Method == "PUT" && q == "tagging":
				tagged = true
				w.WriteHeader(200)
			case r.Method == "PUT" && q == "versioning":
				versioning = strings.Contains(string(body), "Enabled")
				w.WriteHeader(200)
			case r.Method == "PUT" && q == "policy":
				public = true // a public-read policy was put
				w.WriteHeader(200)
			case r.Method == "PUT": // public-access-block etc.
				w.WriteHeader(200)
			// ---- Observe reads reflect the recorded state ----
			case r.Method == "GET" && q == "tagging":
				if !tagged {
					w.WriteHeader(404)
					_, _ = w.Write([]byte("<Error><Code>NoSuchTagSet</Code></Error>"))
					return
				}
				_, _ = w.Write([]byte(`<Tagging><TagSet>` +
					`<Tag><Key>groundhold-capability</Key><Value>assets</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
					`</TagSet></Tagging>`))
			case r.Method == "GET" && q == "versioning":
				status := "Suspended"
				if versioning {
					status = "Enabled"
				}
				_, _ = w.Write([]byte(`<VersioningConfiguration><Status>` + status + `</Status></VersioningConfiguration>`))
			case r.Method == "GET" && q == "policyStatus":
				if public {
					_, _ = w.Write([]byte(`<PolicyStatus><IsPublic>true</IsPublic></PolicyStatus>`))
					return
				}
				w.WriteHeader(404)
				_, _ = w.Write([]byte("<Error><Code>NoSuchBucketPolicy</Code></Error>"))
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestMetamorphicS3RoundTrip(t *testing.T) {
	cases := []struct {
		name       string
		versioning bool
		public     bool
	}{
		{"versioned-private", true, false},
		{"unversioned-public", false, true},
		{"versioned-public", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
			srv := metamorphicS3Server(t)
			defer srv.Close()
			d := s3TestDriver(t, srv)

			attrs := map[string]any{
				"location.region":        "eu-central-1",
				"durability.class":       "regional",
				"versioning.enabled":     c.versioning,
				"network.publicExposure": c.public,
				"encryption.atRest":      true,
				"service.managed":        true,
			}
			res := d.createS3("000000000000", "prod", "assets", attrs, nil, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create failed: %+v", res)
			}
			obs, _, err := d.observeS3("assets", res.ProviderID)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			// the metamorphic invariant: Observe reverse-maps what Create wrote.
			if got["versioning.enabled"] != c.versioning {
				t.Errorf("versioning round-trip broke: wrote %v, observed %v", c.versioning, got["versioning.enabled"])
			}
			if got["network.publicExposure"] != c.public {
				t.Errorf("public-exposure round-trip broke: wrote %v, observed %v", c.public, got["network.publicExposure"])
			}
			if got["location.region"] != "eu-central-1" {
				t.Errorf("region round-trip broke: observed %v", got["location.region"])
			}
		})
	}
}
