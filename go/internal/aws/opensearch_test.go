package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func osAttrs() map[string]any {
	return map[string]any{
		"location.region":                "eu-central-1",
		"availability.class":             "regional",
		"network.publicExposure":         true,
		"encryption.atRest":              true,
		"encryption.inTransit":           true,
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	}
}

func osImpl() map[string]any {
	return map[string]any{"kms_key_id": "arn:aws:kms:eu-central-1:000000000000:key/abc"}
}

func TestBuildOpenSearchHonors(t *testing.T) {
	p, err := BuildOpenSearch("prod", "catalog", osAttrs(), osImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.ZoneAwareness || !p.Public || !p.CMEK || p.KmsKeyId == "" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("eu-central-1", "000000000000", "catalog", "prod")
	if body["EncryptionAtRestOptions"].(map[string]any)["KmsKeyId"] == nil || body["AccessPolicies"] == nil {
		t.Fatalf("body = %+v", body)
	}
}

func TestBuildOpenSearchPrivateNeedsVPC(t *testing.T) {
	a := osAttrs()
	a["network.publicExposure"] = false
	delete(a, "encryption.customerManagedKeys") // isolate the VPC-placement check
	if _, err := BuildOpenSearch("prod", "catalog", a, nil, 1); err == nil {
		t.Fatal("private domain without subnets/security groups must refuse")
	}
	impl := map[string]any{"subnet_ids": []any{"subnet-1"}, "security_group_ids": []any{"sg-1"}}
	p, err := BuildOpenSearch("prod", "catalog", a, impl, 1)
	if err != nil || p.Public || len(p.SubnetIDs) != 1 {
		t.Fatalf("private plan = %+v err=%v", p, err)
	}
}

func TestBuildOpenSearchRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"atrest-false":    {"encryption.atRest": false},
		"intransit-false": {"encryption.inTransit": false},
		"unmanaged":       {"service.managed": false},
		"bad-avail":       {"availability.class": "planetary"},
		"unknown-attr":    {"search.tier": "x"},
	}
	for name, extra := range cases {
		a := osAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildOpenSearch("prod", "catalog", a, osImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := osAttrs()
	a["encryption.customerManagedKeys"] = true
	if _, err := BuildOpenSearch("prod", "catalog", a, nil, 1); err == nil {
		t.Error("cmek without impl.kms_key_id must refuse")
	}
}

func osServer(t *testing.T, capLabel string, zoneAware, cmek bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/domain"):
				_, _ = w.Write([]byte(`{"DomainStatus":{"DomainName":"d","Processing":false,"Created":true}}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/tags"):
				_, _ = w.Write([]byte(`{"TagList":[{"Key":"groundhold-capability","Value":"` + capLabel +
					`"},{"Key":"groundhold-environment","Value":"prod"}]}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/domain/"):
				za := "false"
				if zoneAware {
					za = "true"
				}
				kms := ""
				if cmek {
					kms = `,"KmsKeyId":"arn:aws:kms:eu-central-1:000000000000:key/abc"`
				}
				_, _ = w.Write([]byte(`{"DomainStatus":{"DomainName":"d","Processing":false,"Created":true,` +
					`"EncryptionAtRestOptions":{"Enabled":true` + kms + `},` +
					`"DomainEndpointOptions":{"EnforceHTTPS":true},` +
					`"ClusterConfig":{"ZoneAwarenessEnabled":` + za + `}}}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"DomainStatus":{"Deleted":true}}`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func osDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	d.OpenSearchBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteOpenSearch(t *testing.T) {
	srv := osServer(t, "catalog", true, true)
	defer srv.Close()
	d := osDriver(t, srv)
	res := d.createOpenSearch("eu-central-1", "000000000000", "prod", "catalog", osAttrs(), osImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "opensearch:eu-central-1:000000000000:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeOpenSearch("catalog", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eu-central-1" || got["availability.class"] != "regional" ||
		got["encryption.customerManagedKeys"] != true || got["network.publicExposure"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteOpenSearch("catalog", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteOpenSearchForeignRefused(t *testing.T) {
	srv := osServer(t, "someone-else", false, false)
	defer srv.Close()
	d := osDriver(t, srv)
	pid := openSearchProviderID("eu-central-1", "000000000000", OpenSearchDomainName("prod", "catalog", 1))
	res := d.deleteOpenSearch("catalog", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign domain must refuse delete, got %+v", res)
	}
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.search.index on AWS OpenSearch. A STATEFUL fake records the zone
// awareness and CMEK key the create writes and reflects them on the describe read.
func TestMetamorphicOpenSearchRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		regional  bool
		cmek      bool
		wantAvail string
	}{
		{"zonal-nocmek", false, false, "zonal"},
		{"regional-cmek", true, true, "regional"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var za bool
			var kms string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/domain"):
						body, _ := io.ReadAll(r.Body)
						var doc struct {
							ClusterConfig struct {
								ZoneAwarenessEnabled bool `json:"ZoneAwarenessEnabled"`
							} `json:"ClusterConfig"`
							EncryptionAtRestOptions struct {
								KmsKeyId string `json:"KmsKeyId"`
							} `json:"EncryptionAtRestOptions"`
						}
						_ = json.Unmarshal(body, &doc)
						za, kms = doc.ClusterConfig.ZoneAwarenessEnabled, doc.EncryptionAtRestOptions.KmsKeyId
						_, _ = w.Write([]byte(`{"DomainStatus":{"Processing":false,"Created":true}}`))
					case r.Method == "GET" && strings.Contains(r.URL.Path, "/domain/"):
						zaS := "false"
						if za {
							zaS = "true"
						}
						k := ""
						if kms != "" {
							k = `,"KmsKeyId":"` + kms + `"`
						}
						_, _ = w.Write([]byte(`{"DomainStatus":{"Processing":false,"EncryptionAtRestOptions":{"Enabled":true` + k + `},` +
							`"DomainEndpointOptions":{"EnforceHTTPS":true},"ClusterConfig":{"ZoneAwarenessEnabled":` + zaS + `}}}`))
					default:
						w.WriteHeader(404)
					}
				}))
			defer srv.Close()
			d := osDriver(t, srv)
			a := osAttrs()
			if c.regional {
				a["availability.class"] = "regional"
			} else {
				a["availability.class"] = "zonal"
			}
			impl := map[string]any{}
			if c.cmek {
				a["encryption.customerManagedKeys"] = true
				impl["kms_key_id"] = "arn:aws:kms:eu-central-1:000000000000:key/abc"
			} else {
				a["encryption.customerManagedKeys"] = false
			}
			res := d.createOpenSearch("eu-central-1", "000000000000", "prod", "catalog", a, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeOpenSearch("catalog", res.ProviderID)
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
			if _, has := got["encryption.customerManagedKeys"]; has != c.cmek {
				t.Errorf("cmek round-trip: want present=%v got %v", c.cmek, got["encryption.customerManagedKeys"])
			}
		})
	}
}
