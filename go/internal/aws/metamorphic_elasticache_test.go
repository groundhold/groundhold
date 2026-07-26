package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for capability.cache.keyvalue
// on AWS ElastiCache. A STATEFUL fake records the CreateReplicationGroup params
// (transit encryption, automatic failover, CMEK) and reflects them on
// DescribeReplicationGroups; the test varies (transit, availability, cmek) and
// asserts observe reverse-maps what create wrote. A driver that inverted the
// failover->availability mapping or dropped transit encryption fails here.
func metamorphicECServer(t *testing.T) *httptest.Server {
	t.Helper()
	var transit, failover, kms string
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			switch form.Get("Action") {
			case "CreateReplicationGroup":
				transit = form.Get("TransitEncryptionEnabled")
				if form.Get("AutomaticFailoverEnabled") == "true" {
					failover = "enabled"
				} else {
					failover = "disabled"
				}
				kms = form.Get("KmsKeyId")
				_, _ = w.Write([]byte(`<CreateReplicationGroupResponse></CreateReplicationGroupResponse>`))
			case "DescribeReplicationGroups":
				kmsX := ""
				if kms != "" {
					kmsX = "<KmsKeyId>" + kms + "</KmsKeyId>"
				}
				_, _ = w.Write([]byte(`<DescribeReplicationGroupsResponse><DescribeReplicationGroupsResult>` +
					`<ReplicationGroups><ReplicationGroup><Status>available</Status>` +
					`<AtRestEncryptionEnabled>true</AtRestEncryptionEnabled>` +
					`<TransitEncryptionEnabled>` + transit + `</TransitEncryptionEnabled>` +
					`<AutomaticFailover>` + failover + `</AutomaticFailover>` + kmsX +
					`</ReplicationGroup></ReplicationGroups>` +
					`</DescribeReplicationGroupsResult></DescribeReplicationGroupsResponse>`))
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><TagList>` +
					`<member><Key>groundhold-capability</Key><Value>sessions</Value></member>` +
					`<member><Key>groundhold-environment</Key><Value>prod</Value></member>` +
					`</TagList></ListTagsForResourceResult></ListTagsForResourceResponse>`))
			default:
				_, _ = w.Write([]byte(`<ok/>`))
			}
		}))
}

func TestMetamorphicElastiCacheRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		avail     string
		tls       bool
		cmek      bool
		wantClass string
	}{
		{"zonal-notls-nocmek", "zonal", false, false, "zonal"},
		{"regional-tls-cmek", "regional", true, true, "regional"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicECServer(t)
			defer srv.Close()
			d := ecDriver(t, srv)
			attrs := map[string]any{
				"engine.protocol":                "redis/7",
				"location.region":                "eu-central-1",
				"network.publicExposure":         false,
				"encryption.atRest":              true,
				"encryption.inTransit":           c.tls,
				"encryption.customerManagedKeys": c.cmek,
				"availability.class":             c.avail,
				"service.managed":                true,
			}
			var impl map[string]any
			if c.cmek {
				impl = ecImpl()
			}
			res := d.createElastiCache("eu-central-1", "000000000000", "prod", "sessions", attrs, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeElastiCache("sessions", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["availability.class"] != c.wantClass {
				t.Errorf("availability.class %q not reflected: %+v", c.wantClass, got)
			}
			if got["encryption.inTransit"] != c.tls {
				t.Errorf("inTransit %v not reflected: %+v", c.tls, got)
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
