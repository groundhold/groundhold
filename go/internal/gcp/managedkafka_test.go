package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mkafkaAttrs() map[string]any {
	return map[string]any{
		"location.region":                "europe-west1",
		"engine.protocol":                "kafka/3",
		"availability.class":             "regional",
		"encryption.inTransit":           true,
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	}
}

func mkafkaImpl() map[string]any {
	return map[string]any{
		"subnet":       "projects/acme-prod/regions/europe-west1/subnetworks/kafka",
		"kms_key_name": "projects/acme-prod/locations/europe-west1/keyRings/r/cryptoKeys/k",
	}
}

func TestBuildManagedKafkaHonors(t *testing.T) {
	p, err := BuildManagedKafka("acme-prod", "prod", "bus", mkafkaAttrs(), mkafkaImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Location != "europe-west1" || p.Subnet == "" || p.KmsKey == "" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("bus", "prod")
	if body["gcpConfig"].(map[string]any)["kmsKey"] == nil {
		t.Fatalf("body = %+v", body)
	}
}

func TestBuildManagedKafkaRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"zonal-refused":   {"availability.class": "zonal"}, // Managed Kafka is always regional
		"bad-avail":       {"availability.class": "planetary"},
		"intransit-false": {"encryption.inTransit": false},
		"bad-proto":       {"engine.protocol": "amqp/1"},
		"unmanaged":       {"service.managed": false},
		"unknown-attr":    {"kafka.tier": "x"},
	}
	for name, extra := range cases {
		a := mkafkaAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildManagedKafka("acme-prod", "prod", "bus", a, mkafkaImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// missing subnet must refuse.
	if _, err := BuildManagedKafka("acme-prod", "prod", "bus", mkafkaAttrs(), map[string]any{"kms_key_name": "k"}, 1); err == nil {
		t.Error("missing impl.subnet must refuse")
	}
	// missing region must refuse.
	a := mkafkaAttrs()
	delete(a, "location.region")
	if _, err := BuildManagedKafka("acme-prod", "prod", "bus", a, mkafkaImpl(), 1); err == nil {
		t.Error("missing location.region must refuse")
	}
}

func mkafkaServer(t *testing.T, capLabel, kms string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "clusterId="):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op1"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/opdel"}`))
			case r.Method == "GET":
				gcp := ""
				if kms != "" {
					gcp = `,"gcpConfig":{"kmsKey":"` + kms + `"}`
				}
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/clusters/x","state":"ACTIVE",` +
					`"labels":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"}` + gcp + `}`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func mkafkaDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.ManagedKafkaBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteManagedKafka(t *testing.T) {
	srv := mkafkaServer(t, "bus", "projects/acme-prod/locations/europe-west1/keyRings/r/cryptoKeys/k")
	defer srv.Close()
	d := mkafkaDriver(t, srv)
	res := d.createManagedKafka("prod", "bus", mkafkaAttrs(), mkafkaImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "gmkafka:acme-prod:europe-west1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeManagedKafka("bus", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "europe-west1" || got["engine.protocol"] != "kafka/3" ||
		got["encryption.inTransit"] != true || got["encryption.customerManagedKeys"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteManagedKafka("bus", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteManagedKafkaForeignRefused(t *testing.T) {
	srv := mkafkaServer(t, "someone-else", "")
	defer srv.Close()
	d := mkafkaDriver(t, srv)
	pid := managedKafkaProviderID("acme-prod", "europe-west1", ManagedKafkaClusterID("acme-prod", "prod", "bus", 1))
	res := d.deleteManagedKafka("bus", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign cluster must refuse delete, got %+v", res)
	}
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.messaging.kafka on GCP Managed Kafka. A STATEFUL fake records the CMK
// key the create writes and reflects it on the cluster read.
func TestMetamorphicManagedKafkaRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		cmek bool
	}{
		{"nocmek", false},
		{"cmek", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var kms string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "clusterId="):
						body, _ := io.ReadAll(r.Body)
						var doc struct {
							GcpConfig struct {
								KmsKey string `json:"kmsKey"`
							} `json:"gcpConfig"`
						}
						_ = json.Unmarshal(body, &doc)
						kms = doc.GcpConfig.KmsKey
						_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op1"}`))
					case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
						_, _ = w.Write([]byte(`{"done":true}`))
					case r.Method == "GET":
						gcp := ""
						if kms != "" {
							gcp = `,"gcpConfig":{"kmsKey":"` + kms + `"}`
						}
						_, _ = w.Write([]byte(`{"state":"ACTIVE","labels":{"groundhold-capability":"bus","groundhold-environment":"prod"}` + gcp + `}`))
					default:
						w.WriteHeader(404)
					}
				}))
			defer srv.Close()
			d := mkafkaDriver(t, srv)
			a := mkafkaAttrs()
			impl := map[string]any{"subnet": "projects/acme-prod/regions/europe-west1/subnetworks/kafka"}
			if c.cmek {
				impl["kms_key_name"] = "projects/acme-prod/locations/europe-west1/keyRings/r/cryptoKeys/k"
			} else {
				a["encryption.customerManagedKeys"] = false
			}
			res := d.createManagedKafka("prod", "bus", a, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeManagedKafka("bus", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if _, has := got["encryption.customerManagedKeys"]; has != c.cmek {
				t.Errorf("cmek round-trip: want present=%v got %v", c.cmek, got["encryption.customerManagedKeys"])
			}
		})
	}
}
