package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func readJSONBody(r *http.Request) map[string]any {
	b, _ := io.ReadAll(r.Body)
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

func mskAttrs() map[string]any {
	return map[string]any{
		"location.region":                "eu-central-1",
		"engine.protocol":                "kafka/3",
		"availability.class":             "regional",
		"encryption.inTransit":           true,
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	}
}

func mskImpl() map[string]any {
	return map[string]any{
		"subnet_ids":         []any{"subnet-1", "subnet-2"},
		"security_group_ids": []any{"sg-1"},
		"kms_key_id":         "arn:aws:kms:eu-central-1:000000000000:key/abc",
	}
}

func TestBuildMSKHonors(t *testing.T) {
	p, err := BuildMSK("prod", "bus", mskAttrs(), mskImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.KafkaVersion != "3.6.0" || p.Brokers != 2 || !p.CMEK || p.KmsKeyId == "" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("bus", "prod")
	// D879: the wire is restJson1 camelCase. Pin the exact key path so a mutation back
	// to PascalCase (which AWS would drop, then 400) is caught at the desk, not on a run.
	if _, pascal := body["Provisioned"]; pascal {
		t.Fatalf("createBody emits PascalCase Provisioned — AWS ignores it (D879): %+v", body)
	}
	prov := body["provisioned"].(map[string]any)
	if prov["encryptionInfo"].(map[string]any)["encryptionAtRest"].(map[string]any)["dataVolumeKMSKeyId"] == nil {
		t.Fatalf("body = %+v", prov)
	}
	for _, k := range []string{"clusterName", "provisioned", "tags"} {
		if _, ok := body[k]; !ok {
			t.Fatalf("createBody missing camelCase key %q (real MSK locationName): %+v", k, body)
		}
	}
}

func TestBuildMSKRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"zonal-refused":   {"availability.class": "zonal"}, // MSK is always multi-AZ
		"bad-avail":       {"availability.class": "planetary"},
		"intransit-false": {"encryption.inTransit": false},
		"bad-proto":       {"engine.protocol": "amqp/1"},
		"unmanaged":       {"service.managed": false},
		"unknown-attr":    {"kafka.tier": "x"},
	}
	for name, extra := range cases {
		a := mskAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildMSK("prod", "bus", a, mskImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// missing VPC placement must refuse.
	if _, err := BuildMSK("prod", "bus", mskAttrs(), map[string]any{"kms_key_id": "k"}, 1); err == nil {
		t.Error("missing subnets/security groups must refuse")
	}
	// cmek without a key must refuse.
	a := mskAttrs()
	if _, err := BuildMSK("prod", "bus", a, map[string]any{"subnet_ids": []any{"s1", "s2"}, "security_group_ids": []any{"sg"}}, 1); err == nil {
		t.Error("cmek without impl.kms_key_id must refuse")
	}
}

func mskServer(t *testing.T, capLabel, kafkaVersion string, cmek bool) *httptest.Server {
	t.Helper()
	const arn = "arn:aws:kafka:eu-central-1:000000000000:cluster/pv-c/uuid-1"
	deleted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// once deleted, the cluster is GONE — the delete's poll-to-absence (D974)
			// must be able to confirm an empty cluster list.
			if deleted && r.Method == "GET" && strings.Contains(r.URL.Path, "/api/v2/clusters") {
				_, _ = w.Write([]byte(`{"clusterInfoList":[]}`))
				return
			}
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/api/v2/clusters"):
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"clusterArn":"` + arn + `","clusterName":"pv-c","state":"CREATING"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/api/v2/clusters"):
				// ListClustersV2 (name filter) — echo the requested name back so the
				// exact-match resolver finds it.
				reqName := r.URL.Query().Get("clusterNameFilter")
				enc := ""
				if cmek {
					enc = `,"dataVolumeKMSKeyId":"arn:aws:kms:eu-central-1:000000000000:key/abc"`
				}
				_, _ = w.Write([]byte(`{"clusterInfoList":[{"clusterArn":"` + arn + `","clusterName":"` + reqName +
					`","state":"ACTIVE","tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
					`"provisioned":{"currentBrokerSoftwareInfo":{"kafkaVersion":"` + kafkaVersion + `"},` +
					`"encryptionInfo":{"encryptionInTransit":{"clientBroker":"TLS"},"encryptionAtRest":{` + strings.TrimPrefix(enc, ",") + `}}}}]}`))
			case r.Method == "DELETE" && r.URL.EscapedPath() == mskDeletePath+"/"+rfc3986(arn):
				deleted = true
				// D717: EXACT, not "any DELETE". This case used to match the method
				// alone, so it answered 200 to a delete addressed anywhere — and the
				// driver was addressing it to a route MSK does not have. A fixture that
				// answers a request the cloud would reject is not a double for the cloud.
				// D880: the cluster ARN is single-encoded on the wire (rfc3986, one segment),
				// as botocore serializes it against the non-greedy {clusterArn} route.
				w.WriteHeader(200)
			default:
				t.Errorf("fixture asked for %s %s — MSK has no such route, or the test "+
					"has outgrown the fixture", r.Method, r.URL.EscapedPath())
				w.WriteHeader(404)
			}
		}))
}

func mskDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	d.MSKBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteMSK(t *testing.T) {
	srv := mskServer(t, "bus", "3.6.0", true)
	defer srv.Close()
	d := mskDriver(t, srv)
	res := d.createMSK("eu-central-1", "000000000000", "prod", "bus", mskAttrs(), mskImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "msk:eu-central-1:000000000000:pv-") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeMSK("bus", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eu-central-1" || got["engine.protocol"] != "kafka/3" ||
		got["encryption.inTransit"] != true {
		t.Fatalf("observe: %+v", got)
	}
	// customerManagedKeys is unobservable via ListClustersV2 (managed vs customer
	// KMS key indistinguishable by ARN, the RDS case) — never fabricated.
	if _, has := got["encryption.customerManagedKeys"]; has {
		t.Fatalf("cmek must not be observed, got %v", got["encryption.customerManagedKeys"])
	}
	if del := d.deleteMSK("bus", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteMSKForeignRefused(t *testing.T) {
	srv := mskServer(t, "someone-else", "3.6.0", false)
	defer srv.Close()
	d := mskDriver(t, srv)
	pid := mskProviderID("eu-central-1", "000000000000", MSKClusterName("prod", "bus", 1))
	res := d.deleteMSK("bus", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign cluster must refuse delete, got %+v", res)
	}
}

// TestDeleteMSKAsyncNotGoneIsUnknown pins D974: a cluster delete the provider
// ACCEPTS but that stays present (DELETING, not gone) must report unknown —
// never a terminal "succeeded" that tombstones a data-bearing Kafka cluster
// still live.
func TestDeleteMSKAsyncNotGoneIsUnknown(t *testing.T) {
	const arn = "arn:aws:kafka:eu-central-1:000000000000:cluster/pv-c/uuid-1" // same as mskServer: keep the delete route already route-captured
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/api/v2/clusters"): // never gone
				reqName := r.URL.Query().Get("clusterNameFilter")
				_, _ = w.Write([]byte(`{"clusterInfoList":[{"clusterArn":"` + arn + `","clusterName":"` + reqName +
					`","state":"DELETING","tags":{"groundhold-capability":"bus","groundhold-environment":"prod"}}]}`))
			case r.Method == "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := mskDriver(t, srv)
	d.PollTimeout = 5 * time.Millisecond // the cluster never leaves DELETING → times out fast
	res := d.deleteMSK("bus", "prod", "msk:eu-central-1:000000000000:pv-bus-prod-1")
	if res.Status != "unknown" {
		t.Fatalf("an accepted-but-still-deleting cluster must be unknown (keep the handle), "+
			"got %+v — reporting succeeded tombstones a Kafka cluster still live", res)
	}
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.messaging.kafka on AWS MSK. A STATEFUL fake records the KafkaVersion
// and CMK key the create writes and reflects them on the list read.
func TestMetamorphicMSKRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		proto     string
		wantProto string
		cmek      bool
	}{
		{"v2-nocmek", "kafka/2", "kafka/2", false},
		{"v3-cmek", "kafka/3", "kafka/3", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			const arn = "arn:aws:kafka:eu-central-1:000000000000:cluster/pv-c/uuid-1"
			var kafkaVersion, kms string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == "POST":
						body := readJSONBody(r)
						prov, _ := body["provisioned"].(map[string]any)
						if v, ok := prov["kafkaVersion"].(string); ok {
							kafkaVersion = v
						}
						if enc, ok := prov["encryptionInfo"].(map[string]any); ok {
							if ar, ok := enc["encryptionAtRest"].(map[string]any); ok {
								if k, ok := ar["dataVolumeKMSKeyId"].(string); ok {
									kms = k
								}
							}
						}
						w.WriteHeader(200)
						_, _ = w.Write([]byte(`{"clusterArn":"` + arn + `","state":"CREATING"}`))
					case r.Method == "GET":
						reqName := r.URL.Query().Get("clusterNameFilter")
						enc := ""
						if kms != "" {
							enc = `"dataVolumeKMSKeyId":"` + kms + `"`
						}
						_, _ = w.Write([]byte(`{"clusterInfoList":[{"clusterArn":"` + arn + `","clusterName":"` + reqName +
							`","state":"ACTIVE","tags":{"groundhold-capability":"bus","groundhold-environment":"prod"},` +
							`"provisioned":{"currentBrokerSoftwareInfo":{"kafkaVersion":"` + kafkaVersion + `"},` +
							`"encryptionInfo":{"encryptionInTransit":{"clientBroker":"TLS"},"encryptionAtRest":{` + enc + `}}}}]}`))
					default:
						w.WriteHeader(200)
					}
				}))
			defer srv.Close()
			d := mskDriver(t, srv)
			a := mskAttrs()
			a["engine.protocol"] = c.proto
			impl := map[string]any{"subnet_ids": []any{"subnet-1", "subnet-2"}, "security_group_ids": []any{"sg-1"}}
			if c.cmek {
				impl["kms_key_id"] = "arn:aws:kms:x:y:key/z"
			} else {
				a["encryption.customerManagedKeys"] = false
			}
			res := d.createMSK("eu-central-1", "000000000000", "prod", "bus", a, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, diags, err := d.observeMSK("bus", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["engine.protocol"] != c.wantProto {
				t.Errorf("protocol round-trip: want %q got %v", c.wantProto, got["engine.protocol"])
			}
			// customerManagedKeys is unobservable: the DataVolumeKMSKeyId ARN does
			// not distinguish the AWS-managed key from a customer key (the RDS case).
			// observe never reports it; a KMS key emits a diagnostic instead.
			if _, has := got["encryption.customerManagedKeys"]; has {
				t.Errorf("cmek must be unobservable, got %v (fabricated)", got["encryption.customerManagedKeys"])
			}
			hasDiag := false
			for _, dg := range diags {
				if strings.Contains(dg, "customerManagedKeys not observed") {
					hasDiag = true
				}
			}
			if c.cmek && !hasDiag {
				t.Errorf("a CMEK cluster must emit a customerManagedKeys diagnostic, got %v", diags)
			}
		})
	}
}

func mskRESTRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingMSK enrols msk in the D391 gate. The cluster name is deterministic,
// a second create is answered with a Conflict, and the driver resolves by name and
// checks the tags before adopting.
func TestAdoptsExistingMSK(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	const arn = "arn:aws:kafka:eu-central-1:000000000000:cluster/pv-c/uuid-1"
	p := &certifynet.ExistingProbe{
		Name:     "aws/msk",
		Classify: mskRESTRole,
		ExistingServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/api/v2/clusters"):
						w.WriteHeader(409)
						_, _ = w.Write([]byte(`{"message":"Conflict: cluster already exists"}`))
					case r.Method == "GET" && strings.Contains(r.URL.Path, "/api/v2/clusters"):
						reqName := r.URL.Query().Get("clusterNameFilter")
						_, _ = w.Write([]byte(`{"clusterInfoList":[{"clusterArn":"` + arn +
							`","clusterName":"` + reqName + `","state":"ACTIVE",` +
							`"tags":{"groundhold-capability":"events","groundhold-environment":"prod"},` +
							`"provisioned":{"currentBrokerSoftwareInfo":{"kafkaVersion":"3.6.0"},` +
							`"encryptionInfo":{"encryptionInTransit":{"clientBroker":"TLS"},` +
							`"encryptionAtRest":{}}}}]}`))
					default:
						w.WriteHeader(404)
					}
				}))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.MSKBaseURL = happyURL
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("msk", "events", "prod", mskAttrs(), mskImpl(), "events", 1)
		},
		AllowedMutations: 1, // the refused create
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
