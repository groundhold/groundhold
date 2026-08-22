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
	deleted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// D800: the driver asks KMS who manages the key, so the fixture answers.
			if strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".DescribeKey") {
				_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyManager":"CUSTOMER"}}`))
				return
			}
			// once deleted, the domain is GONE — the delete's poll-to-absence (D973)
			// must be able to confirm a ResourceNotFound.
			if deleted && r.Method == "GET" && strings.Contains(r.URL.Path, "/domain/") {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException"}`))
				return
			}
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
				deleted = true
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
	d.KMSBaseURL = srv.URL // D800: the key is traced to KMS
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

// TestDeleteOpenSearchAsyncNotGoneIsUnknown pins D973: a domain delete the provider
// ACCEPTS but that stays present (still deleting) must report unknown — never a
// terminal "succeeded" that tombstones a data-bearing search domain still live.
func TestDeleteOpenSearchAsyncNotGoneIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/tags"):
				_, _ = w.Write([]byte(`{"TagList":[{"Key":"groundhold-capability","Value":"catalog"},` +
					`{"Key":"groundhold-environment","Value":"prod"}]}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/domain/"): // never gone
				_, _ = w.Write([]byte(`{"DomainStatus":{"DomainName":"d","Processing":true,"Created":true}}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"DomainStatus":{"Deleted":true}}`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := osDriver(t, srv)
	d.PollTimeout = 5 * time.Millisecond // the domain never leaves "deleting" → times out fast
	res := d.deleteOpenSearch("catalog", "prod", "opensearch:eu-central-1:000000000000:pv-catalog-prod-1")
	if res.Status != "unknown" {
		t.Fatalf("an accepted-but-still-deleting domain must be unknown (keep the handle), "+
			"got %+v — reporting succeeded tombstones a data-bearing domain still live", res)
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
					// D800: the driver asks KMS who manages the key, so the fixture answers.
					if strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".DescribeKey") {
						_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyManager":"CUSTOMER"}}`))
						return
					}
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
			// D1040: customerManagedKeys is a MEASURED value for BOTH states — assert the
			// value, not mere presence (unencrypted reads false, not an omitted obs).
			if got["encryption.customerManagedKeys"] != c.cmek {
				t.Errorf("cmek round-trip: want %v got %v", c.cmek, got["encryption.customerManagedKeys"])
			}
		})
	}
}

func osRESTRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	// the adopt-check's KMS key trace is a POST to KMS (X-Amz-Target: TrentService.
	// DescribeKey) — a READ despite the method, or it inflates the mutation count (D1062).
	if strings.HasSuffix(req.Header.Get("X-Amz-Target"), ".DescribeKey") {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// osAdoptSrv builds a 409-adopt fixture: our domain already standing, with the
// encryption controls set however the case needs (D1062).
func osAdoptSrv(atRest, https bool, kmsKeyId, keyManager string) func() *httptest.Server {
	return func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".DescribeKey") {
				km := keyManager
				if km == "" {
					km = "CUSTOMER"
				}
				_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyManager":"` + km + `"}}`))
				return
			}
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/domain"):
				w.WriteHeader(409)
				_, _ = w.Write([]byte(`{"__type":"ResourceAlreadyExistsException","message":"ResourceAlreadyExists"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/tags"):
				_, _ = w.Write([]byte(`{"TagList":[{"Key":"groundhold-capability","Value":"search"},` +
					`{"Key":"groundhold-environment","Value":"prod"}]}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/domain/"):
				kms := ""
				if kmsKeyId != "" {
					kms = `,"KmsKeyId":"` + kmsKeyId + `"`
				}
				_, _ = w.Write([]byte(`{"DomainStatus":{"DomainName":"d","Processing":false,"Created":true,` +
					`"EncryptionAtRestOptions":{"Enabled":` + boolStr(atRest) + kms + `},` +
					`"DomainEndpointOptions":{"EnforceHTTPS":` + boolStr(https) + `},` +
					`"ClusterConfig":{"ZoneAwarenessEnabled":true}}}`))
			default:
				w.WriteHeader(404)
			}
		}))
	}
}

// TestAdoptsExistingOpenSearch enrols opensearch in the D391 gate. The domain name is
// deterministic, a second create is answered ResourceAlreadyExists, and the tags decide.
func TestAdoptsExistingOpenSearch(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:           "aws/opensearch",
		Classify:       osRESTRole,
		ExistingServer: osAdoptSrv(true, true, "arn:aws:kms:eu-central-1:000000000000:key/abc", "CUSTOMER"),
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.OpenSearchBaseURL = happyURL
			d.KMSBaseURL = happyURL // D800: the key is traced to KMS
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("opensearch", "search", "prod", osAttrs(), osImpl(), "search", 1)
		},
		AllowedMutations: 1, // the refused create
		// D1062: at-rest encryption and the customer key are fixed at create (missing → failed);
		// D1213: in-transit (EnforceHTTPS) is UpdateDomainConfig-mutable (missing → bound-reconcile).
		AdoptControls: osAdoptControls,
		MissingControl: []certifynet.ControlCase{
			{Path: "encryption.atRest", WantStatus: "failed", WantMutations: 1,
				Server: osAdoptSrv(false, true, "arn:aws:kms:eu-central-1:000000000000:key/abc", "CUSTOMER")},
			// D1213: EnforceHTTPS is UpdateDomainConfig-mutable, so a domain adopted without it
			// is BOUND (unknown) and converge reconciles it — not refused like the create-fixed pair.
			{Path: "encryption.inTransit", WantStatus: "unknown", WantMutations: 1,
				Server: osAdoptSrv(true, false, "arn:aws:kms:eu-central-1:000000000000:key/abc", "CUSTOMER")},
			{Path: "encryption.customerManagedKeys", WantStatus: "failed", WantMutations: 1,
				Server: osAdoptSrv(true, true, "arn:aws:kms:eu-central-1:000000000000:key/abc", "AWS")}, // AWS-managed → not customer
		},
		MoreSecure: osAdoptSrv(true, true, "arn:aws:kms:eu-central-1:000000000000:key/abc", "CUSTOMER"),
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// D1213: updateOpenSearch enforces encryption.inTransit in place — UpdateDomainConfig sets
// EnforceHTTPS, then POLLS to the APPLIED state (D953) before reporting succeeded, so a
// security-closing change is never reported done while the domain still serves plaintext.
// Ownership re-checked by tags; foreign refused.
func TestUpdateOpenSearchInTransit(t *testing.T) {
	newSrv := func(capLabel string, startEnforced bool, seenEnforce *[]bool) *httptest.Server {
		enforced := startEnforced
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/tags"):
				_, _ = w.Write([]byte(`{"TagList":[{"Key":"groundhold-capability","Value":"` + capLabel +
					`"},{"Key":"groundhold-environment","Value":"prod"}]}`))
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/config"):
				body, _ := io.ReadAll(r.Body)
				var b struct {
					DomainEndpointOptions struct {
						EnforceHTTPS bool `json:"EnforceHTTPS"`
					} `json:"DomainEndpointOptions"`
				}
				_ = json.Unmarshal(body, &b)
				if seenEnforce != nil {
					*seenEnforce = append(*seenEnforce, b.DomainEndpointOptions.EnforceHTTPS)
				}
				enforced = b.DomainEndpointOptions.EnforceHTTPS // applied by the next DescribeDomain
				_, _ = w.Write([]byte(`{"DomainConfig":{}}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/domain/"):
				eh := "false"
				if enforced {
					eh = "true"
				}
				_, _ = w.Write([]byte(`{"DomainStatus":{"DomainName":"d","Processing":false,"Created":true,` +
					`"DomainEndpointOptions":{"EnforceHTTPS":` + eh + `}}}`))
			default:
				w.WriteHeader(404)
			}
		}))
	}
	pid := openSearchProviderID("eu-central-1", "000000000000", OpenSearchDomainName("prod", "catalog", 1))

	t.Run("enforce HTTPS on a plaintext domain, poll to applied", func(t *testing.T) {
		var seen []bool
		srv := newSrv("catalog", false, &seen)
		defer srv.Close()
		d := osDriver(t, srv)
		res := d.updateOpenSearch("catalog", "prod", pid,
			map[string]any{"encryption.inTransit": true}, []string{"encryption.inTransit"})
		if res.Status != "succeeded" {
			t.Fatalf("update: %+v", res)
		}
		if len(seen) != 1 || seen[0] != true {
			t.Fatalf("must UpdateDomainConfig EnforceHTTPS=true, got %+v", seen)
		}
	})

	t.Run("foreign domain refused, no UpdateDomainConfig", func(t *testing.T) {
		var seen []bool
		srv := newSrv("someone-else", false, &seen)
		defer srv.Close()
		d := osDriver(t, srv)
		res := d.updateOpenSearch("catalog", "prod", pid,
			map[string]any{"encryption.inTransit": true}, []string{"encryption.inTransit"})
		if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
			t.Fatalf("a foreign domain must be refused, got %+v", res)
		}
		if len(seen) != 0 {
			t.Fatalf("a refused update must issue NO UpdateDomainConfig, got %+v", seen)
		}
	})
}

func TestClassifyOpenSearchChange(t *testing.T) {
	if got, _ := classifyOpenSearchChange("encryption.inTransit"); got != "mutable" {
		t.Fatalf("encryption.inTransit must be mutable (in-place), got %q", got)
	}
	// VPC placement (publicExposure) is genuinely create-fixed — it must stay a replacement.
	for _, p := range []string{"network.publicExposure", "encryption.atRest", "location.region"} {
		if got, _ := classifyOpenSearchChange(p); got != "immutable" {
			t.Fatalf("%s must be immutable (replacement), got %q", p, got)
		}
	}
}
