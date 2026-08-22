package aws

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func ecAttrs() map[string]any {
	return map[string]any{
		"engine.protocol":                "redis/7",
		"location.region":                "eu-central-1",
		"network.publicExposure":         false,
		"encryption.atRest":              true,
		"encryption.inTransit":           true,
		"encryption.customerManagedKeys": true,
		"availability.class":             "regional",
		"service.managed":                true,
	}
}

func ecImpl() map[string]any {
	return map[string]any{"kms_key_id": "arn:aws:kms:eu-central-1:000000000000:key/abc"}
}

func TestBuildElastiCacheHonors(t *testing.T) {
	p, err := BuildElastiCacheCreate("000000000000", "prod", "sessions", ecAttrs(), ecImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.EngineVersion != "7.0" || !p.AtRest || !p.Transit || !p.MultiAZ || p.KmsKeyID == "" {
		t.Fatalf("plan = %+v", p)
	}
	if !ecacheIDOK.MatchString(p.ID) {
		t.Fatalf("id invalid: %q", p.ID)
	}
	form := p.createParams("sessions", "prod")
	if form["AutomaticFailoverEnabled"] != "true" || form["MultiAZEnabled"] != "true" ||
		form["TransitEncryptionEnabled"] != "true" {
		t.Fatalf("form = %+v", form)
	}
}

func TestBuildElastiCacheRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"engine.protocol": "redis/7", "location.region": "eu-central-1",
			"encryption.atRest": true, "service.managed": true}
	}
	cases := map[string]map[string]any{
		"public-refused": {"network.publicExposure": true},
		"atRest-false":   {"encryption.atRest": false},
		"unmanaged":      {"service.managed": false},
		"multi-regional": {"availability.class": "multi-regional"},
		"memcached":      {"engine.protocol": "memcached/1.6"},
		"unknown-attr":   {"eviction.policy": "lru"},
	}
	for name, extra := range cases {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildElastiCacheCreate("000000000000", "prod", "sessions", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	cmk := base()
	cmk["encryption.customerManagedKeys"] = true
	if _, err := BuildElastiCacheCreate("000000000000", "prod", "sessions", cmk, nil, 1); err == nil {
		t.Error("CMK without kms_key_id must refuse")
	}
}

func ecServer(t *testing.T, tagCap, atRest, transit, failover, kms string) *httptest.Server {
	t.Helper()
	deleted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// D800: the driver asks KMS who manages the key, so the fixture answers.
			if strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".DescribeKey") {
				_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyManager":"CUSTOMER"}}`))
				return
			}
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			switch form.Get("Action") {
			case "CreateReplicationGroup":
				_, _ = w.Write([]byte(`<CreateReplicationGroupResponse></CreateReplicationGroupResponse>`))
			case "DescribeReplicationGroups":
				// once deleted, the group is GONE — the delete's poll-to-absence
				// (D970) must be able to confirm the not-found fault.
				if deleted {
					w.WriteHeader(400)
					_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>ReplicationGroupNotFoundFault</Code></Error></ErrorResponse>`))
					return
				}
				kmsX := ""
				if kms != "" {
					kmsX = "<KmsKeyId>" + kms + "</KmsKeyId>"
				}
				_, _ = w.Write([]byte(`<DescribeReplicationGroupsResponse><DescribeReplicationGroupsResult>` +
					`<ReplicationGroups><ReplicationGroup><Status>available</Status>` +
					`<AtRestEncryptionEnabled>` + atRest + `</AtRestEncryptionEnabled>` +
					`<TransitEncryptionEnabled>` + transit + `</TransitEncryptionEnabled>` +
					`<AutomaticFailover>` + failover + `</AutomaticFailover>` +
					// D955: observe now reads MultiAZ (the zone-survival field); here it
					// agrees with failover (regional sets both), the divergent case has its
					// own test.
					`<MultiAZ>` + failover + `</MultiAZ>` + kmsX +
					`</ReplicationGroup></ReplicationGroups>` +
					`</DescribeReplicationGroupsResult></DescribeReplicationGroupsResponse>`))
			case "ListTagsForResource":
				// F28: ElastiCache (like the whole RDS Query family) returns tags as
				// <Tag>, NOT the EC2-style <member> — the parser and this fake had
				// AGREED on <member>, so the bug (real AWS tags read as empty → "not
				// ours") passed green. Render the real shape.
				_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><TagList>` +
					`<Tag><Key>groundhold-capability</Key><Value>` + tagCap + `</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
					`</TagList></ListTagsForResourceResult></ListTagsForResourceResponse>`))
			case "DeleteReplicationGroup":
				deleted = true
				_, _ = w.Write([]byte(`<DeleteReplicationGroupResponse></DeleteReplicationGroupResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func ecDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.ElastiCacheBaseURL = srv.URL
	d.KMSBaseURL = srv.URL // D800: the key is traced to KMS
	d.Account = "000000000000"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteElastiCache(t *testing.T) {
	srv := ecServer(t, "sessions", "true", "true", "enabled",
		"arn:aws:kms:eu-central-1:000000000000:key/abc")
	defer srv.Close()
	d := ecDriver(t, srv)
	res := d.createElastiCache("eu-central-1", "000000000000", "prod", "sessions", ecAttrs(), ecImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "ecredis:eu-central-1:000000000000:") {
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
	if got["encryption.atRest"] != true || got["encryption.inTransit"] != true ||
		got["encryption.customerManagedKeys"] != true || got["availability.class"] != "regional" ||
		got["network.publicExposure"] != false || got["location.region"] != "eu-central-1" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteElastiCache("sessions", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// D955: a replication group with AutomaticFailover=enabled but MultiAZ=disabled keeps its
// replica in the primary's own AZ — single-zone. observe must read MultiAZ (the field that
// carries zone survival) and report availability.class=zonal, not regional off the
// AutomaticFailover proxy. Field-confirmed 2026-08-08 that AWS accepts exactly this combo.
func TestObserveElastiCacheFailoverWithoutMultiAZIsZonal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		switch form.Get("Action") {
		case "DescribeReplicationGroups":
			_, _ = w.Write([]byte(`<DescribeReplicationGroupsResponse><DescribeReplicationGroupsResult>` +
				`<ReplicationGroups><ReplicationGroup><Status>available</Status>` +
				`<AutomaticFailover>enabled</AutomaticFailover><MultiAZ>disabled</MultiAZ>` +
				`</ReplicationGroup></ReplicationGroups>` +
				`</DescribeReplicationGroupsResult></DescribeReplicationGroupsResponse>`))
		case "ListTagsForResource":
			_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><TagList>` +
				`</TagList></ListTagsForResourceResult></ListTagsForResourceResponse>`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := ecDriver(t, srv)
	obs, _, err := d.observeElastiCache("sessions", "ecredis:eu-central-1:000000000000:pv-sessions-prod-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["availability.class"] != "zonal" {
		t.Fatalf("AutomaticFailover without MultiAZ must be zonal (single-zone), got %v", got["availability.class"])
	}
}

// TestDeleteElastiCacheAsyncNotGoneIsUnknown pins D970: a delete the provider
// ACCEPTS but that leaves the replication group "deleting" (not gone) must report
// unknown — never a terminal "succeeded" that tombstones a group still live.
func TestDeleteElastiCacheAsyncNotGoneIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			switch form.Get("Action") {
			case "DescribeReplicationGroups": // never gone — stays deleting
				_, _ = w.Write([]byte(`<DescribeReplicationGroupsResponse><DescribeReplicationGroupsResult>` +
					`<ReplicationGroups><ReplicationGroup><Status>deleting</Status></ReplicationGroup></ReplicationGroups>` +
					`</DescribeReplicationGroupsResult></DescribeReplicationGroupsResponse>`))
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><TagList>` +
					`<Tag><Key>groundhold-capability</Key><Value>sessions</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
					`</TagList></ListTagsForResourceResult></ListTagsForResourceResponse>`))
			case "DeleteReplicationGroup":
				_, _ = w.Write([]byte(`<DeleteReplicationGroupResponse></DeleteReplicationGroupResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := ecDriver(t, srv)
	d.PollTimeout = 5 * time.Millisecond // the group never leaves "deleting" → times out fast
	res := d.deleteElastiCache("sessions", "prod", "ecredis:eu-central-1:000000000000:pv-sessions-prod-1a2b")
	if res.Status != "unknown" {
		t.Fatalf("an accepted-but-still-deleting replication group must be unknown (keep the handle), "+
			"got %+v — reporting succeeded tombstones a group still live and billing", res)
	}
}

func TestDeleteElastiCacheForeignRefused(t *testing.T) {
	srv := ecServer(t, "someone-else", "true", "false", "disabled", "")
	defer srv.Close()
	d := ecDriver(t, srv)
	res := d.deleteElastiCache("sessions", "prod", "ecredis:eu-central-1:000000000000:x")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign group must refuse delete, got %+v", res)
	}
}

// TestElastiCacheSubnetGroupKey pins F26: the aurora-consistent key
// implementation.subnetGroupName is honored (and lands as CacheSubnetGroupName), with
// the old cache_subnet_group kept as a back-compat fallback. A key mismatch here left
// CreateReplicationGroup without a subnet group → AWS "account has no default subnets".
func TestElastiCacheSubnetGroupKey(t *testing.T) {
	impl := map[string]any{"kms_key_id": "arn:aws:kms:eu-central-1:000000000000:key/abc", "subnetGroupName": "acme-cache"}
	p, err := BuildElastiCacheCreate("000000000000", "prod", "sessions", ecAttrs(), impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.SubnetGroup != "acme-cache" {
		t.Fatalf("subnetGroupName not honored: %q", p.SubnetGroup)
	}
	if p.createParams("sessions", "prod")["CacheSubnetGroupName"] != "acme-cache" {
		t.Fatal("CacheSubnetGroupName missing from CreateReplicationGroup params")
	}
	// back-compat: the old snake_case key still works when the new one is absent.
	legacy := map[string]any{"kms_key_id": "arn:aws:kms:eu-central-1:000000000000:key/abc", "cache_subnet_group": "legacy-cache"}
	p2, _ := BuildElastiCacheCreate("000000000000", "prod", "sessions", ecAttrs(), legacy, 1)
	if p2.SubnetGroup != "legacy-cache" {
		t.Fatalf("cache_subnet_group back-compat broken: %q", p2.SubnetGroup)
	}
}

// TestEcacheTagsParsesTagElement pins F28: ElastiCache ListTagsForResource returns tags
// as <Tag> (the RDS Query family shape), NOT the EC2-style <member> the parser used to
// expect. The mismatch meant real ownership tags read as EMPTY, so reconcile concluded
// "does not carry our ownership tags" for a resource that DID carry them (Acme's live
// redis). Serving the real <Tag> shape, the tags must be read.
func TestEcacheTagsParsesTagElement(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><TagList>` +
			`<Tag><Key>groundhold-capability</Key><Value>sessions</Value></Tag>` +
			`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
			`</TagList></ListTagsForResourceResult></ListTagsForResourceResponse>`))
	}))
	defer srv.Close()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.ElastiCacheBaseURL = srv.URL
	d.KMSBaseURL = srv.URL // D800: the key is traced to KMS

	tags, terr := d.ecacheTags("eu-central-1", "000000000000", "red-x")
	if terr != nil {
		t.Fatalf("ecacheTags read failed: %v", terr)
	}
	if tags["groundhold-capability"] != "sessions" || tags["groundhold-environment"] != "prod" {
		t.Fatalf("ElastiCache <Tag> tags not parsed (F28): %v", tags)
	}
}

// D278: placement via implementation.subnetIds — the driver derives and owns
// the cache subnet group; two placement sources refuse.
func TestBuildElastiCacheSubnetIdsDerivesGroup(t *testing.T) {
	i := ecImpl()
	i["subnetIds"] = []any{"subnet-a", "subnet-b"}
	p, err := BuildElastiCacheCreate("000000000000", "prod", "sessions", ecAttrs(), i, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := derivedSubnetGroupName("prod", "sessions")
	if p.DeriveSubnetGroup != want || p.SubnetGroup != want {
		t.Fatalf("derived group = %q / SubnetGroup %q, want %q", p.DeriveSubnetGroup, p.SubnetGroup, want)
	}
	i["subnetGroupName"] = "acme-cache"
	if _, err := BuildElastiCacheCreate("000000000000", "prod", "sessions", ecAttrs(), i, 1); err == nil {
		t.Fatal("subnetGroupName+subnetIds together must refuse")
	}
}

// ensureCacheSubnetGroup: already-exists resolves by CONTENT — equal set is
// reused, a different set refuses (foreign or drifted).
func TestEnsureCacheSubnetGroupContentCheck(t *testing.T) {
	exists := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		body := string(b)
		switch {
		case strings.Contains(body, "Action=CreateCacheSubnetGroup"):
			if exists {
				w.WriteHeader(400)
				fmt.Fprint(w, `<ErrorResponse><Error><Code>CacheSubnetGroupAlreadyExists</Code></Error></ErrorResponse>`)
				return
			}
			exists = true
			fmt.Fprint(w, `<CreateCacheSubnetGroupResponse></CreateCacheSubnetGroupResponse>`)
		case strings.Contains(body, "Action=DescribeCacheSubnetGroups"):
			fmt.Fprint(w, `<DescribeCacheSubnetGroupsResponse><DescribeCacheSubnetGroupsResult><CacheSubnetGroups><CacheSubnetGroup>
				<Subnets><Subnet><SubnetIdentifier>subnet-a</SubnetIdentifier></Subnet><Subnet><SubnetIdentifier>subnet-b</SubnetIdentifier></Subnet></Subnets>
			</CacheSubnetGroup></CacheSubnetGroups></DescribeCacheSubnetGroupsResult></DescribeCacheSubnetGroupsResponse>`)
		default:
			t.Errorf("unexpected action: %s", body)
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.ElastiCacheBaseURL = srv.URL
	d.KMSBaseURL = srv.URL // D800: the key is traced to KMS

	if r := d.ensureCacheSubnetGroup("eu-central-1", "pv-x-sng-abc",
		[]string{"subnet-a", "subnet-b"}, "sessions", "prod"); r != nil {
		t.Fatalf("fresh create must ensure cleanly: %+v", r)
	}
	if r := d.ensureCacheSubnetGroup("eu-central-1", "pv-x-sng-abc",
		[]string{"subnet-b", "subnet-a"}, "sessions", "prod"); r != nil {
		t.Fatalf("already-exists with the SAME set (any order) must reuse: %+v", r)
	}
	r := d.ensureCacheSubnetGroup("eu-central-1", "pv-x-sng-abc",
		[]string{"subnet-a", "subnet-OTHER"}, "sessions", "prod")
	if r == nil || r.Status != "failed" || !strings.Contains(r.Reason, "DIFFERENT subnets") {
		t.Fatalf("already-exists with a different set must refuse: %+v", r)
	}
}

// ecacheAdoptSrv builds a 409-adopt fixture: our replication group already standing,
// with the encryption controls set however the case needs (D1062).
func ecacheAdoptSrv(atRest, transit bool, kmsKeyId, keyManager string) func() *httptest.Server {
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
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			switch form.Get("Action") {
			case "CreateReplicationGroup":
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>ReplicationGroupAlreadyExists</Code></Error></ErrorResponse>`))
			case "DescribeReplicationGroups":
				kmsX := ""
				if kmsKeyId != "" {
					kmsX = "<KmsKeyId>" + kmsKeyId + "</KmsKeyId>"
				}
				_, _ = w.Write([]byte(`<DescribeReplicationGroupsResponse><DescribeReplicationGroupsResult>` +
					`<ReplicationGroups><ReplicationGroup><Status>available</Status>` +
					`<AtRestEncryptionEnabled>` + boolStr(atRest) + `</AtRestEncryptionEnabled>` +
					`<TransitEncryptionEnabled>` + boolStr(transit) + `</TransitEncryptionEnabled>` +
					`<AutomaticFailover>enabled</AutomaticFailover><MultiAZ>enabled</MultiAZ>` + kmsX +
					`</ReplicationGroup></ReplicationGroups>` +
					`</DescribeReplicationGroupsResult></DescribeReplicationGroupsResponse>`))
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><TagList>` +
					`<Tag><Key>groundhold-capability</Key><Value>sessions</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
					`</TagList></ListTagsForResourceResult></ListTagsForResourceResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
	}
}

// TestAdoptsExistingElastiCache enrols elasticache in the D391 gate. The replication
// group id is deterministic and client-assigned, so a second create is answered
// ReplicationGroupAlreadyExists and the tags decide. This driver carries the F28 scar:
// the parser and the fake had AGREED on the wrong tag element, so "not ours" passed
// green against real AWS — which makes the ours-path worth asserting through the public
// dispatch rather than trusting the fake's shape.
func TestAdoptsExistingElastiCache(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:           "aws/elasticache",
		Classify:       rdsQueryRole,
		ExistingServer: ecacheAdoptSrv(true, true, "arn:aws:kms:eu-central-1:000000000000:key/abc", "CUSTOMER"),
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.ElastiCacheBaseURL = happyURL
			d.KMSBaseURL = happyURL    // D800: the key is traced to KMS
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("elasticache", "sessions", "prod", ecAttrs(), ecImpl(), "sessions", 1)
		},
		AllowedMutations: 1, // the refused CreateReplicationGroup
		// D1062: at-rest/in-transit encryption and the customer key are fixed at create;
		// each must block an adopt that lacks it.
		AdoptControls: ecacheAdoptControls,
		MissingControl: []certifynet.ControlCase{
			{Path: "encryption.atRest", WantStatus: "failed", WantMutations: 1,
				Server: ecacheAdoptSrv(false, true, "arn:aws:kms:eu-central-1:000000000000:key/abc", "CUSTOMER")},
			// D1220: in-transit is UpdateWired (the two-step TLS migration), so a group missing
			// enforced TLS BINDS (unknown) and converge reconciles it — not the old failed.
			{Path: "encryption.inTransit", WantStatus: "unknown", WantMutations: 1,
				Server: ecacheAdoptSrv(true, false, "arn:aws:kms:eu-central-1:000000000000:key/abc", "CUSTOMER")},
			{Path: "encryption.customerManagedKeys", WantStatus: "failed", WantMutations: 1,
				Server: ecacheAdoptSrv(true, true, "arn:aws:kms:eu-central-1:000000000000:key/abc", "AWS")}, // AWS-managed key → not customer
		},
		MoreSecure: ecacheAdoptSrv(true, true, "arn:aws:kms:eu-central-1:000000000000:key/abc", "CUSTOMER"),
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// D1219: encryption.inTransit must reflect ENFORCEMENT, not the bare TransitEncryptionEnabled
// flag. A group in TransitEncryptionMode=preferred has the flag true but still accepts plaintext,
// so the old read reported inTransit=true while the group spoke plaintext — a false green.
func TestObserveElastiCacheInTransitMode(t *testing.T) {
	rgWithMode := func(mode string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			switch form.Get("Action") {
			case "DescribeReplicationGroups":
				_, _ = w.Write([]byte(`<DescribeReplicationGroupsResponse><DescribeReplicationGroupsResult>` +
					`<ReplicationGroups><ReplicationGroup><Status>available</Status>` +
					`<AtRestEncryptionEnabled>true</AtRestEncryptionEnabled>` +
					`<TransitEncryptionEnabled>true</TransitEncryptionEnabled>` +
					`<TransitEncryptionMode>` + mode + `</TransitEncryptionMode>` +
					`<AutomaticFailover>enabled</AutomaticFailover><MultiAZ>enabled</MultiAZ>` +
					`</ReplicationGroup></ReplicationGroups>` +
					`</DescribeReplicationGroupsResult></DescribeReplicationGroupsResponse>`))
			default:
				w.WriteHeader(400)
			}
		}))
	}
	pid := "ecredis:eu-central-1:000000000000:pv-sessions-prod-abcd1234"

	t.Run("preferred still accepts plaintext -> inTransit false + diag", func(t *testing.T) {
		srv := rgWithMode("preferred")
		defer srv.Close()
		d := ecDriver(t, srv)
		obs, diags, err := d.observeElastiCache("sessions", pid)
		if err != nil {
			t.Fatal(err)
		}
		var it any
		for _, o := range obs {
			if o.Path == "encryption.inTransit" {
				it = o.Value
			}
		}
		if it != false {
			t.Fatalf("preferred mode must read inTransit=false (plaintext still allowed), got %v", it)
		}
		joined := strings.Join(diags, " | ")
		if !strings.Contains(joined, "preferred") {
			t.Fatalf("a preferred-mode group must carry a diag explaining TLS is not enforced, got %q", joined)
		}
	})

	t.Run("required enforces TLS -> inTransit true", func(t *testing.T) {
		srv := rgWithMode("required")
		defer srv.Close()
		d := ecDriver(t, srv)
		obs, _, err := d.observeElastiCache("sessions", pid)
		if err != nil {
			t.Fatal(err)
		}
		var it any
		for _, o := range obs {
			if o.Path == "encryption.inTransit" {
				it = o.Value
			}
		}
		if it != true {
			t.Fatalf("required mode must read inTransit=true (enforced), got %v", it)
		}
	})
}

// D1220: updateElastiCache enforces encryption.inTransit in place via the two-step, no-downtime
// migration — ModifyReplicationGroup to `preferred` (both encrypted and plaintext) then `required`
// (enforced), each polled to applied. succeeded only once the group is `required`. Foreign refused.
func TestUpdateElastiCacheInTransit(t *testing.T) {
	type modify struct{ enabled, mode string }
	// stateful fake: starts with TLS off; the two modifies walk it enabled+preferred -> required.
	enabled, mode := "false", ""
	var seen []modify
	rg := func() string {
		return `<DescribeReplicationGroupsResponse><DescribeReplicationGroupsResult><ReplicationGroups>` +
			`<ReplicationGroup><Status>available</Status><AtRestEncryptionEnabled>true</AtRestEncryptionEnabled>` +
			`<TransitEncryptionEnabled>` + enabled + `</TransitEncryptionEnabled>` +
			`<TransitEncryptionMode>` + mode + `</TransitEncryptionMode>` +
			`<AutomaticFailover>enabled</AutomaticFailover><MultiAZ>enabled</MultiAZ>` +
			`</ReplicationGroup></ReplicationGroups></DescribeReplicationGroupsResult></DescribeReplicationGroupsResponse>`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		switch form.Get("Action") {
		case "DescribeReplicationGroups":
			_, _ = w.Write([]byte(rg()))
		case "ListTagsForResource":
			_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><TagList>` +
				`<Tag><Key>groundhold-capability</Key><Value>sessions</Value></Tag>` +
				`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
				`</TagList></ListTagsForResourceResult></ListTagsForResourceResponse>`))
		case "ModifyReplicationGroup":
			m := modify{enabled: form.Get("TransitEncryptionEnabled"), mode: form.Get("TransitEncryptionMode")}
			seen = append(seen, m)
			if m.enabled == "true" {
				enabled = "true"
			}
			if m.mode != "" {
				mode = m.mode // the migration applies; the next Describe reflects it
			}
			_, _ = w.Write([]byte(`<ModifyReplicationGroupResponse></ModifyReplicationGroupResponse>`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := ecDriver(t, srv)
	pid := "ecredis:eu-central-1:000000000000:pv-sessions-prod-abcd1234"
	res := d.updateElastiCache("sessions", "prod", pid,
		map[string]any{"encryption.inTransit": true}, []string{"encryption.inTransit"})
	if res.Status != "succeeded" {
		t.Fatalf("update: %+v", res)
	}
	// two phases: enable+preferred, then required.
	if len(seen) != 2 ||
		seen[0].enabled != "true" || seen[0].mode != "preferred" ||
		seen[1].mode != "required" {
		t.Fatalf("must migrate preferred then required, got %+v", seen)
	}
}

func TestUpdateElastiCacheDisableRefused(t *testing.T) {
	// a group with TLS enforced (required); the contract wants it OFF — refused as a weakening.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		switch form.Get("Action") {
		case "DescribeReplicationGroups":
			_, _ = w.Write([]byte(`<DescribeReplicationGroupsResponse><DescribeReplicationGroupsResult><ReplicationGroups>` +
				`<ReplicationGroup><Status>available</Status><TransitEncryptionEnabled>true</TransitEncryptionEnabled>` +
				`<TransitEncryptionMode>required</TransitEncryptionMode></ReplicationGroup>` +
				`</ReplicationGroups></DescribeReplicationGroupsResult></DescribeReplicationGroupsResponse>`))
		case "ListTagsForResource":
			_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><TagList>` +
				`<Tag><Key>groundhold-capability</Key><Value>sessions</Value></Tag>` +
				`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
				`</TagList></ListTagsForResourceResult></ListTagsForResourceResponse>`))
		default:
			t.Errorf("disable must not %s", form.Get("Action"))
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := ecDriver(t, srv)
	res := d.updateElastiCache("sessions", "prod", "ecredis:eu-central-1:000000000000:pv-sessions-prod-abcd1234",
		map[string]any{"encryption.inTransit": false}, []string{"encryption.inTransit"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "weakening") {
		t.Fatalf("disabling TLS must be refused as a weakening, got %+v", res)
	}
}

func TestClassifyElastiCacheChange(t *testing.T) {
	if got, _ := classifyElastiCacheChange("encryption.inTransit"); got != "mutable" {
		t.Fatalf("encryption.inTransit must be mutable, got %q", got)
	}
	for _, p := range []string{"encryption.atRest", "location.region", "durability.class"} {
		if got, _ := classifyElastiCacheChange(p); got != "immutable" {
			t.Fatalf("%s must be immutable, got %q", p, got)
		}
	}
}
