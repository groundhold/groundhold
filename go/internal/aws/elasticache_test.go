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
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			switch form.Get("Action") {
			case "CreateReplicationGroup":
				_, _ = w.Write([]byte(`<CreateReplicationGroupResponse></CreateReplicationGroupResponse>`))
			case "DescribeReplicationGroups":
				kmsX := ""
				if kms != "" {
					kmsX = "<KmsKeyId>" + kms + "</KmsKeyId>"
				}
				_, _ = w.Write([]byte(`<DescribeReplicationGroupsResponse><DescribeReplicationGroupsResult>` +
					`<ReplicationGroups><ReplicationGroup><Status>available</Status>` +
					`<AtRestEncryptionEnabled>` + atRest + `</AtRestEncryptionEnabled>` +
					`<TransitEncryptionEnabled>` + transit + `</TransitEncryptionEnabled>` +
					`<AutomaticFailover>` + failover + `</AutomaticFailover>` + kmsX +
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
