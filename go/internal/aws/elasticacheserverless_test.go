package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"bytes"
	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func ecslAttrs() map[string]any {
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

func ecslImpl() map[string]any {
	return map[string]any{
		"kms_key_id":       "arn:aws:kms:eu-central-1:000000000000:key/abc",
		"subnetIds":        []any{"subnet-a", "subnet-b"},
		"securityGroupIds": []any{"sg-1"},
	}
}

func TestBuildElastiCacheServerlessHonors(t *testing.T) {
	p, err := BuildElastiCacheServerlessCreate("000000000000", "prod", "sessions", ecslAttrs(), ecslImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Engine != "redis" || p.MajorEngineVersion != "7" || p.KmsKeyID == "" {
		t.Fatalf("plan = %+v", p)
	}
	if !ecacheIDOK.MatchString(p.Name) {
		t.Fatalf("name invalid: %q", p.Name)
	}
	form := p.createParams("sessions", "prod")
	for k, want := range map[string]string{
		"Action":                    "CreateServerlessCache",
		"Engine":                    "redis",
		"MajorEngineVersion":        "7",
		"SubnetIds.member.1":        "subnet-a",
		"SubnetIds.member.2":        "subnet-b",
		"SecurityGroupIds.member.1": "sg-1",
		"KmsKeyId":                  "arn:aws:kms:eu-central-1:000000000000:key/abc",
		"Tags.member.1.Key":         "groundhold-capability",
	} {
		if form[k] != want {
			t.Errorf("form[%q] = %q, want %q", k, form[k], want)
		}
	}
	// serverless has NO sizing params — the point of the backend.
	for _, forbidden := range []string{"CacheNodeType", "NumNodeGroups", "ReplicasPerNodeGroup", "MultiAZEnabled", "CacheSubnetGroupName"} {
		if _, ok := form[forbidden]; ok {
			t.Errorf("serverless create must not carry provisioned sizing param %q", forbidden)
		}
	}
}

// TestBuildElastiCacheServerlessValkey: valkey is honored (the redis-compatible fork).
func TestBuildElastiCacheServerlessValkey(t *testing.T) {
	a := ecslAttrs()
	a["engine.protocol"] = "valkey/8"
	p, err := BuildElastiCacheServerlessCreate("000000000000", "prod", "sessions", a, ecslImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Engine != "valkey" || p.MajorEngineVersion != "8" {
		t.Fatalf("valkey/8 plan = %+v", p)
	}
}

func TestBuildElastiCacheServerlessRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"engine.protocol": "redis/7", "location.region": "eu-central-1",
			"encryption.atRest": true, "service.managed": true}
	}
	cases := map[string]map[string]any{
		"public-refused":  {"network.publicExposure": true},
		"atRest-false":    {"encryption.atRest": false},
		"inTransit-false": {"encryption.inTransit": false},
		"unmanaged":       {"service.managed": false},
		"zonal":           {"availability.class": "zonal"},
		"multi-regional":  {"availability.class": "multi-regional"},
		"memcached":       {"engine.protocol": "memcached/1.6"},
		"old-redis":       {"engine.protocol": "redis/6"},
		"unknown-attr":    {"eviction.policy": "lru"},
	}
	for name, extra := range cases {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildElastiCacheServerlessCreate("000000000000", "prod", "sessions", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// CMK without a key refuses.
	cmk := base()
	cmk["encryption.customerManagedKeys"] = true
	if _, err := BuildElastiCacheServerlessCreate("000000000000", "prod", "sessions", cmk, nil, 1); err == nil {
		t.Error("CMK without kms_key_id must refuse")
	}
}

func TestClassifyElastiCacheServerlessChange(t *testing.T) {
	if c, _ := classifyElastiCacheServerlessChange("location.region"); c != "immutable" {
		t.Errorf("location.region must be immutable (replacement), got %q", c)
	}
	if c, _ := classifyElastiCacheServerlessChange("encryption.atRest"); c != "unsupported" {
		t.Errorf("encryption.atRest must be unsupported (always-on), got %q", c)
	}
	if c, _ := classifyElastiCacheServerlessChange("availability.class"); c != "unsupported" {
		t.Errorf("availability.class must be unsupported (regional by construction), got %q", c)
	}
}

func TestSplitECacheServerlessProviderID(t *testing.T) {
	if _, _, _, err := splitECacheServerlessProviderID("ecserverless:eu-central-1:000000000000:sessions-abcd1234"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	for _, bad := range []string{
		"ecredis:eu-central-1:000000000000:x", // provisioned prefix, not serverless
		"ecserverless:bad:000000000000:x",
		"ecserverless:eu-central-1:bad:x",
		"eu:app",
	} {
		if _, _, _, err := splitECacheServerlessProviderID(bad); err == nil {
			t.Errorf("accepted malformed serverless id %q", bad)
		}
	}
}

// ecslFake serves the ElastiCache Serverless Query actions and RECORDS every
// Action seen, so the LRO anti-regression test can assert the poll concluded on
// the OBSERVABLE cache Status and NEVER hit an operation-by-id call (D273).
type ecslFake struct {
	tagCap  string
	stuck   string // if set, DescribeServerlessCaches always returns this Status
	seen    []string
	deleted bool
}

func (f *ecslFake) handler(t *testing.T) *httptest.Server {
	t.Helper()
	if f.tagCap == "" {
		f.tagCap = "sessions"
	}
	arn := "arn:aws:elasticache:eu-central-1:000000000000:serverlesscache:x"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		action := form.Get("Action")
		f.seen = append(f.seen, action)
		switch action {
		case "CreateServerlessCache":
			_, _ = w.Write([]byte(`<CreateServerlessCacheResponse><CreateServerlessCacheResult><ServerlessCache>` +
				`<ServerlessCacheName>x</ServerlessCacheName><Status>CREATING</Status><ARN>` + arn + `</ARN>` +
				`</ServerlessCache></CreateServerlessCacheResult></CreateServerlessCacheResponse>`))
		case "DescribeServerlessCaches":
			if f.deleted {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>ServerlessCacheNotFoundFault</Code></Error></ErrorResponse>`))
				return
			}
			status := "AVAILABLE"
			if f.stuck != "" {
				status = f.stuck
			}
			// D936: real AWS wraps each list member in <member>, not <ServerlessCache>.
			_, _ = w.Write([]byte(`<DescribeServerlessCachesResponse><DescribeServerlessCachesResult>` +
				`<ServerlessCaches><member><ServerlessCacheName>x</ServerlessCacheName>` +
				`<Status>` + status + `</Status><ARN>` + arn + `</ARN>` +
				`<Engine>redis</Engine><MajorEngineVersion>7</MajorEngineVersion>` +
				`<Endpoint><Address>x.serverless.euc1.cache.amazonaws.com</Address><Port>6379</Port></Endpoint>` +
				`</member></ServerlessCaches>` +
				`</DescribeServerlessCachesResult></DescribeServerlessCachesResponse>`))
		case "ListTagsForResource":
			// AWS ElastiCache ListTagsForResource uses <TagList><Tag> (verified against
			// the real API 2026-08-08) — unlike DescribeServerlessCaches, which wraps
			// list members in <member> (D936). AWS is not internally consistent here.
			_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><TagList>` +
				`<Tag><Key>groundhold-capability</Key><Value>` + f.tagCap + `</Value></Tag>` +
				`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
				`</TagList></ListTagsForResourceResult></ListTagsForResourceResponse>`))
		case "DeleteServerlessCache":
			f.deleted = true
			_, _ = w.Write([]byte(`<DeleteServerlessCacheResponse></DeleteServerlessCacheResponse>`))
		default:
			w.WriteHeader(404)
		}
	}))
}

func ecslDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.ElastiCacheServerlessBaseURL = srv.URL
	d.Account = "000000000000"
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

// TestCreateObserveDeleteElastiCacheServerless: create -> poll AVAILABLE ->
// observe -> delete. Asserts the D273 discipline: the poll concluded on the
// OBSERVABLE cache Status (DescribeServerlessCaches) and NEVER hit an
// operation-by-id call.
func TestCreateObserveDeleteElastiCacheServerless(t *testing.T) {
	f := &ecslFake{}
	srv := f.handler(t)
	defer srv.Close()
	d := ecslDriver(t, srv)

	res := d.createElastiCacheServerless("eu-central-1", "000000000000", "prod", "sessions", ecslAttrs(), ecslImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "ecserverless:eu-central-1:000000000000:") {
		t.Fatalf("create: %+v", res)
	}
	sawDescribe := false
	for _, a := range f.seen {
		if strings.Contains(a, "Operation") { // ListOperations / DescribeOperation-style
			t.Fatalf("D273 violation: the poll hit an operation-by-id call %q", a)
		}
		if a == "DescribeServerlessCaches" {
			sawDescribe = true
		}
	}
	if !sawDescribe {
		t.Fatal("the create poll must read the observable cache state via DescribeServerlessCaches")
	}

	obs, _, err := d.observeElastiCacheServerless("sessions", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["encryption.atRest"] != true || got["encryption.inTransit"] != true ||
		got["availability.class"] != "regional" || got["network.publicExposure"] != false ||
		got["location.region"] != "eu-central-1" || got["engine.protocol"] != "redis/7" {
		t.Fatalf("observe: %+v", got)
	}

	if del := d.deleteElastiCacheServerless("sessions", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteElastiCacheServerlessForeignRefused(t *testing.T) {
	f := &ecslFake{tagCap: "someone-else"}
	srv := f.handler(t)
	defer srv.Close()
	d := ecslDriver(t, srv)
	res := d.deleteElastiCacheServerless("sessions", "prod", "ecserverless:eu-central-1:000000000000:x")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign cache must refuse delete, got %+v", res)
	}
}

// TestElastiCacheServerlessEndpointOutput: the endpoint output is derived from
// one live read (host:port), the honest source for a created OR adopted cache.
func TestElastiCacheServerlessEndpointOutput(t *testing.T) {
	f := &ecslFake{}
	srv := f.handler(t)
	defer srv.Close()
	d := ecslDriver(t, srv)
	outs, err := d.deriveOutputs("elasticache-serverless", "ecserverless:eu-central-1:000000000000:x")
	if err != nil {
		t.Fatal(err)
	}
	if outs["endpoint"] != "x.serverless.euc1.cache.amazonaws.com:6379" {
		t.Fatalf("endpoint output = %v", outs["endpoint"])
	}
}

// TestBoundedPollElastiCacheServerless enrolls the serverless cache in the D266
// bounded-poll gate: a cache stuck in CREATING must conclude unknown-with-pid
// within the poll budget, never hang, never a false success.
func TestBoundedPollElastiCacheServerless(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.LifecycleProbe{
		Name: "aws/elasticache-serverless",
		StuckServer: func() *httptest.Server {
			f := &ecslFake{stuck: "CREATING"}
			return f.handler(t)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000"
			d.ElastiCacheServerlessBaseURL = happyURL
			d.PollInterval = 0
			d.PollTimeout = time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("elasticache-serverless", "capability.cache.keyvalue", "prod",
				ecslAttrs(), ecslImpl(), "k", 1)
		},
		PID: ecacheServerlessProviderID("eu-central-1", "000000000000",
			ecacheID("000000000000", "prod", "capability.cache.keyvalue", 1)),
	}
	certifynet.CertifyBoundedPoll(t, p)
}

// TestAdoptsExistingElastiCacheServerless enrols elasticache-serverless in the D391
// gate: the cache name is deterministic, a second create is answered
// ServerlessCacheAlreadyExistsFault, and the tags off the ARN decide.
func TestAdoptsExistingElastiCacheServerless(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:     "aws/elasticache-serverless",
		Classify: rdsQueryRole,
		ExistingServer: func() *httptest.Server {
			f := &ecslFake{}
			inner := f.handler(t)
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				form, _ := url.ParseQuery(string(body))
				if form.Get("Action") == "CreateServerlessCache" {
					w.WriteHeader(400)
					_, _ = w.Write([]byte(`<ErrorResponse><Error>` +
						`<Code>ServerlessCacheAlreadyExistsFault</Code></Error></ErrorResponse>`))
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(body))
				r.ContentLength = int64(len(body))
				inner.Config.Handler.ServeHTTP(w, r)
			}))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.ElastiCacheServerlessBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("elasticache-serverless", "sessions", "prod", ecslAttrs(), ecslImpl(), "sessions", 1)
		},
		AllowedMutations: 1, // the refused create
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// D937: discoverElastiCacheServerless had the SAME wrong list element as the
// lifecycle read (D936) — a second copy the D936 fix missed. With <ServerlessCache>
// instead of <member>, brownfield discovery parses ZERO caches and reports a live
// serverless cache as ABSENT — the dangerous false-absence: onboarding misses it,
// and a later create makes a duplicate.
func TestDiscoverElastiCacheServerlessSeesTheCache(t *testing.T) {
	f := &ecslFake{}
	srv := f.handler(t)
	defer srv.Close()
	d := ecslDriver(t, srv)
	d.Account = "000000000000" // skip CallerIdentity

	found, diags, err := d.discoverElastiCacheServerless("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("discovery found %d serverless caches, want 1 — a wrong list element reads a "+
			"live cache as absent (D937 false-absence in onboarding); diags %v", len(found), diags)
	}
}
