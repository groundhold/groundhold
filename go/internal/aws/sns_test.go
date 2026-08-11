package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func snsAttrs() map[string]any {
	return map[string]any{
		"location.region":        "eu-central-1",
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"service.managed":        true,
	}
}

func TestTopicNameDeterministic(t *testing.T) {
	n := TopicName("000000000000", "prod", "events", 1)
	if !snsNameOK.MatchString(n) {
		t.Fatalf("topic name not valid: %q", n)
	}
	if n != TopicName("000000000000", "prod", "events", 1) {
		t.Fatal("topic name must be deterministic")
	}
	if g2 := TopicName("000000000000", "prod", "events", 2); g2 == n {
		t.Fatal("a replacement (g2) must not collide with g1")
	}
}

// atRest without CMEK is honored via the AWS-managed alias/aws/sns key (genuine
// provider-default SSE) — NOT refused.
func TestBuildSNSAtRestProviderDefault(t *testing.T) {
	plan, err := BuildSNSCreate("acct", "prod", "events", snsAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.KmsKeyID != snsAWSManagedKey {
		t.Fatalf("atRest without CMEK must use %q, got %q", snsAWSManagedKey, plan.KmsKeyID)
	}
}

// atRest=false is honestly honorable (SNS is unencrypted by default) — no key.
func TestBuildSNSNoEncryption(t *testing.T) {
	a := snsAttrs()
	a["encryption.atRest"] = false
	plan, err := BuildSNSCreate("acct", "prod", "events", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.KmsKeyID != "" {
		t.Fatalf("atRest=false must set NO key, got %q", plan.KmsKeyID)
	}
}

func TestBuildSNSCMEK(t *testing.T) {
	a := snsAttrs()
	a["encryption.customerManagedKeys"] = true
	impl := map[string]any{"kms_key_id": "arn:aws:kms:eu-central-1:000000000000:key/abc"}
	plan, err := BuildSNSCreate("acct", "prod", "events", a, impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.KmsKeyID != impl["kms_key_id"] {
		t.Fatalf("CMEK must use the customer key, got %q", plan.KmsKeyID)
	}
}

func TestBuildSNSRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate func(map[string]any)
		impl   map[string]any
	}{
		"cmek without key":  {func(a map[string]any) { a["encryption.customerManagedKeys"] = true }, nil},
		"cmek with aws key": {func(a map[string]any) { a["encryption.customerManagedKeys"] = true }, map[string]any{"kms_key_id": snsAWSManagedKey}},
		"unmanaged":         {func(a map[string]any) { a["service.managed"] = false }, nil},
		"no region":         {func(a map[string]any) { delete(a, "location.region") }, nil},
		"bad region":        {func(a map[string]any) { a["location.region"] = "not a region" }, nil},
		"unknown attr":      {func(a map[string]any) { a["engine.protocol"] = "x" }, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := snsAttrs()
			c.mutate(a)
			if _, err := BuildSNSCreate("acct", "prod", "events", a, c.impl, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}

func TestSNSPublicPolicyIsAnonymous(t *testing.T) {
	pol := snsPublicPolicy("arn:aws:sns:eu-central-1:000000000000:events-x")
	pub, ok := snsPolicyPublic(pol)
	if !ok || !pub {
		t.Fatalf("the public policy must read back as public, got public=%v parseable=%v", pub, ok)
	}
}

func TestSNSPolicyPrivateNotPublic(t *testing.T) {
	// an owner-only statement (a real account principal, no wildcard) is NOT public
	pol := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sns:Publish"}]}`
	pub, ok := snsPolicyPublic(pol)
	if !ok || pub {
		t.Fatalf("an owner-only policy must not be public, got public=%v parseable=%v", pub, ok)
	}
	// a conditioned wildcard is NOT an unconditional public path
	cond := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sns:Publish","Condition":{"StringEquals":{"aws:SourceOwner":"000000000000"}}}]}`
	if pub, _ := snsPolicyPublic(cond); pub {
		t.Fatal("a conditioned wildcard must not read as public")
	}
}

func TestSplitSNSProviderID(t *testing.T) {
	if _, _, _, err := splitSNSProviderID("sns:eu-central-1:000000000000:events-x"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	for _, bad := range []string{
		"sns:eu-central-1:events", "rds:eu-central-1:000000000000:events",
		"sns:badregion:000000000000:events", "sns:eu-central-1:12:events",
		"sns:eu-central-1:000000000000:bad/name",
	} {
		if _, _, _, err := splitSNSProviderID(bad); err == nil {
			t.Errorf("accepted malformed sns id %q", bad)
		}
	}
}

// snsServer answers the SNS Query protocol with OUR ownership tags — used by the
// honesty harness and the happy-path unit tests.
func snsServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch queryAction(body) {
			case "CreateTopic":
				_, _ = w.Write([]byte(`<CreateTopicResponse><CreateTopicResult>` +
					`<TopicArn>arn:aws:sns:eu-central-1:000000000000:t</TopicArn>` +
					`</CreateTopicResult></CreateTopicResponse>`))
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><Tags>` +
					`<member><Key>groundhold-capability</Key><Value>events</Value></member>` +
					`<member><Key>groundhold-environment</Key><Value>prod</Value></member>` +
					`</Tags></ListTagsForResourceResult></ListTagsForResourceResponse>`))
			case "SetTopicAttributes":
				_, _ = w.Write([]byte(`<SetTopicAttributesResponse></SetTopicAttributesResponse>`))
			case "GetTopicAttributes":
				_, _ = w.Write([]byte(`<GetTopicAttributesResponse><GetTopicAttributesResult><Attributes>` +
					`<entry><key>KmsMasterKeyId</key><value>alias/aws/sns</value></entry>` +
					`</Attributes></GetTopicAttributesResult></GetTopicAttributesResponse>`))
			case "DeleteTopic":
				_, _ = w.Write([]byte(`<DeleteTopicResponse></DeleteTopicResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func snsTestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.SNSBaseURL = srv.URL
	d.Account = "000000000000"
	return d
}

func TestCreateSNSHappyPath(t *testing.T) {
	srv := snsServer(t)
	defer srv.Close()
	d := snsTestDriver(t, srv)
	res := d.createSNS("eu-central-1", "000000000000", "prod", "events", snsAttrs(), nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "sns:eu-central-1:000000000000:") {
		t.Fatalf("got %+v, want succeeded + sns-prefixed id", res)
	}
}

// An untagged same-account topic (CreateTopic did not apply our tags) must NOT
// be silently taken over — unknown carrying the deterministic pid (mirrors S3).
func TestCreateSNSUntaggedRefusesToAdopt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch queryAction(body) {
			case "CreateTopic":
				_, _ = w.Write([]byte(`<CreateTopicResponse></CreateTopicResponse>`))
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult>` +
					`<Tags></Tags></ListTagsForResourceResult></ListTagsForResourceResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := snsTestDriver(t, srv)
	res := d.createSNS("eu-central-1", "000000000000", "prod", "events", snsAttrs(), nil, 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("an untagged topic must be unknown WITH a pid, got %+v", res)
	}
}

// A foreign-tagged same-account topic is refused (failed), never reconfigured.
func TestCreateSNSForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch queryAction(body) {
			case "CreateTopic":
				_, _ = w.Write([]byte(`<CreateTopicResponse></CreateTopicResponse>`))
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><Tags>` +
					`<member><Key>groundhold-capability</Key><Value>other</Value></member>` +
					`</Tags></ListTagsForResourceResult></ListTagsForResourceResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := snsTestDriver(t, srv)
	res := d.createSNS("eu-central-1", "000000000000", "prod", "events", snsAttrs(), nil, 1)
	if res.Status != "failed" {
		t.Fatalf("a foreign-tagged topic must be refused, got %+v", res)
	}
}

func TestDeleteSNSOurs(t *testing.T) {
	srv := snsServer(t)
	defer srv.Close()
	d := snsTestDriver(t, srv)
	res := d.deleteSNS("events", "prod", "sns:eu-central-1:000000000000:events-x")
	if res.Status != "succeeded" {
		t.Fatalf("delete of an owned topic must succeed, got %+v", res)
	}
}

func TestDeleteSNSForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if queryAction(body) == "ListTagsForResource" {
				_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><Tags>` +
					`<member><Key>groundhold-capability</Key><Value>other</Value></member>` +
					`</Tags></ListTagsForResourceResult></ListTagsForResourceResponse>`))
				return
			}
			t.Errorf("delete must not proceed past the ownership check, saw %s", queryAction(body))
			w.WriteHeader(404)
		}))
	defer srv.Close()
	d := snsTestDriver(t, srv)
	res := d.deleteSNS("events", "prod", "sns:eu-central-1:000000000000:events-x")
	if res.Status != "failed" {
		t.Fatalf("delete of a foreign topic must be refused, got %+v", res)
	}
}

// Weapon 2 (D87): the metamorphic write/read round-trip. A stateful fake records
// what SetTopicAttributes WRITES (KmsMasterKeyId, Policy) and reflects it on
// GetTopicAttributes; the test asserts observeSNS reverse-maps the SAME semantic
// attributes create was given.
func metamorphicSNSServer(t *testing.T) *httptest.Server {
	t.Helper()
	var kms, policy string
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(raw))
			switch form.Get("Action") {
			case "CreateTopic":
				_, _ = w.Write([]byte(`<CreateTopicResponse></CreateTopicResponse>`))
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><Tags>` +
					`<member><Key>groundhold-capability</Key><Value>events</Value></member>` +
					`<member><Key>groundhold-environment</Key><Value>prod</Value></member>` +
					`</Tags></ListTagsForResourceResult></ListTagsForResourceResponse>`))
			case "SetTopicAttributes":
				switch form.Get("AttributeName") {
				case "KmsMasterKeyId":
					kms = form.Get("AttributeValue")
				case "Policy":
					policy = form.Get("AttributeValue")
				}
				_, _ = w.Write([]byte(`<SetTopicAttributesResponse></SetTopicAttributesResponse>`))
			case "GetTopicAttributes":
				entries := ""
				if kms != "" {
					entries += `<entry><key>KmsMasterKeyId</key><value>` + xmlEsc(kms) + `</value></entry>`
				}
				if policy != "" {
					entries += `<entry><key>Policy</key><value>` + xmlEsc(policy) + `</value></entry>`
				}
				_, _ = w.Write([]byte(`<GetTopicAttributesResponse><GetTopicAttributesResult><Attributes>` +
					entries + `</Attributes></GetTopicAttributesResult></GetTopicAttributesResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestMetamorphicSNSRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		public   bool
		atRest   bool
		cmek     bool
		wantCMEK bool
	}{
		{"private-provider-default", false, true, false, false},
		{"public-cmek", true, true, true, true},
		{"unencrypted-private", false, false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicSNSServer(t)
			defer srv.Close()
			d := snsTestDriver(t, srv)
			attrs := map[string]any{
				"location.region":        "eu-central-1",
				"network.publicExposure": c.public,
				"encryption.atRest":      c.atRest,
				"service.managed":        true,
			}
			var impl map[string]any
			if c.cmek {
				attrs["encryption.customerManagedKeys"] = true
				impl = map[string]any{"kms_key_id": "arn:aws:kms:eu-central-1:000000000000:key/abc"}
			}
			res := d.createSNS("eu-central-1", "000000000000", "prod", "events", attrs, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create failed: %+v", res)
			}
			obs, _, err := d.observeSNS("events", res.ProviderID)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["location.region"] != "eu-central-1" {
				t.Errorf("region round-trip broke: %v", got["location.region"])
			}
			if got["network.publicExposure"] != c.public {
				t.Errorf("public round-trip broke: wrote %v observed %v", c.public, got["network.publicExposure"])
			}
			wantEncrypted := c.atRest || c.cmek
			if got["encryption.atRest"] != wantEncrypted {
				t.Errorf("atRest round-trip broke: want %v observed %v", wantEncrypted, got["encryption.atRest"])
			}
			if got["encryption.customerManagedKeys"] != c.cmek {
				t.Errorf("cmek round-trip broke: want %v observed %v", c.cmek, got["encryption.customerManagedKeys"])
			}
		})
	}
}

func snsRole(_ *http.Request, body []byte) certifynet.Role {
	switch queryAction(body) {
	case "ListTagsForResource", "GetTopicAttributes", "ListTopics":
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingSNS enrols SNS in the D391 gate. CreateTopic is idempotent by NAME —
// it returns the existing topic's ARN rather than minting a second one — so the
// load-bearing proof here is the pid: the create must bind the topic that already
// exists, carrying our tags. The untagged and foreign cases already have tests; the
// OURS case did not.
func TestAdoptsExistingSNS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:     "aws/sns",
		Classify: snsRole,
		ExistingServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					switch queryAction(body) {
					case "CreateTopic":
						_, _ = w.Write([]byte(`<CreateTopicResponse></CreateTopicResponse>`))
					case "ListTagsForResource":
						_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><Tags>` +
							`<member><Key>groundhold-capability</Key><Value>events</Value></member>` +
							`<member><Key>groundhold-environment</Key><Value>prod</Value></member>` +
							`</Tags></ListTagsForResourceResult></ListTagsForResourceResponse>`))
					default:
						_, _ = w.Write([]byte(`<Response></Response>`))
					}
				}))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.SNSBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("sns", "events", "prod", snsAttrs(), nil, "events", 1)
		},
		// The pid is the deterministic name the plan builds; the gate asserts a pid is
		// bound at all, and the tags-match path is what makes binding legitimate.
		AllowedMutations: 4, // name-idempotent CreateTopic + attribute convergence
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
