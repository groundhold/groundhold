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

// The CloudFront + OAC -> Lambda Function URL (AuthType AWS_IAM) edge pattern:
// a serverless api is public at the edge WITHOUT anonymous invoke. These golden
// tests pin the three wired parts — the IAM-auth URL (no anonymous grant), the
// OAC + Function-URL origin, and the SourceArn-scoped invoke grant — plus the
// outputs the $ref graph rides on and the OAC reverse-delete.

// TestLambdaURLAuthIAMNoAnonymousGrant: url_auth=iam creates the Function URL with
// AuthType=AWS_IAM and adds NO principal:* grant (the org RCP forbids it) — the
// invoke grant is left to the fronting CloudFront distribution.
func TestLambdaURLAuthIAMNoAnonymousGrant(t *testing.T) {
	var urlAuthType string
	var policyCalled bool
	created := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case r.Method == "POST" && strings.HasSuffix(p, "/url"):
			b, _ := io.ReadAll(r.Body)
			var body struct{ AuthType string }
			_ = json.Unmarshal(b, &body)
			urlAuthType = body.AuthType
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"FunctionUrl":"https://abc123.lambda-url.eu-central-1.on.aws/","AuthType":"` + body.AuthType + `"}`))
		case r.Method == "POST" && strings.HasSuffix(p, "/policy"):
			policyCalled = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Statement":"{}"}`))
		case r.Method == "POST" && strings.HasSuffix(p, "/functions"):
			created = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"FunctionName":"fn","State":"Pending"}`))
		case r.Method == "GET" && strings.HasSuffix(p, "/url"):
			_, _ = w.Write([]byte(`{"AuthType":"AWS_IAM","FunctionUrl":"https://abc123.lambda-url.eu-central-1.on.aws/"}`))
		case r.Method == "GET" && strings.Contains(p, "/functions/"):
			if !created {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"Configuration":{"State":"Active","Timeout":300},` +
				`"Tags":{"groundhold-capability":"api","groundhold-environment":"prod"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	d := lambdaDriver(t, srv)

	attrs := lambdaAttrs()
	// D749: the edge function is NOT publicly exposed — a SigV4-signed CloudFront is
	// the only caller. This test declared `true` because the create path used to read
	// the attribute as "has a Function URL"; under the vocabulary's definition, which
	// observe has always measured, that declaration can never converge.
	attrs["network.publicExposure"] = false
	impl := lambdaImpl()
	impl["url_auth"] = "iam"
	res := d.createLambda("eu-central-1", "000000000000", "prod", "api", attrs, impl, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	if urlAuthType != "AWS_IAM" {
		t.Fatalf("Function URL AuthType = %q, want AWS_IAM", urlAuthType)
	}
	if policyCalled {
		t.Fatal("url_auth=iam must NOT add an anonymous principal:* grant")
	}
}

// D749 SUPERSEDES TestLambdaURLAuthIAMRequiresPublic, which asserted that
// `url_auth: iam` on a private function must REFUSE. That assertion was the defect
// written down: it read `network.publicExposure` as "has a Function URL", while the
// vocabulary defines it as "invokable over public HTTPS by anyone" and observe measures
// it that way. Under the old rule the edge pattern had no honest declaration, and the
// one declaration that passed made the plan want to open the function. The refusal that
// remains is the MIRROR: iam WITH public exposure, which cannot converge.
func TestLambdaURLAuthContradictionsRefuse(t *testing.T) {
	attrs := lambdaAttrs() // publicExposure: true
	impl := lambdaImpl()
	impl["url_auth"] = "iam"
	if _, err := BuildLambda("000000000000", "prod", "api", attrs, impl, 1); err == nil {
		t.Fatal("url_auth=iam with publicExposure:true must refuse — an AWS_IAM URL has " +
			"no anonymous grant, so observe measures false forever and it never converges")
	}
	// an unknown url_auth value refuses
	impl2 := lambdaImpl()
	impl2["url_auth"] = "sigv4-please"
	if _, err := BuildLambda("000000000000", "prod", "api", lambdaAttrs(), impl2, 1); err == nil {
		t.Fatal("an unknown url_auth value must refuse")
	}
}

// TestLambdaFunctionURLOutputs: functionArn/functionName from the pid; the URL
// outputs from one GetFunctionUrlConfig read; a private function (404) omits the
// URL outputs rather than failing (attachOutputs must not demote it).
func TestLambdaFunctionURLOutputs(t *testing.T) {
	hasURL := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/url") {
			if !hasURL {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"AuthType":"AWS_IAM","FunctionUrl":"https://abc123.lambda-url.eu-central-1.on.aws/"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := lambdaDriver(t, srv)

	pid := lambdaProviderID("eu-central-1", "000000000000", "pv-api-prod-1a2b3c4d")
	outs, err := d.deriveOutputs("lambda", pid)
	if err != nil {
		t.Fatal(err)
	}
	if outs["functionArn"] != "arn:aws:lambda:eu-central-1:000000000000:function:pv-api-prod-1a2b3c4d" {
		t.Fatalf("functionArn = %v", outs["functionArn"])
	}
	if outs["functionName"] != "pv-api-prod-1a2b3c4d" {
		t.Fatalf("functionName = %v", outs["functionName"])
	}
	if outs["functionUrl"] != "https://abc123.lambda-url.eu-central-1.on.aws/" {
		t.Fatalf("functionUrl = %v", outs["functionUrl"])
	}
	if outs["functionUrlDomain"] != "abc123.lambda-url.eu-central-1.on.aws" {
		t.Fatalf("functionUrlDomain = %v", outs["functionUrlDomain"])
	}

	// private function: the URL outputs are OMITTED, never fabricated. Asserted by
	// their absence rather than by counting the map — the derived outputs (arn,
	// name, log group) are a growing set, and a count would fail on every honest
	// addition while catching nothing.
	hasURL = false
	outs, err = d.deriveOutputs("lambda", pid)
	if err != nil {
		t.Fatal(err)
	}
	if outs["functionUrl"] != nil || outs["functionUrlDomain"] != nil {
		t.Fatalf("a private function must omit URL outputs, got %v", outs)
	}
	// the derived-from-the-pid outputs are present either way
	for _, want := range []string{"functionArn", "functionName", "logGroupName"} {
		if outs[want] == nil {
			t.Errorf("%s is missing for a private function; it derives from the "+
				"providerId and does not depend on a URL", want)
		}
	}
	// D381, and the assertion the conformance case cannot make: it pins the
	// declared output and the reference's type, not the VALUE. This string is what
	// a retention guarantee lands on — a wrong one sets 365 days on a group nobody
	// writes to while the real logs keep forever.
	if outs["logGroupName"] != "/aws/lambda/pv-api-prod-1a2b3c4d" {
		t.Errorf("logGroupName = %v, want the group AWS creates for this function",
			outs["logGroupName"])
	}
}

// cdnOACServer is a stateful CloudFront + Lambda fake for the edge pattern. It
// records the OAC config, the origin domain + attached OAC id, and the lambda
// AddPermission grant body.
type cdnOACServer struct {
	oacName, oacProtocol, oacBehavior, oacOriginType string
	originDomain, originOACId                        string
	grants                                           []map[string]any
}

func (s *cdnOACServer) handler(t *testing.T) http.HandlerFunc {
	const arn = "arn:aws:cloudfront::000000000000:distribution/E1234567890ABC"
	dist := func() string {
		return `<Distribution><Id>E1234567890ABC</Id><ARN>` + arn + `</ARN>` +
			`<DomainName>d111111abcdef8.cloudfront.net</DomainName>` +
			`<DistributionConfig><Enabled>false</Enabled>` +
			`<Origins><Items><Origin><DomainName>` + s.originDomain + `</DomainName>` +
			`<OriginAccessControlId>` + s.originOACId + `</OriginAccessControlId></Origin></Items></Origins>` +
			`<DefaultCacheBehavior><ViewerProtocolPolicy>https-only</ViewerProtocolPolicy></DefaultCacheBehavior>` +
			`</DistributionConfig></Distribution>`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case r.Method == "POST" && strings.HasPrefix(p, cloudFrontPath+"/origin-access-control"):
			b, _ := io.ReadAll(r.Body)
			body := string(b)
			s.oacName = betweenAWS(body, "<Name>", "</Name>")
			s.oacProtocol = betweenAWS(body, "<SigningProtocol>", "</SigningProtocol>")
			s.oacBehavior = betweenAWS(body, "<SigningBehavior>", "</SigningBehavior>")
			s.oacOriginType = betweenAWS(body, "<OriginAccessControlOriginType>", "</OriginAccessControlOriginType>")
			w.Header().Set("ETag", "oac-etag")
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`<OriginAccessControl><Id>OAC123ABC</Id></OriginAccessControl>`))
		case r.Method == "POST" && strings.HasPrefix(p, cloudFrontPath+"/distribution"):
			b, _ := io.ReadAll(r.Body)
			body := string(b)
			s.originDomain = betweenAWS(body, "<DomainName>", "</DomainName>")
			s.originOACId = betweenAWS(body, "<OriginAccessControlId>", "</OriginAccessControlId>")
			w.Header().Set("ETag", "dist-etag")
			w.WriteHeader(201)
			_, _ = w.Write([]byte(dist()))
		case r.Method == "GET" && strings.HasPrefix(p, cloudFrontPath+"/tagging"):
			_, _ = w.Write([]byte(`<Tags><Items><Tag><Key>groundhold-capability</Key><Value>edge</Value></Tag>` +
				`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag></Items></Tags>`))
		case r.Method == "GET" && strings.Contains(p, "/origin-access-control/"):
			w.Header().Set("ETag", "oac-etag")
			_, _ = w.Write([]byte(`<OriginAccessControl><Id>OAC123ABC</Id></OriginAccessControl>`))
		case r.Method == "DELETE" && strings.Contains(p, "/origin-access-control/"):
			w.WriteHeader(204)
		case r.Method == "GET" && strings.Contains(p, "/distribution/"):
			w.Header().Set("ETag", "dist-etag")
			_, _ = w.Write([]byte(dist()))
		case r.Method == "DELETE" && strings.Contains(p, "/distribution/"):
			w.WriteHeader(204)
		// the lambda invoke grant (cross-driver AddPermission)
		case r.Method == "POST" && strings.HasSuffix(p, "/policy"):
			b, _ := io.ReadAll(r.Body)
			g := map[string]any{}
			_ = json.Unmarshal(b, &g)
			s.grants = append(s.grants, g)
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"Statement":"{}"}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, p)
			w.WriteHeader(404)
		}
	}
}

func TestCloudFrontOACEdgePattern(t *testing.T) {
	s := &cdnOACServer{}
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("us-east-1")
	d.Account = "000000000000"
	d.CloudFrontBaseURL = srv.URL
	d.LambdaBaseURL = srv.URL // the grant AddPermission is a lambda call
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second

	attrs := map[string]any{"viewer.protocol": "https-only", "service.managed": true}
	impl := map[string]any{
		"origin_domain":       "abc123.lambda-url.eu-central-1.on.aws",
		"origin_access":       "oac",
		"grant_invoke_lambda": "arn:aws:lambda:eu-central-1:000000000000:function:pv-api-prod-1a2b3c4d",
	}
	res := d.createCloudFront("000000000000", "prod", "edge", attrs, impl, 1)
	if res.Status != "succeeded" || res.ProviderID != "cf:000000000000:E1234567890ABC" {
		t.Fatalf("create: %+v", res)
	}
	// OAC created always/sigv4/lambda
	if s.oacProtocol != "sigv4" || s.oacBehavior != "always" || s.oacOriginType != "lambda" {
		t.Fatalf("OAC config = %q/%q/%q", s.oacProtocol, s.oacBehavior, s.oacOriginType)
	}
	// the distribution origin points at the Function URL host + carries the OAC id
	if s.originDomain != "abc123.lambda-url.eu-central-1.on.aws" || s.originOACId != "OAC123ABC" {
		t.Fatalf("origin = %q, oac id = %q", s.originDomain, s.originOACId)
	}
	// the grant is TWO AddPermission calls (AWS ~Oct 2025 requires BOTH
	// InvokeFunctionUrl AND InvokeFunction on a post-change Function URL). Both:
	// principal cloudfront.amazonaws.com, SourceArn = this distribution, distinct
	// statement ids. FunctionUrlAuthType=AWS_IAM only on the InvokeFunctionUrl grant.
	if len(s.grants) != 2 {
		t.Fatalf("want 2 AddPermission grants, got %d: %v", len(s.grants), s.grants)
	}
	byAction := map[string]map[string]any{}
	for _, g := range s.grants {
		if g["Principal"] != "cloudfront.amazonaws.com" {
			t.Fatalf("grant principal = %v", g["Principal"])
		}
		if g["SourceArn"] != "arn:aws:cloudfront::000000000000:distribution/E1234567890ABC" {
			t.Fatalf("grant SourceArn = %v", g["SourceArn"])
		}
		byAction[g["Action"].(string)] = g
	}
	url := byAction["lambda:InvokeFunctionUrl"]
	if url == nil || url["FunctionUrlAuthType"] != "AWS_IAM" {
		t.Fatalf("InvokeFunctionUrl grant missing or wrong authtype: %v", url)
	}
	inv := byAction["lambda:InvokeFunction"]
	if inv == nil {
		t.Fatal("InvokeFunction grant missing")
	}
	if _, has := inv["FunctionUrlAuthType"]; has {
		t.Fatalf("InvokeFunction grant must NOT carry FunctionUrlAuthType: %v", inv)
	}
	if url["StatementId"] == inv["StatementId"] {
		t.Fatalf("grants must have distinct statement ids, both = %v", url["StatementId"])
	}

	// cloudfront outputs: ARN from pid, domainName from the read
	outs, err := d.deriveOutputs("cloudfront", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	if outs["distributionArn"] != "arn:aws:cloudfront::000000000000:distribution/E1234567890ABC" {
		t.Fatalf("distributionArn = %v", outs["distributionArn"])
	}
	if outs["domainName"] != "d111111abcdef8.cloudfront.net" {
		t.Fatalf("domainName = %v", outs["domainName"])
	}

	// reverse delete tears down the OAC (the origin carries its id)
	del := d.deleteCloudFront("edge", "prod", res.ProviderID)
	if del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// TestCloudFrontOriginOperandRules: exactly one of the origin.domain attribute /
// origin_domain operand; grant requires OAC.
func TestCloudFrontOriginOperandRules(t *testing.T) {
	// both set -> refuse
	if _, err := BuildCloudFront("prod", "edge",
		map[string]any{"origin.domain": "a.example.com", "viewer.protocol": "https-only"},
		map[string]any{"origin_domain": "b.example.com"}, 1); err == nil {
		t.Fatal("origin set by both attribute and operand must refuse")
	}
	// neither set -> refuse
	if _, err := BuildCloudFront("prod", "edge",
		map[string]any{"viewer.protocol": "https-only"}, nil, 1); err == nil {
		t.Fatal("no origin must refuse")
	}
	// grant without OAC -> refuse
	if _, err := BuildCloudFront("prod", "edge",
		map[string]any{"viewer.protocol": "https-only"},
		map[string]any{"origin_domain": "b.example.com",
			"grant_invoke_lambda": "arn:aws:lambda:eu-central-1:000000000000:function:fn"}, 1); err == nil {
		t.Fatal("grant_invoke_lambda without origin_access:oac must refuse")
	}
	// operand-only origin with OAC + grant -> honored
	p, err := BuildCloudFront("prod", "edge",
		map[string]any{"viewer.protocol": "https-only"},
		map[string]any{"origin_domain": "b.example.com", "origin_access": "oac",
			"grant_invoke_lambda": "arn:aws:lambda:eu-central-1:000000000000:function:fn"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.OriginDomain != "b.example.com" || !p.OACEnabled || p.GrantLambdaArn == "" {
		t.Fatalf("plan = %+v", p)
	}
}
