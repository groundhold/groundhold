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

func aossAttrs() map[string]any {
	return map[string]any{
		"location.region":                "eu-central-1",
		"network.publicExposure":         true,
		"encryption.atRest":              true,
		"encryption.inTransit":           true,
		"encryption.customerManagedKeys": true,
		"availability.class":             "regional",
		"service.managed":                true,
	}
}

func aossImpl() map[string]any {
	return map[string]any{"kms_key_arn": "arn:aws:kms:eu-central-1:000000000000:key/abc"}
}

func TestBuildOpenSearchServerlessHonors(t *testing.T) {
	p, err := BuildOpenSearchServerless("prod", "catalog", aossAttrs(), aossImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.CMEK || p.KmsKeyArn == "" || !p.Public {
		t.Fatalf("plan = %+v", p)
	}
	if !osNameOK.MatchString(p.Name) {
		t.Fatalf("collection name invalid: %q", p.Name)
	}
	// the encryption policy carries a KmsARN (CMK) and covers collection/<name>.
	enc := p.encryptionPolicyBody()
	if enc["type"] != "encryption" || !strings.Contains(enc["policy"].(string), "KmsARN") ||
		!strings.Contains(enc["policy"].(string), "collection/"+p.Name) {
		t.Fatalf("encryption policy = %+v", enc)
	}
	// the network policy is public and covers collection + dashboard.
	net := p.networkPolicyBody()
	if net["type"] != "network" || !strings.Contains(net["policy"].(string), `"AllowFromPublic":true`) {
		t.Fatalf("network policy = %+v", net)
	}
	body := p.createCollectionBody("catalog", "prod")
	if body["name"] != p.Name || body["type"] != "SEARCH" {
		t.Fatalf("collection body = %+v", body)
	}
	// serverless has NO sizing params — the point of the backend.
	for _, forbidden := range []string{"ClusterConfig", "EBSOptions", "InstanceType", "InstanceCount"} {
		if _, ok := body[forbidden]; ok {
			t.Errorf("serverless collection must not carry provisioned sizing param %q", forbidden)
		}
	}
}

// A private collection uses AWSOwnedKey encryption + a VPC network policy.
func TestBuildOpenSearchServerlessPrivate(t *testing.T) {
	a := aossAttrs()
	a["network.publicExposure"] = false
	delete(a, "encryption.customerManagedKeys")
	p, err := BuildOpenSearchServerless("prod", "catalog",
		a, map[string]any{"vpc_endpoint_ids": []any{"vpce-1"}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Public || p.CMEK {
		t.Fatalf("expected private + AWS-owned, plan = %+v", p)
	}
	if !strings.Contains(p.encryptionPolicyBody()["policy"].(string), `"AWSOwnedKey":true`) {
		t.Fatalf("AWS-owned encryption policy = %+v", p.encryptionPolicyBody())
	}
	net := p.networkPolicyBody()["policy"].(string)
	if !strings.Contains(net, `"AllowFromPublic":false`) || !strings.Contains(net, "vpce-1") {
		t.Fatalf("VPC network policy = %s", net)
	}
}

func TestBuildOpenSearchServerlessRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"location.region": "eu-central-1", "encryption.atRest": true,
			"network.publicExposure": true, "service.managed": true}
	}
	cases := map[string]map[string]any{
		"atRest-false":    {"encryption.atRest": false},
		"inTransit-false": {"encryption.inTransit": false},
		"unmanaged":       {"service.managed": false},
		"zonal":           {"availability.class": "zonal"},
		"bad-class":       {"availability.class": "planetary"},
		"sizing-operand":  {"instance.type": "r6g.large.search"},
		"private-no-vpce": {"network.publicExposure": false},
	}
	for name, extra := range cases {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildOpenSearchServerless("prod", "catalog", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// CMK without a key refuses.
	cmk := base()
	cmk["encryption.customerManagedKeys"] = true
	if _, err := BuildOpenSearchServerless("prod", "catalog", cmk, nil, 1); err == nil {
		t.Error("CMK without kms_key_arn must refuse")
	}
}

func TestClassifyOpenSearchServerlessChange(t *testing.T) {
	if c, _ := classifyOpenSearchServerlessChange("location.region"); c != "immutable" {
		t.Errorf("location.region must be immutable (replacement), got %q", c)
	}
	if c, _ := classifyOpenSearchServerlessChange("encryption.atRest"); c != "unsupported" {
		t.Errorf("encryption.atRest must be unsupported (always-on), got %q", c)
	}
	if c, _ := classifyOpenSearchServerlessChange("availability.class"); c != "unsupported" {
		t.Errorf("availability.class must be unsupported (regional by construction), got %q", c)
	}
}

func TestSplitOpenSearchServerlessProviderID(t *testing.T) {
	if _, _, _, err := splitOpenSearchServerlessProviderID("aoss:eu-central-1:000000000000:catalog-abcd1234"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	for _, bad := range []string{
		"opensearch:eu-central-1:000000000000:x", // provisioned prefix, not serverless
		"aoss:bad:000000000000:x",
		"aoss:eu-central-1:bad:x",
		"eu:app",
	} {
		if _, _, _, err := splitOpenSearchServerlessProviderID(bad); err == nil {
			t.Errorf("accepted malformed serverless id %q", bad)
		}
	}
}

// aossFake serves the OpenSearch Serverless JSON-1.0 actions and RECORDS every
// X-Amz-Target seen, so the LRO anti-regression test can assert the poll concluded
// on the OBSERVABLE collection Status (BatchGetCollection) and NEVER hit an
// operation-by-id call (D273).
type aossFake struct {
	// conflict: CreateCollection answers ConflictException — the estate a re-converge
	// meets when the collection is already standing (D411).
	conflict bool
	tagCap   string
	stuck    string // if set, BatchGetCollection always returns this Status
	public   bool
	seen     []string
	deleted  bool
}

func (f *aossFake) handler(t *testing.T) *httptest.Server {
	t.Helper()
	if f.tagCap == "" {
		f.tagCap = "catalog"
	}
	arn := "arn:aws:aoss:eu-central-1:000000000000:collection/col-x"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		target := r.Header.Get("X-Amz-Target")
		action := target
		if i := strings.LastIndex(target, "."); i >= 0 {
			action = target[i+1:]
		}
		f.seen = append(f.seen, action)
		switch action {
		case "CreateSecurityPolicy":
			_, _ = w.Write([]byte(`{"securityPolicyDetail":{"name":"p","type":"encryption","policyVersion":"v1"}}`))
		case "CreateCollection":
			if f.conflict {
				w.WriteHeader(409)
				_, _ = w.Write([]byte(`{"__type":"ConflictException","message":"already exists"}`))
				return
			}
			_, _ = w.Write([]byte(`{"createCollectionDetail":{"id":"col-x","name":"col-x","status":"CREATING","arn":"` + arn + `"}}`))
		case "BatchGetCollection":
			if f.deleted {
				_, _ = w.Write([]byte(`{"collectionDetails":[]}`))
				return
			}
			status := "ACTIVE"
			if f.stuck != "" {
				status = f.stuck
			}
			_, _ = w.Write([]byte(`{"collectionDetails":[{"id":"col-x","name":"col-x","status":"` + status +
				`","arn":"` + arn + `","kmsKeyArn":"arn:aws:kms:eu-central-1:000000000000:key/abc",` +
				`"collectionEndpoint":"https://col-x.eu-central-1.aoss.amazonaws.com"}]}`))
		case "ListTagsForResource":
			_, _ = w.Write([]byte(`{"tags":[{"key":"groundhold-capability","value":"` + f.tagCap + `"},` +
				`{"key":"groundhold-environment","value":"prod"}]}`))
		case "GetSecurityPolicy":
			doc := `[{"AllowFromPublic":false}]`
			if f.public {
				doc = `[{"AllowFromPublic":true}]`
			}
			enc, _ := json.Marshal(doc) // aoss returns the document as a JSON STRING
			_, _ = w.Write([]byte(`{"securityPolicyDetail":{"policy":` + string(enc) + `}}`))
		case "DeleteCollection":
			f.deleted = true
			_, _ = w.Write([]byte(`{"deleteCollectionDetail":{"id":"col-x","status":"DELETING"}}`))
		case "DeleteSecurityPolicy":
			_, _ = w.Write([]byte(`{}`))
		case "ListCollections":
			_, _ = w.Write([]byte(`{"collectionSummaries":[{"id":"col-x","name":"col-x","status":"ACTIVE"}]}`))
		default:
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"__type":"UnknownOperationException"}`))
		}
	}))
}

func aossDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.OpenSearchServerlessBaseURL = srv.URL
	d.Account = "000000000000"
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

// TestCreateObserveDeleteOpenSearchServerless: the COMPOSITE create (encryption
// policy -> network policy -> CreateCollection -> poll ACTIVE) -> observe ->
// reverse delete. Asserts the D273 discipline (poll on BatchGetCollection, never an
// operation-by-id path) AND the composite ordering (both security policies created
// BEFORE the collection).
func TestCreateObserveDeleteOpenSearchServerless(t *testing.T) {
	f := &aossFake{public: true}
	srv := f.handler(t)
	defer srv.Close()
	d := aossDriver(t, srv)

	res := d.createOpenSearchServerless("eu-central-1", "000000000000", "prod", "catalog", aossAttrs(), aossImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "aoss:eu-central-1:000000000000:") {
		t.Fatalf("create: %+v", res)
	}
	// composite ordering + LRO discipline.
	firstCollection, policyCount, sawBatchGet := -1, 0, false
	for i, a := range f.seen {
		if strings.Contains(a, "Operation") {
			t.Fatalf("D273 violation: the poll hit an operation-by-id call %q", a)
		}
		switch a {
		case "CreateSecurityPolicy":
			if firstCollection >= 0 {
				t.Fatalf("a security policy was created AFTER the collection — composite order broken: %v", f.seen)
			}
			policyCount++
		case "CreateCollection":
			if firstCollection < 0 {
				firstCollection = i
			}
		case "BatchGetCollection":
			sawBatchGet = true
		}
	}
	if policyCount < 2 {
		t.Fatalf("expected the encryption AND network policies created before the collection, saw %d: %v", policyCount, f.seen)
	}
	if !sawBatchGet {
		t.Fatal("the create poll must read the observable collection state via BatchGetCollection")
	}

	obs, _, err := d.observeOpenSearchServerless("catalog", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["encryption.atRest"] != true || got["encryption.inTransit"] != true ||
		got["availability.class"] != "regional" || got["network.publicExposure"] != true ||
		got["location.region"] != "eu-central-1" || got["encryption.customerManagedKeys"] != true {
		t.Fatalf("observe: %+v", got)
	}

	// reverse delete: DeleteCollection -> poll gone -> DeleteSecurityPolicy x2.
	del := d.deleteOpenSearchServerless("catalog", "prod", res.ProviderID)
	if del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
	sawDeleteCollection, sawDeletePolicy := -1, -1
	for i, a := range f.seen {
		if a == "DeleteCollection" {
			sawDeleteCollection = i
		}
		if a == "DeleteSecurityPolicy" && sawDeletePolicy < 0 {
			sawDeletePolicy = i
		}
	}
	if sawDeleteCollection < 0 || sawDeletePolicy < 0 || sawDeletePolicy < sawDeleteCollection {
		t.Fatalf("reverse delete broken (collection must be removed before its owned policies): %v", f.seen)
	}
}

func TestDeleteOpenSearchServerlessForeignRefused(t *testing.T) {
	f := &aossFake{tagCap: "someone-else"}
	srv := f.handler(t)
	defer srv.Close()
	d := aossDriver(t, srv)
	res := d.deleteOpenSearchServerless("catalog", "prod", "aoss:eu-central-1:000000000000:col-x")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign collection must refuse delete, got %+v", res)
	}
	for _, a := range f.seen {
		if a == "DeleteCollection" || a == "DeleteSecurityPolicy" {
			t.Fatalf("a foreign-owned collection must not be mutated, saw %q", a)
		}
	}
}

// TestBoundedPollOpenSearchServerless enrolls the collection in the D266
// bounded-poll gate: a collection stuck in CREATING must conclude unknown-with-pid
// within the poll budget, never hang, never a false success.
func TestBoundedPollOpenSearchServerless(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.LifecycleProbe{
		Name: "aws/opensearch-serverless",
		StuckServer: func() *httptest.Server {
			f := &aossFake{stuck: "CREATING"}
			return f.handler(t)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000"
			d.OpenSearchServerlessBaseURL = happyURL
			d.PollInterval = 0
			d.PollTimeout = time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("opensearch-serverless", "capability.search.index", "prod",
				aossAttrs(), aossImpl(), "k", 1)
		},
		PID: openSearchServerlessProviderID("eu-central-1", "000000000000",
			OpenSearchDomainName("prod", "capability.search.index", 1)),
	}
	certifynet.CertifyBoundedPoll(t, p)
}

func aossRole(req *http.Request, _ []byte) certifynet.Role {
	tgt := req.Header.Get("X-Amz-Target")
	a := tgt[strings.LastIndex(tgt, ".")+1:]
	if strings.HasPrefix(a, "Get") || strings.HasPrefix(a, "List") || strings.HasPrefix(a, "BatchGet") {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingOpenSearchServerless enrols opensearch-serverless in the D391 gate.
// It is a COMPOSITE (encryption policy, network policy, collection) where the policies
// already tolerate a ConflictException at their deterministic names and the collection
// adopts on the same signal after a tag check — so a re-converge over a standing estate
// binds rather than failing part-way.
func TestAdoptsExistingOpenSearchServerless(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:     "aws/opensearch-serverless",
		Classify: aossRole,
		ExistingServer: func() *httptest.Server {
			f := &aossFake{public: true, conflict: true}
			return f.handler(t)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.OpenSearchServerlessBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("opensearch-serverless", "catalog", "prod", aossAttrs(), aossImpl(), "catalog", 1)
		},
		AllowedMutations: 3, // the two policy creates + the refused CreateCollection
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
