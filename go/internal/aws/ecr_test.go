package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func ecrAttrs() map[string]any {
	return map[string]any{
		"location.region":                "eu-central-1",
		"network.publicExposure":         false,
		"encryption.customerManagedKeys": true,
		"immutable.tags":                 true,
		"service.managed":                true,
	}
}

func ecrImpl() map[string]any {
	return map[string]any{"kms_key": "arn:aws:kms:eu-central-1:000000000000:key/abc"}
}

func TestBuildECRHonors(t *testing.T) {
	p, err := BuildECR("prod", "images", ecrAttrs(), ecrImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.ImmutableTags || !p.CMEK || p.KmsKey == "" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("images", "prod")
	if !strings.Contains(body, `"imageTagMutability":"IMMUTABLE"`) || !strings.Contains(body, `"encryptionType":"KMS"`) {
		t.Fatalf("body = %s", body)
	}
}

func TestBuildECRRefusals(t *testing.T) {
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"public-refused": {map[string]any{"network.publicExposure": true}, ecrImpl()}, // ECR Public is separate
		"cmek-no-key":    {map[string]any{"encryption.customerManagedKeys": true}, nil},
		"unmanaged":      {map[string]any{"service.managed": false}, ecrImpl()},
		"unknown-attr":   {map[string]any{"registry.tier": "premium"}, ecrImpl()},
	}
	for name, c := range cases {
		a := ecrAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildECR("prod", "images", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

// security.scanOnPush sets imageScanningConfiguration.scanOnPush at create.
func TestBuildECRScanOnPush(t *testing.T) {
	a := ecrAttrs()
	a["security.scanOnPush"] = true
	p, err := BuildECR("prod", "images", a, ecrImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.ScanOnPush {
		t.Fatalf("scanOnPush must be honored, got %+v", p)
	}
	if !strings.Contains(p.createBody("images", "prod"), `"imageScanningConfiguration":{"scanOnPush":true}`) {
		t.Fatalf("body missing scan config: %s", p.createBody("images", "prod"))
	}
	// absent/false -> no scan config emitted (ECR default).
	p2, err := BuildECR("prod", "images", ecrAttrs(), ecrImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p2.createBody("images", "prod"), "imageScanningConfiguration") {
		t.Fatalf("no scanOnPush must emit no scan config: %s", p2.createBody("images", "prod"))
	}
}

// scan-on-push is re-assertable in place (PutImageScanningConfiguration) -> mutable
// with an updater; tag mutability likewise; encryption/region are replacements.
func TestClassifyECRChange(t *testing.T) {
	want := map[string]string{
		"security.scanOnPush":            "mutable",
		"immutable.tags":                 "mutable",
		"encryption.customerManagedKeys": "immutable",
		"location.region":                "immutable",
		"network.publicExposure":         "unsupported",
		"cost.monthly":                   "unsupported",
	}
	for path, exp := range want {
		if got, _ := classifyECRChange(path); got != exp {
			t.Errorf("classify %s: want %s got %s", path, exp, got)
		}
	}
}

// updateECR patches scan-on-push in place via PutImageScanningConfiguration,
// refusing to touch a repository whose ownership tags are not ours.
func TestUpdateECRScanOnPush(t *testing.T) {
	var sawScanCall bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			target := r.Header.Get("X-Amz-Target")
			action := target[strings.LastIndex(target, ".")+1:]
			switch action {
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`{"tags":[{"Key":"groundhold-capability","Value":"images"},` +
					`{"Key":"groundhold-environment","Value":"prod"}]}`))
			case "PutImageScanningConfiguration":
				sawScanCall = true
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := ecrDriver(t, srv)
	a := ecrAttrs()
	a["security.scanOnPush"] = true
	res := d.updateECR("images", "prod", "ecr:eu-central-1:000000000000:pv-images-prod-abcd1234",
		a, ecrImpl(), []string{"security.scanOnPush"})
	if res.Status != "succeeded" || !sawScanCall {
		t.Fatalf("scanOnPush update must call PutImageScanningConfiguration, got %+v (called=%v)", res, sawScanCall)
	}
}

func TestUpdateECRForeignRefused(t *testing.T) {
	srv := ecrServer(t, "someone-else")
	defer srv.Close()
	d := ecrDriver(t, srv)
	res := d.updateECR("images", "prod", "ecr:eu-central-1:000000000000:pv-images-prod-abcd1234",
		ecrAttrs(), ecrImpl(), []string{"security.scanOnPush"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("update of a foreign repo must refuse, got %+v", res)
	}
}

func ecrServer(t *testing.T, tagCap string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			target := r.Header.Get("X-Amz-Target")
			action := target[strings.LastIndex(target, ".")+1:]
			switch action {
			case "CreateRepository":
				_, _ = w.Write([]byte(`{"repository":{"repositoryName":"x"}}`))
			case "DescribeRepositories":
				// a customer CMK repo (D954: observe traces the key to KMS, not the type)
				_, _ = w.Write([]byte(`{"repositories":[{"imageTagMutability":"IMMUTABLE",` +
					`"encryptionConfiguration":{"encryptionType":"KMS",` +
					`"kmsKey":"arn:aws:kms:eu-central-1:000000000000:key/customer-cmk-1"}}]}`))
			case "DescribeKey":
				// KeyManager by key id: an "aws-managed" arn is AWS-managed, else CUSTOMER.
				body := make([]byte, r.ContentLength)
				_, _ = io.ReadFull(r.Body, body)
				mgr := "CUSTOMER"
				if strings.Contains(string(body), "aws-managed") {
					mgr = "AWS"
				}
				_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyManager":"` + mgr + `"}}`))
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`{"tags":[{"Key":"groundhold-capability","Value":"` + tagCap + `"},` +
					`{"Key":"groundhold-environment","Value":"prod"}]}`))
			case "DeleteRepository":
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func ecrDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.ECRBaseURL = srv.URL
	d.KMSBaseURL = srv.URL // D954: observe traces the repo's kmsKey to KMS DescribeKey
	d.Account = "000000000000"
	return d
}

func TestCreateObserveDeleteECR(t *testing.T) {
	srv := ecrServer(t, "images")
	defer srv.Close()
	d := ecrDriver(t, srv)
	res := d.createECR("eu-central-1", "000000000000", "prod", "images", ecrAttrs(), ecrImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "ecr:eu-central-1:000000000000:pv-images-prod-") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeECR("images", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["immutable.tags"] != true || got["encryption.customerManagedKeys"] != true ||
		got["network.publicExposure"] != false || got["location.region"] != "eu-central-1" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteECR("images", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// D954: encryptionType=KMS with the AWS-managed aws/ecr key (KeyManager=AWS) is NOT a
// customer key. observe must trace the key and report customerManagedKeys=false, not read
// it true off the type — else a hard BYOK constraint reads satisfied against an
// AWS-managed repo. This is the regression guard the old type-only test lacked.
func TestObserveECRAWSManagedKeyIsNotCustomer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := ""
		if tg := r.Header.Get("X-Amz-Target"); tg != "" {
			action = tg[strings.LastIndex(tg, ".")+1:]
		}
		switch action {
		case "DescribeRepositories":
			_, _ = w.Write([]byte(`{"repositories":[{"imageTagMutability":"MUTABLE",` +
				`"encryptionConfiguration":{"encryptionType":"KMS",` +
				`"kmsKey":"arn:aws:kms:eu-central-1:000000000000:key/aws-managed-ecr"}}]}`))
		case "DescribeKey":
			_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyManager":"AWS"}}`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := ecrDriver(t, srv)
	obs, _, err := d.observeECR("images", "ecr:eu-central-1:000000000000:pv-images-prod-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["encryption.customerManagedKeys"] != false {
		t.Fatalf("an AWS-managed KMS key must read customerManagedKeys=false, got %v", got["encryption.customerManagedKeys"])
	}
}

func TestDeleteECRForeignRefused(t *testing.T) {
	srv := ecrServer(t, "someone-else")
	defer srv.Close()
	d := ecrDriver(t, srv)
	res := d.deleteECR("images", "prod", "ecr:eu-central-1:000000000000:pv-images-prod-abcd1234")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign registry must refuse delete, got %+v", res)
	}
}

// ecrExistingServer: the repository already exists at our deterministic name and
// carries our tags, so CreateRepository is answered RepositoryAlreadyExists and the
// driver must recognise and bind it.
func ecrExistingServer(t *testing.T, tagCap string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			target := r.Header.Get("X-Amz-Target")
			switch target[strings.LastIndex(target, ".")+1:] {
			case "CreateRepository":
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"RepositoryAlreadyExistsException",` +
					`"message":"RepositoryAlreadyExists"}`))
			case "DescribeRepositories":
				_, _ = w.Write([]byte(`{"repositories":[{"imageTagMutability":"IMMUTABLE",` +
					`"encryptionConfiguration":{"encryptionType":"KMS"}}]}`))
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`{"tags":[{"Key":"groundhold-capability","Value":"` + tagCap + `"},` +
					`{"Key":"groundhold-environment","Value":"prod"}]}`))
			case "PutImageScanningConfiguration", "PutImageTagMutability", "TagResource":
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func ecrTargetRole(req *http.Request, _ []byte) certifynet.Role {
	tgt := req.Header.Get("X-Amz-Target")
	switch tgt[strings.LastIndex(tgt, ".")+1:] {
	case "DescribeRepositories", "ListTagsForResource":
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingECR enrols ecr in the D391 gate. A repository is name-addressed and
// the create is answered RepositoryAlreadyExists; only an OURS-tagged repo may be bound.
func TestAdoptsExistingECR(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:           "aws/ecr",
		Classify:       ecrTargetRole,
		ExistingServer: func() *httptest.Server { return ecrExistingServer(t, "images") },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.ECRBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("ecr", "images", "prod", ecrAttrs(), ecrImpl(), "images", 1)
		},
		AllowedMutations: 2, // the refused CreateRepository + convergence
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
