package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
				_, _ = w.Write([]byte(`{"repositories":[{"imageTagMutability":"IMMUTABLE",` +
					`"encryptionConfiguration":{"encryptionType":"KMS"}}]}`))
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

func TestDeleteECRForeignRefused(t *testing.T) {
	srv := ecrServer(t, "someone-else")
	defer srv.Close()
	d := ecrDriver(t, srv)
	res := d.deleteECR("images", "prod", "ecr:eu-central-1:000000000000:pv-images-prod-abcd1234")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign registry must refuse delete, got %+v", res)
	}
}
