package aws

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// claimRDSServer answers the Query protocol for a claim: DescribeDBInstances
// returns an ADOPTED instance (an operator tag, NO groundhold tags — the realistic
// pre-claim state), and AddTagsToResource captures the signed body so the test can
// assert the groundhold ownership tags were stamped. notFound makes DescribeDBInstances
// report DBInstanceNotFound (a vanished resource).
func claimRDSServer(t *testing.T, notFound bool, gotTagBody *string, sawSigV4 *bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			*sawSigV4 = true
		}
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		action := ""
		for _, kv := range strings.Split(string(body), "&") {
			if strings.HasPrefix(kv, "Action=") {
				action = strings.TrimPrefix(kv, "Action=")
			}
		}
		switch action {
		case "DescribeDBInstances":
			if notFound {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>DBInstanceNotFound</Code></Error></ErrorResponse>`))
				return
			}
			_, _ = w.Write([]byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>` +
				`<DBInstanceIdentifier>db-abcd1234</DBInstanceIdentifier>` +
				`<DBInstanceStatus>available</DBInstanceStatus>` +
				`<Engine>postgres</Engine><EngineVersion>16.3</EngineVersion>` +
				`<StorageEncrypted>true</StorageEncrypted><PubliclyAccessible>false</PubliclyAccessible>` +
				`<MultiAZ>false</MultiAZ><DeletionProtection>true</DeletionProtection>` +
				`<TagList><Tag><Key>team</Key><Value>ops</Value></Tag></TagList>` +
				`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
		case "AddTagsToResource":
			*gotTagBody = string(body)
			_, _ = w.Write([]byte(`<AddTagsToResourceResponse></AddTagsToResourceResponse>`))
		default:
			w.WriteHeader(404)
		}
	}))
}

// TestClaimRDSStampsOwnershipTags: claiming an adopted (TF-created) instance STAMPS
// groundhold's ownership tags via AddTagsToResource (additive — no read-modify-write)
// and succeeds WITH the providerId. Asserts the signed tag request carries the
// groundhold tags and the DB ARN, and that the request was SigV4-signed.
func TestClaimRDSStampsOwnershipTags(t *testing.T) {
	var tagBody string
	var sawSigV4 bool
	srv := claimRDSServer(t, false, &tagBody, &sawSigV4)
	defer srv.Close()
	d := rdsTestDriver(t, srv)

	pid := "rds:eu-central-1:db-abcd1234"
	cr := d.Claim("rds", "orders-db", "prod", pid)
	if cr.Status != "succeeded" {
		t.Fatalf("claim must succeed, got %+v", cr)
	}
	if cr.ProviderID != pid {
		t.Fatalf("claim must carry the providerId, got %q", cr.ProviderID)
	}
	if tagBody == "" {
		t.Fatal("claim must issue an AddTagsToResource request")
	}
	if !sawSigV4 {
		t.Fatal("the tag request must be SigV4-signed")
	}
	for _, want := range []string{
		"Action=AddTagsToResource", "groundhold-capability", "orders-db",
		"groundhold-environment", "prod",
		// the DB ARN (colons rfc3986-encoded as %3A) — account + instance id survive.
		"000000000000", "db-abcd1234",
	} {
		if !strings.Contains(tagBody, want) {
			t.Errorf("tag request missing %q\nbody: %s", want, tagBody)
		}
	}
}

// TestClaimRDSNotFoundFails: a claim on an instance that is gone fails cleanly
// (never a fabricated success).
func TestClaimRDSNotFoundFails(t *testing.T) {
	var tagBody string
	var sawSigV4 bool
	srv := claimRDSServer(t, true, &tagBody, &sawSigV4)
	defer srv.Close()
	d := rdsTestDriver(t, srv)

	cr := d.Claim("rds", "orders-db", "prod", "rds:eu-central-1:db-abcd1234")
	if cr.Status != "failed" {
		t.Fatalf("a vanished instance must fail the claim, got %+v", cr)
	}
	if tagBody != "" {
		t.Fatalf("a vanished instance must not be tagged: %s", tagBody)
	}
}

// TestClaimRDSUnwiredServiceRefusesHonestly: a service groundhold cannot claim refuses
// (failed) so the converge stops and the resource stays externally owned — a failed
// claim is safer than a silent one (no orphan). These mark ownership by
// identity/name (route53 zones, iam roles) or are read-only (loadbalancer), so they
// carry no taggable groundhold marker and stay honest-refuse permanently.
func TestClaimRDSUnwiredServiceRefusesHonestly(t *testing.T) {
	d := NewDriver("us-east-1")
	for _, svc := range []string{"route53health", "iam", "rolepolicy", "loadbalancer"} {
		cr := d.Claim(svc, "assets", "prod", svc+":whatever")
		if cr.Status != "failed" {
			t.Fatalf("%s must refuse (failed), got %+v", svc, cr)
		}
		if !strings.Contains(cr.Reason, "externally owned") {
			t.Fatalf("%s refusal must say it stays externally owned: %q", svc, cr.Reason)
		}
	}
}

// TestClaimRDSUnknownServiceFailsClosed: dispatch is fail-closed (D76).
func TestClaimRDSUnknownServiceFailsClosed(t *testing.T) {
	d := NewDriver("us-east-1")
	cr := d.Claim("__not_a_service__", "x", "y", "a:b:c")
	if cr.Status != "failed" {
		t.Fatalf("an unknown service must fail closed, got %+v", cr)
	}
}

// ---- D145: the generic Resource Groups Tagging API path + the native ASM path ----

// rgtTestDriver points the driver's Resource Groups Tagging API at a stub and pins
// the account so the ARN account component is deterministic.
func rgtTestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.RGTBaseURL = srv.URL
	d.Account = "000000000000"
	return d
}

// rgtServer answers TagResources, capturing the signed body. failCode!="" puts the
// sent ARN into FailedResourcesMap so the test can drive the per-resource failure.
func rgtServer(t *testing.T, failCode string, gotBody *string, sawSigV4 *bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			*sawSigV4 = true
		}
		if !strings.Contains(r.Header.Get("X-Amz-Target"), "TagResources") {
			w.WriteHeader(400)
			return
		}
		body := make([]byte, r.ContentLength)
		_, _ = io.ReadFull(r.Body, body)
		*gotBody = string(body)
		if failCode != "" {
			var req struct {
				ARNs []string `json:"ResourceARNList"`
			}
			_ = json.Unmarshal(body, &req)
			arn := ""
			if len(req.ARNs) > 0 {
				arn = req.ARNs[0]
			}
			_, _ = w.Write([]byte(fmt.Sprintf(
				`{"FailedResourcesMap":{%q:{"ErrorCode":%q,"StatusCode":400}}}`, arn, failCode)))
			return
		}
		_, _ = w.Write([]byte(`{"FailedResourcesMap":{}}`))
	}))
}

// TestClaimS3StampsTagsViaRGT: claiming an adopted bucket stamps groundhold's tags via
// the additive Resource Groups Tagging API (never PutBucketTagging's full-map
// clobber) and succeeds WITH the providerId. Asserts the signed body carries the
// groundhold tags + the s3 ARN, and that the request was SigV4-signed.
func TestClaimS3StampsTagsViaRGT(t *testing.T) {
	var body string
	var sawSigV4 bool
	srv := rgtServer(t, "", &body, &sawSigV4)
	defer srv.Close()
	d := rgtTestDriver(t, srv)

	pid := "s3:eu-central-1:acme-assets"
	cr := d.Claim("s3", "assets", "prod", pid)
	if cr.Status != "succeeded" {
		t.Fatalf("s3 claim must succeed, got %+v", cr)
	}
	if cr.ProviderID != pid {
		t.Fatalf("claim must carry the providerId, got %q", cr.ProviderID)
	}
	if !sawSigV4 {
		t.Fatal("the tag request must be SigV4-signed")
	}
	for _, want := range []string{
		`"groundhold-capability":"assets"`, `"groundhold-environment":"prod"`,
		"ResourceARNList", "arn:aws:s3:::acme-assets",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("tag request missing %q\nbody: %s", want, body)
		}
	}
}

// TestClaimSQSStampsTagsViaRGT: an account+region service builds its ARN straight
// from the providerId — the sqs queue ARN reaches the additive RGT stamp.
func TestClaimSQSStampsTagsViaRGT(t *testing.T) {
	var body string
	var sawSigV4 bool
	srv := rgtServer(t, "", &body, &sawSigV4)
	defer srv.Close()
	d := rgtTestDriver(t, srv)

	pid := "sqs:eu-central-1:000000000000:orders"
	cr := d.Claim("sqs", "orders-q", "prod", pid)
	if cr.Status != "succeeded" {
		t.Fatalf("sqs claim must succeed, got %+v", cr)
	}
	if cr.ProviderID != pid {
		t.Fatalf("claim must carry the providerId, got %q", cr.ProviderID)
	}
	if !sawSigV4 {
		t.Fatal("the tag request must be SigV4-signed")
	}
	for _, want := range []string{
		`"groundhold-capability":"orders-q"`, `"groundhold-environment":"prod"`,
		"arn:aws:sqs:eu-central-1:000000000000:orders",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("tag request missing %q\nbody: %s", want, body)
		}
	}
}

// TestClaimRGTFailedResourceFails: a NotFound per-resource entry in
// FailedResourcesMap is a clean failure (never a fabricated success).
func TestClaimRGTFailedResourceFails(t *testing.T) {
	var body string
	var sawSigV4 bool
	srv := rgtServer(t, "ResourceNotFoundException", &body, &sawSigV4)
	defer srv.Close()
	d := rgtTestDriver(t, srv)

	cr := d.Claim("sqs", "orders-q", "prod", "sqs:eu-central-1:000000000000:orders")
	if cr.Status != "failed" {
		t.Fatalf("a failed resource must fail the claim, got %+v", cr)
	}
}

// TestClaimRGTInternalServiceUnknown: a retryable per-resource entry is ambiguous —
// unknown WITH the providerId (the tag may have landed).
func TestClaimRGTInternalServiceUnknown(t *testing.T) {
	var body string
	var sawSigV4 bool
	srv := rgtServer(t, "InternalServiceException", &body, &sawSigV4)
	defer srv.Close()
	d := rgtTestDriver(t, srv)

	pid := "sqs:eu-central-1:000000000000:orders"
	cr := d.Claim("sqs", "orders-q", "prod", pid)
	if cr.Status != "unknown" {
		t.Fatalf("a retryable failure must be unknown, got %+v", cr)
	}
	if cr.ProviderID != pid {
		t.Fatalf("an unknown claim must still carry the providerId, got %q", cr.ProviderID)
	}
}

// asmClaimServer answers DescribeSecret (existence) + TagResource, capturing the
// signed tag body. notFound makes DescribeSecret report ResourceNotFoundException.
func asmClaimServer(t *testing.T, notFound bool, gotBody *string, sawSigV4 *bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			*sawSigV4 = true
		}
		body := make([]byte, r.ContentLength)
		_, _ = io.ReadFull(r.Body, body)
		target := r.Header.Get("X-Amz-Target")
		switch {
		case strings.Contains(target, "DescribeSecret"):
			if notFound {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException"}`))
				return
			}
			_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:app-db-AbCdEf",` +
				`"Name":"app-db"}`))
		case strings.Contains(target, "TagResource"):
			*gotBody = string(body)
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(404)
		}
	}))
}

// TestClaimSecretsManagerNativeTagResource: the secret ARN carries a random suffix,
// so claim stamps via the name-keyed native TagResource (additive) and succeeds WITH
// the providerId. Asserts the signed body carries SecretId + the groundhold tags, SigV4.
func TestClaimSecretsManagerNativeTagResource(t *testing.T) {
	var tagBody string
	var sawSigV4 bool
	srv := asmClaimServer(t, false, &tagBody, &sawSigV4)
	defer srv.Close()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.SecretsManagerBaseURL = srv.URL
	d.Account = "000000000000"

	pid := "asm:eu-central-1:app-db"
	cr := d.Claim("secretsmanager", "app-db", "prod", pid)
	if cr.Status != "succeeded" {
		t.Fatalf("secretsmanager claim must succeed, got %+v", cr)
	}
	if cr.ProviderID != pid {
		t.Fatalf("claim must carry the providerId, got %q", cr.ProviderID)
	}
	if tagBody == "" {
		t.Fatal("claim must issue a TagResource request")
	}
	if !sawSigV4 {
		t.Fatal("the tag request must be SigV4-signed")
	}
	for _, want := range []string{
		`"SecretId":"app-db"`, "groundhold-capability", "app-db",
		"groundhold-environment", "prod",
	} {
		if !strings.Contains(tagBody, want) {
			t.Errorf("tag request missing %q\nbody: %s", want, tagBody)
		}
	}
}

// TestClaimSecretsManagerNotFoundFails: a claim on a secret that is gone fails
// cleanly and never issues a tag request (never a fabricated success).
func TestClaimSecretsManagerNotFoundFails(t *testing.T) {
	var tagBody string
	var sawSigV4 bool
	srv := asmClaimServer(t, true, &tagBody, &sawSigV4)
	defer srv.Close()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.SecretsManagerBaseURL = srv.URL
	d.Account = "000000000000"

	cr := d.Claim("secretsmanager", "app-db", "prod", "asm:eu-central-1:app-db")
	if cr.Status != "failed" {
		t.Fatalf("a vanished secret must fail the claim, got %+v", cr)
	}
	if tagBody != "" {
		t.Fatalf("a vanished secret must not be tagged: %s", tagBody)
	}
}

// TestClaimMSKResolvesArnThenTagsViaRGT: a describe-to-resolve-ARN service reads the
// authoritative ARN (ListClustersV2) then stamps groundhold's tags via the additive
// RGT path — succeeds WITH the providerId, and the tag body carries the resolved ARN.
func TestClaimMSKResolvesArnThenTagsViaRGT(t *testing.T) {
	arn := "arn:aws:kafka:eu-central-1:000000000000:cluster/broker-msk/abc-123-4"
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("X-Amz-Target"), "TagResources") {
			b := make([]byte, r.ContentLength)
			_, _ = io.ReadFull(r.Body, b)
			body = string(b)
			_, _ = w.Write([]byte(`{"FailedResourcesMap":{}}`))
			return
		}
		// MSK ListClustersV2 (the ARN resolve)
		fmt.Fprintf(w, `{"ClusterInfoList":[{"ClusterName":"broker-msk","ClusterArn":%q}]}`, arn)
	}))
	defer srv.Close()
	d := rgtTestDriver(t, srv)
	d.MSKBaseURL = srv.URL

	pid := mskProviderID("eu-central-1", "000000000000", "broker-msk")
	cr := d.Claim("msk", "broker", "prod", pid)
	if cr.Status != "succeeded" || cr.ProviderID != pid {
		t.Fatalf("msk claim must resolve the ARN then succeed with the pid, got %+v", cr)
	}
	if !strings.Contains(body, arn) || !strings.Contains(body, `"groundhold-capability":"broker"`) {
		t.Fatalf("the RGT tag body must carry the resolved ARN + groundhold tags:\n%s", body)
	}
}

// TestClaimMSKVanishedFails: a describe that finds no cluster is a clean failure, not
// a fabricated ARN.
func TestClaimMSKVanishedFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ClusterInfoList":[]}`)
	}))
	defer srv.Close()
	d := rgtTestDriver(t, srv)
	d.MSKBaseURL = srv.URL
	cr := d.Claim("msk", "broker", "prod", mskProviderID("eu-central-1", "000000000000", "gone"))
	if cr.Status != "failed" {
		t.Fatalf("a vanished msk cluster must fail the claim, got %+v", cr)
	}
}
