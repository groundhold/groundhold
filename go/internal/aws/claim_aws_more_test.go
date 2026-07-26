package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file rounds out claim_aws.go's claimARN coverage (11.2%): every ARN-
// derivable service reaches the generic Resource Groups Tagging API stamp
// (claimByARN), but claim_aws_test.go only drove s3/sqs/msk through it. The
// other ~20 branches — the account+region ARN builders and the three
// describe-to-resolve services — were never exercised via d.Claim.

// ---- group 1: ARN built straight from the providerId, no resolveAccount ---

func TestClaimDirectARNServices(t *testing.T) {
	cases := []struct {
		service string
		pid     string
		wantARN string
	}{
		{"dynamodb", dynamoProviderID("eu-central-1", "000000000000", "orders"),
			"arn:aws:dynamodb:eu-central-1:000000000000:table/orders"},
		{"ecr", ecrProviderID("eu-central-1", "000000000000", "orders-repo"),
			"arn:aws:ecr:eu-central-1:000000000000:repository/orders-repo"},
		{"efs", efsProviderID("eu-central-1", "000000000000", "fs-0abc12345"),
			"arn:aws:elasticfilesystem:eu-central-1:000000000000:file-system/fs-0abc12345"},
		{"opensearch", openSearchProviderID("eu-central-1", "000000000000", "search-domain"),
			"eu-central-1:000000000000:domain/search-domain"},
		{"kinesis", kinesisProviderID("eu-central-1", "000000000000", "orders-stream"),
			"arn:aws:kinesis:eu-central-1:000000000000:stream/orders-stream"},
		{"elasticache", ecacheProviderID("eu-central-1", "000000000000", "cache-1"),
			"eu-central-1:000000000000"},
		{"acm", acmProviderID("eu-central-1", "000000000000", "12345678-1234-1234-1234-123456789012"),
			"12345678-1234-1234-1234-123456789012"},
		{"cloudwatch", cwAlarmProviderID("eu-central-1", "000000000000", "high-cpu"),
			"arn:aws:cloudwatch:eu-central-1:000000000000:alarm:high-cpu"},
		{"backupvault", bkvProviderID("eu-central-1", "000000000000", "nightly"),
			"eu-central-1:000000000000"},
		{"apigateway", apigwProviderID("eu-central-1", "000000000000", "abc123xy"),
			"arn:aws:apigateway:eu-central-1::/apis/abc123xy"},
		{"cloudfront", cfProviderID("000000000000", "E1234567890ABC"),
			"arn:aws:cloudfront::000000000000:distribution/E1234567890ABC"},
	}
	for _, c := range cases {
		t.Run(c.service, func(t *testing.T) {
			var body string
			srv := rgtServer(t, "", &body, new(bool))
			defer srv.Close()
			d := rgtTestDriver(t, srv)
			cr := d.Claim(c.service, "cap", "prod", c.pid)
			if cr.Status != "succeeded" || cr.ProviderID != c.pid {
				t.Fatalf("%s claim must succeed WITH the pid, got %+v", c.service, cr)
			}
			if !strings.Contains(body, c.wantARN) {
				t.Fatalf("%s tag body must carry the ARN %q:\n%s", c.service, c.wantARN, body)
			}
			if !strings.Contains(body, `"groundhold-capability":"cap"`) {
				t.Fatalf("%s tag body missing groundhold-capability: %s", c.service, body)
			}
		})
	}
}

// ---- group 2: ARN needs the acting-identity account (resolveAccount) ------

func TestClaimResolveAccountServices(t *testing.T) {
	cases := []struct {
		service string
		pid     string
		wantARN string
	}{
		{"vpc", awsVpcProviderID("eu-central-1", "vpc-0abc123"),
			"arn:aws:ec2:eu-central-1:000000000000:vpc/vpc-0abc123"},
		{"vpngateway", vgwProviderID("eu-central-1", "vgw-0abc123"),
			"arn:aws:ec2:eu-central-1:000000000000:vpn-gateway/vgw-0abc123"},
		{"kms", awsKMSProviderID("eu-central-1", "12345678-1234-1234-1234-123456789012"),
			"arn:aws:kms:eu-central-1:000000000000:key/12345678-1234-1234-1234-123456789012"},
		{"eks", eksProviderID("eu-central-1", "my-cluster"),
			"arn:aws:eks:eu-central-1:000000000000:cluster/my-cluster"},
		{"ses-sending", sesSendingProviderID("eu-central-1", "example.com"),
			"arn:aws:ses:eu-central-1:000000000000:identity/example.com"},
		{"aurora", auroraProviderID("eu-central-1", "db-1"),
			"arn:aws:rds:eu-central-1:000000000000:cluster:db-1"},
		{"guardduty", guardDutyProviderID("eu-central-1", strings.Repeat("a", 32)),
			"arn:aws:guardduty:eu-central-1:000000000000:detector/" + strings.Repeat("a", 32)},
		{"cwlogs", cwLogsProviderID("eu-central-1", "/my/log/group"),
			"arn:aws:logs:eu-central-1:000000000000:log-group:/my/log/group"},
	}
	for _, c := range cases {
		t.Run(c.service, func(t *testing.T) {
			var body string
			srv := rgtServer(t, "", &body, new(bool))
			defer srv.Close()
			d := rgtTestDriver(t, srv) // pins d.Account = "000000000000"
			cr := d.Claim(c.service, "cap", "prod", c.pid)
			if cr.Status != "succeeded" || cr.ProviderID != c.pid {
				t.Fatalf("%s claim must succeed WITH the pid, got %+v", c.service, cr)
			}
			if !strings.Contains(body, c.wantARN) {
				t.Fatalf("%s tag body must carry the ARN %q:\n%s", c.service, c.wantARN, body)
			}
		})
	}
}

// TestClaimResolveAccountSTSFailureIsUnknown: when the account is not cached,
// resolveAccount falls to STS; an unreachable STS makes the claim ambiguous —
// unknown WITH the pid, never a fabricated ARN with a blank account.
func TestClaimResolveAccountSTSFailureIsUnknown(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.STSBaseURL = "http://127.0.0.1:1" // unreachable, and Account is NOT pinned
	pid := awsVpcProviderID("eu-central-1", "vpc-0abc123")
	cr := d.Claim("vpc", "cap", "prod", pid)
	if cr.Status != "unknown" || cr.ProviderID != pid {
		t.Fatalf("an STS failure resolving the claim ARN must be unknown WITH the pid, got %+v", cr)
	}
}

// ---- group 3: describe-to-resolve-ARN services (ecs / redshiftserverless / waf) --

// TestClaimECSResolvesArnThenTagsViaRGT: the ecs providerId carries no ARN (a
// server-assigned suffix); claim reads it via DescribeServices then stamps via RGT.
func TestClaimECSResolvesArnThenTagsViaRGT(t *testing.T) {
	arn := "arn:aws:ecs:eu-central-1:000000000000:service/orders-cluster/orders-svc"
	var tagBody string
	ecsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"services":[{"serviceArn":"` + arn + `","status":"ACTIVE"}]}`))
	}))
	defer ecsSrv.Close()
	rgtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		tagBody = string(b)
		_, _ = w.Write([]byte(`{"FailedResourcesMap":{}}`))
	}))
	defer rgtSrv.Close()
	d := rgtTestDriver(t, rgtSrv)
	d.ECSBaseURL = ecsSrv.URL

	pid := ecsProviderID("eu-central-1", "orders-cluster")
	cr := d.Claim("ecs", "orders", "prod", pid)
	if cr.Status != "succeeded" || cr.ProviderID != pid {
		t.Fatalf("ecs claim must resolve the ARN then succeed with the pid, got %+v", cr)
	}
	if !strings.Contains(tagBody, arn) {
		t.Fatalf("the RGT tag body must carry the resolved ARN:\n%s", tagBody)
	}
}

// TestClaimECSVanishedFails: no matching service in DescribeServices is a
// clean failure, never a fabricated ARN.
func TestClaimECSVanishedFails(t *testing.T) {
	ecsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"services":[]}`))
	}))
	defer ecsSrv.Close()
	d := rgtTestDriver(t, ecsSrv)
	d.ECSBaseURL = ecsSrv.URL
	cr := d.Claim("ecs", "orders", "prod", ecsProviderID("eu-central-1", "gone-cluster"))
	if cr.Status != "failed" {
		t.Fatalf("a vanished ecs service must fail the claim, got %+v", cr)
	}
}

// TestClaimECSReadErrorIsUnknown: an unreadable pre-claim describe is ambiguous.
func TestClaimECSReadErrorIsUnknown(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	d.ECSBaseURL = "http://127.0.0.1:1"
	pid := ecsProviderID("eu-central-1", "orders-cluster")
	cr := d.Claim("ecs", "orders", "prod", pid)
	if cr.Status != "unknown" || cr.ProviderID != pid {
		t.Fatalf("an unreadable ecs pre-claim describe must be unknown WITH the pid, got %+v", cr)
	}
}

// TestClaimRedshiftServerlessResolvesArnThenTagsViaRGT.
func TestClaimRedshiftServerlessResolvesArnThenTagsViaRGT(t *testing.T) {
	arn := "arn:aws:redshift-serverless:eu-central-1:000000000000:workgroup/abc-123"
	var tagBody string
	rssSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"workgroup":{"workgroupName":"analytics","workgroupArn":"` + arn + `"}}`))
	}))
	defer rssSrv.Close()
	rgtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		tagBody = string(b)
		_, _ = w.Write([]byte(`{"FailedResourcesMap":{}}`))
	}))
	defer rgtSrv.Close()
	d := rgtTestDriver(t, rgtSrv)
	d.RedshiftServerlessBaseURL = rssSrv.URL

	pid := rssProviderID("eu-central-1", "analytics")
	cr := d.Claim("redshiftserverless", "analytics", "prod", pid)
	if cr.Status != "succeeded" || cr.ProviderID != pid {
		t.Fatalf("redshiftserverless claim must resolve the ARN then succeed with the pid, got %+v", cr)
	}
	if !strings.Contains(tagBody, arn) {
		t.Fatalf("the RGT tag body must carry the resolved ARN:\n%s", tagBody)
	}
}

// TestClaimRedshiftServerlessVanishedFails.
func TestClaimRedshiftServerlessVanishedFails(t *testing.T) {
	rssSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException"}`))
	}))
	defer rssSrv.Close()
	d := rgtTestDriver(t, rssSrv)
	d.RedshiftServerlessBaseURL = rssSrv.URL
	cr := d.Claim("redshiftserverless", "analytics", "prod", rssProviderID("eu-central-1", "gone"))
	if cr.Status != "failed" {
		t.Fatalf("a vanished redshift-serverless workgroup must fail the claim, got %+v", cr)
	}
}

// TestClaimWAFResolvesArnThenTagsViaRGT: WAF is CLOUDFRONT-scope (global) — the
// RGT endpoint used is us-east-1 regardless of the driver's own region.
func TestClaimWAFResolvesArnThenTagsViaRGT(t *testing.T) {
	arn := "arn:aws:wafv2:us-east-1:000000000000:global/webacl/edge-acl/abc-123"
	var tagBody string
	wafSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"WebACLs":[{"Name":"edge-acl","Id":"abc-123","ARN":"` + arn + `"}]}`))
	}))
	defer wafSrv.Close()
	rgtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		tagBody = string(b)
		_, _ = w.Write([]byte(`{"FailedResourcesMap":{}}`))
	}))
	defer rgtSrv.Close()
	d := rgtTestDriver(t, rgtSrv)
	d.WAFBaseURL = wafSrv.URL

	pid := wafProviderID("000000000000", "edge-acl")
	cr := d.Claim("waf", "edge", "prod", pid)
	if cr.Status != "succeeded" || cr.ProviderID != pid {
		t.Fatalf("waf claim must resolve the ARN then succeed with the pid, got %+v", cr)
	}
	if !strings.Contains(tagBody, arn) {
		t.Fatalf("the RGT tag body must carry the resolved ARN:\n%s", tagBody)
	}
}

// TestClaimWAFVanishedFails.
func TestClaimWAFVanishedFails(t *testing.T) {
	wafSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"WebACLs":[]}`))
	}))
	defer wafSrv.Close()
	d := rgtTestDriver(t, wafSrv)
	d.WAFBaseURL = wafSrv.URL
	cr := d.Claim("waf", "edge", "prod", wafProviderID("000000000000", "gone-acl"))
	if cr.Status != "failed" {
		t.Fatalf("a vanished waf web ACL must fail the claim, got %+v", cr)
	}
}

// ---- claimByARN: the remaining pure/wire branches --------------------------

// TestClaimByARN_UnparseableResponseIsUnknown: a garbled 200 must never be
// mistaken for a fabricated success.
func TestClaimByARN_UnparseableResponseIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	d := rgtTestDriver(t, srv)
	pid := "sqs:eu-central-1:000000000000:orders"
	cr := d.Claim("sqs", "orders-q", "prod", pid)
	if cr.Status != "unknown" || cr.ProviderID != pid {
		t.Fatalf("a garbled 200 must be unknown WITH the pid, got %+v", cr)
	}
}

// TestClaimByARN_TransportErrorIsUnknown.
func TestClaimByARN_TransportErrorIsUnknown(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.RGTBaseURL = "http://127.0.0.1:1"
	d.Account = "000000000000"
	pid := "sqs:eu-central-1:000000000000:orders"
	cr := d.Claim("sqs", "orders-q", "prod", pid)
	if cr.Status != "unknown" || cr.ProviderID != pid {
		t.Fatalf("an unreachable RGT endpoint must be unknown WITH the pid, got %+v", cr)
	}
}

// TestClaimByARN_5xxIsUnknown.
func TestClaimByARN_5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	d := rgtTestDriver(t, srv)
	pid := "sqs:eu-central-1:000000000000:orders"
	cr := d.Claim("sqs", "orders-q", "prod", pid)
	if cr.Status != "unknown" || cr.ProviderID != pid {
		t.Fatalf("a 5xx RGT response must be unknown WITH the pid, got %+v", cr)
	}
}

// TestClaimByARN_4xxIsFailed: a non-throttle 4xx (e.g. AccessDenied) is a
// clean failure, never a fabricated success.
func TestClaimByARN_4xxIsFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"__type":"AccessDeniedException"}`))
	}))
	defer srv.Close()
	d := rgtTestDriver(t, srv)
	pid := "sqs:eu-central-1:000000000000:orders"
	cr := d.Claim("sqs", "orders-q", "prod", pid)
	if cr.Status != "failed" {
		t.Fatalf("a clean 4xx RGT response must be failed, got %+v", cr)
	}
}

// TestClaimByARN_ThrottledTopLevelIsUnknown: a throttled TagResources call
// itself (not a per-resource failure) is ambiguous — unknown WITH the pid.
func TestClaimByARN_ThrottledTopLevelIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"__type":"ThrottlingException"}`))
	}))
	defer srv.Close()
	d := rgtTestDriver(t, srv)
	pid := "sqs:eu-central-1:000000000000:orders"
	cr := d.Claim("sqs", "orders-q", "prod", pid)
	if cr.Status != "unknown" || cr.ProviderID != pid {
		t.Fatalf("a top-level throttle must be unknown WITH the pid, got %+v", cr)
	}
}
