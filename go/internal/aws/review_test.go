package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Region threading (review #1, CRITICAL): a create must refuse a missing/invalid
// location.region rather than defaulting to the driver's env-pinned region.
func TestCreateRefusesMissingRegion(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000" // skip STS
	// RDS candidate with NO location.region
	attrs := map[string]any{"engine.protocol": "postgresql/16", "encryption.atRest": true, "service.managed": true}
	res := d.Create("rds", "db", "prod", attrs, rdsImpl(), "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "location.region") {
		t.Fatalf("missing region must refuse, got %+v", res)
	}
}

// Garbled 200 describe (review #2, CRITICAL): deleteRDS must NOT report a false
// idempotent succeeded when the ownership read is unparseable.
func TestDeleteRDSGarbledReadIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// a truncated/garbled 200 (not a well-formed "not found")
			_, _ = w.Write([]byte(`<DescribeDBInstancesResponse><trunc`))
		}))
	defer srv.Close()
	d := rdsTestDriver(t, srv)
	res := d.deleteRDS("db", "prod", "rds:eu-central-1:db-abcd1234")
	if res.Status != "unknown" {
		t.Fatalf("a garbled ownership read must be unknown, never a false succeeded; got %+v", res)
	}
}

// EC2 error parsing (review #4): InvalidVpcID.NotFound must be detected so a
// re-run of delete on an already-gone VPC is idempotent succeeded (not unknown).
func TestDeleteAWSVPCIdempotentViaEC2ErrCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			// EC2 error shape: <Response><Errors><Error><Code>
			_, _ = w.Write([]byte(`<Response><Errors><Error><Code>InvalidVpcID.NotFound</Code></Error></Errors></Response>`))
		}))
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	res := d.deleteAWSVPC("net", "prod", "vpc:eu-central-1:vpc-0abc123")
	if res.Status != "succeeded" {
		t.Fatalf("a gone VPC (InvalidVpcID.NotFound) must be idempotent succeeded, got %+v", res)
	}
}

// S3 NoSuchTagSet (review #3): an existing UNtagged bucket must NOT be reported
// retired — the ownership check refuses it (tags empty != ours).
func TestDeleteS3UntaggedRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && r.URL.RawQuery == "tagging" {
				w.WriteHeader(404)
				_, _ = w.Write([]byte("<Error><Code>NoSuchTagSet</Code></Error>"))
				return
			}
			w.WriteHeader(204) // a DELETE must NOT be reached
			t.Errorf("delete must not proceed on an untagged (not-ours) bucket")
		}))
	defer srv.Close()
	d := s3TestDriver(t, srv)
	res := d.deleteS3("assets", "prod", "s3:eu-central-1:pv-assets-abcd1234")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("an untagged bucket must refuse delete (NoSuchTagSet != gone), got %+v", res)
	}
}

// VPC flow-logs partial (review #5): a 200 with an <unsuccessful> set means the
// flow log was NOT created — create must be failed (audit not on), never succeeded.
func TestCreateAWSVPCFlowLogsPartialFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, r.ContentLength)
			r.Body.Read(b)
			switch {
			case strings.Contains(string(b), "CreateVpc"):
				_, _ = w.Write([]byte(`<CreateVpcResponse><vpc><vpcId>vpc-0abc123</vpcId></vpc></CreateVpcResponse>`))
			case strings.Contains(string(b), "CreateSubnet"):
				_, _ = w.Write([]byte(`<CreateSubnetResponse><subnet><subnetId>subnet-0x</subnetId></subnet></CreateSubnetResponse>`))
			case strings.Contains(string(b), "CreateSecurityGroup"):
				// ingress.public declared => baseline SG authored before flow logs
				_, _ = w.Write([]byte(`<CreateSecurityGroupResponse><groupId>sg-01</groupId></CreateSecurityGroupResponse>`))
			case strings.Contains(string(b), "AuthorizeSecurityGroupIngress"):
				_, _ = w.Write([]byte(`<Response/>`))
			case strings.Contains(string(b), "CreateFlowLogs"):
				// 200 but the batch failed: unsuccessful, no flowLogId
				_, _ = w.Write([]byte(`<CreateFlowLogsResponse><unsuccessful><item><error><code>Bad</code></error></item></unsuccessful></CreateFlowLogsResponse>`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	a := awsVpcAttrs()
	a["flowLogs.enabled"] = true
	res := d.createAWSVPC("eu-central-1", "000000000000", "prod", "net", a,
		map[string]any{"flow_log_destination": "grp", "flow_log_role_arn": "arn:role"}, 1)
	if res.Status != "failed" || res.ProviderID == "" {
		t.Fatalf("flow-logs partial must be failed WITH pid (audit not on), got %+v", res)
	}
}

// DBIdentifier collapses consecutive hyphens (review #13) — RDS rejects "--".
func TestDBIdentifierNoConsecutiveHyphens(t *testing.T) {
	id := DBIdentifier("acct", "prod", "a_.b--c", 1)
	if strings.Contains(id, "--") {
		t.Fatalf("db id must not contain consecutive hyphens: %q", id)
	}
	if !dbIDOK.MatchString(id) {
		t.Fatalf("db id invalid: %q", id)
	}
}
