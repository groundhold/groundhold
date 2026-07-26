package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Review round 3 (adversarial review): the ambiguous "may have landed" create branches must
// carry the deterministic providerId so a reconcile keeps the handle (invariant
// #1). Each had a sibling path in the same file that already did it correctly.

// RDS create 5xx -> unknown WITH pid.
func TestCreateRDS5xxCarriesPid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>InternalFailure</Code></Error></ErrorResponse>`))
		}))
	defer srv.Close()
	d := rdsTestDriver(t, srv)
	res := d.createRDS("eu-central-1", "000000000000", "prod", "db", rdsAttrs(), rdsImpl(), 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a 5xx create may have landed — must be unknown WITH pid, got %+v", res)
	}
}

// RDS DBInstanceAlreadyExists + unreadable describe -> unknown WITH pid (AWS
// confirmed the instance exists; the deterministic pid is a valid handle).
func TestCreateRDSAlreadyExistsUnreadableCarriesPid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, r.ContentLength)
			r.Body.Read(b)
			if strings.Contains(string(b), "CreateDBInstance") {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>DBInstanceAlreadyExists</Code></Error></ErrorResponse>`))
				return
			}
			// the follow-up describe is unreadable (5xx)
			w.WriteHeader(500)
		}))
	defer srv.Close()
	d := rdsTestDriver(t, srv)
	res := d.createRDS("eu-central-1", "000000000000", "prod", "db", rdsAttrs(), rdsImpl(), 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("already-exists + unreadable must be unknown WITH pid, got %+v", res)
	}
}

// ECS CreateCluster 5xx -> unknown WITH pid (the cluster may have landed).
func TestCreateECSClusterErrorCarriesPid(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			target := r.Header.Get("X-Amz-Target")
			if strings.HasSuffix(target, "CreateCluster") {
				w.WriteHeader(500)
				_, _ = w.Write([]byte(`{"__type":"ServerException","message":"boom"}`))
				return
			}
			w.WriteHeader(400)
		}))
	defer srv.Close()
	d := ecsTestDriver(t, srv)
	res := d.createECS("eu-central-1", "000000000000", "prod", "app", ecsAttrs(), ecsImpl(), 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("cluster 5xx may have landed — must be unknown WITH pid, got %+v", res)
	}
}

// RDS builder refuses an unmapped availability.class rather than silently
// building single-AZ.
func TestRDSBuilderRefusesUnknownAvailability(t *testing.T) {
	a := rdsAttrs()
	a["availability.class"] = "frobnicate"
	_, _, err := BuildRDSCreate("000000000000", "prod", "db", a, rdsImpl(), 1)
	if err == nil || !strings.Contains(err.Error(), "availability.class") {
		t.Fatalf("an unmapped availability.class must refuse, got %v", err)
	}
}

// No credentials -> Create refuses (failed) before any mutation, never an
// ambiguous "unknown — may have landed".
func TestCreateNoCredsRefuses(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000" // even with an account cached, no creds must refuse
	res := d.Create("s3", "assets", "prod", s3Attrs(), nil, "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "refusing before any mutation") {
		t.Fatalf("no creds must refuse before mutating, got %+v", res)
	}
}

// VPC delete: a DeleteFlowLogs 200 carrying an <unsuccessful> item means the flow
// log was NOT deleted — the delete must be failed, symmetric with the create side.
func TestDeleteFlowLogsBatchUnsuccessfulFails(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, r.ContentLength)
			r.Body.Read(b)
			body := string(b)
			switch {
			case strings.Contains(body, "Action=DescribeVpcs"):
				_, _ = w.Write([]byte(`<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-0abc123</vpcId>` +
					`<tagSet><item><key>groundhold-capability</key><value>net</value></item>` +
					`<item><key>groundhold-environment</key><value>prod</value></item></tagSet>` +
					`</item></vpcSet></DescribeVpcsResponse>`))
			case strings.Contains(body, "Action=DescribeFlowLogs"):
				_, _ = w.Write([]byte(`<DescribeFlowLogsResponse><flowLogSet><item>` +
					`<flowLogId>fl-0abc</flowLogId></item></flowLogSet></DescribeFlowLogsResponse>`))
			case strings.Contains(body, "Action=DeleteFlowLogs"):
				// 200 but the batch item failed
				_, _ = w.Write([]byte(`<DeleteFlowLogsResponse><unsuccessful><item>` +
					`<error><code>Client.Error</code></error><resourceId>fl-0abc</resourceId>` +
					`</item></unsuccessful></DeleteFlowLogsResponse>`))
			case strings.Contains(body, "Action=DeleteSubnet") || strings.Contains(body, "Action=DeleteVpc"):
				t.Errorf("delete must halt on the unsuccessful flow-log batch, not proceed to %s", body)
				_, _ = w.Write([]byte(`<Response/>`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	res := d.deleteAWSVPC("net", "prod", "vpc:eu-central-1:vpc-0abc123")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not deleted") {
		t.Fatalf("an unsuccessful flow-log batch must fail the delete, got %+v", res)
	}
}
