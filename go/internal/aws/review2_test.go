package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ECS resume message-match (review #2, self-introduced regression the second pass
// caught): the "already exists" resume signal lives in the ECS error MESSAGE
// ("Creation of service was not idempotent."), NOT the __type
// (InvalidParameterException). ecsErr must join both so a re-run of a create whose
// service already exists (and is OURS) continues to poll instead of failing.
func TestCreateECSResumesOnIdempotentMessage(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	describes := 0
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			target := r.Header.Get("X-Amz-Target")
			action := target[strings.LastIndex(target, ".")+1:]
			switch action {
			case "CreateCluster":
				_, _ = w.Write([]byte(`{"cluster":{"status":"ACTIVE"}}`))
			case "RegisterTaskDefinition":
				_, _ = w.Write([]byte(`{"taskDefinition":{"taskDefinitionArn":"arn:aws:ecs:eu-central-1:000000000000:task-definition/app:1"}}`))
			case "CreateService":
				// the message carries the resume signal; the __type does not
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"InvalidParameterException","message":"Creation of service was not idempotent."}`))
			case "DescribeServices":
				describes++
				running, roll := 0, "IN_PROGRESS"
				if describes >= 2 {
					running, roll = 1, "COMPLETED"
				}
				_, _ = w.Write([]byte(`{"services":[{"status":"ACTIVE","runningCount":` + itoa(running) +
					`,"desiredCount":1,"launchType":"FARGATE","deployments":[{"rolloutState":"` + roll + `"}],` +
					`"tags":[{"key":"groundhold-capability","value":"app"},{"key":"groundhold-environment","value":"prod"}]}]}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := ecsTestDriver(t, srv)
	res := d.createECS("eu-central-1", "000000000000", "prod", "app", ecsAttrs(), ecsImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("an already-exists OURS service must resume to succeeded via the message match, got %+v", res)
	}
}

// deleteECS cluster ownership (review #2): after the service (the workload) is
// retired, a same-name cluster whose tags are NOT ours must be LEFT STANDING
// (succeeded, cluster untouched) — never deleted. DeleteCluster must not be called.
func TestDeleteECSForeignClusterLeftStanding(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	deleted := false
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			target := r.Header.Get("X-Amz-Target")
			action := target[strings.LastIndex(target, ".")+1:]
			switch action {
			case "DescribeServices":
				if deleted {
					_, _ = w.Write([]byte(`{"services":[{"status":"INACTIVE"}]}`))
					return
				}
				_, _ = w.Write([]byte(`{"services":[{"status":"ACTIVE","runningCount":1,"desiredCount":1,` +
					`"tags":[{"key":"groundhold-capability","value":"app"},{"key":"groundhold-environment","value":"prod"}]}]}`))
			case "DeleteService":
				deleted = true
				_, _ = w.Write([]byte(`{}`))
			case "DescribeClusters":
				// the cluster is tagged for a DIFFERENT capability — not ours
				_, _ = w.Write([]byte(`{"clusters":[{"tags":[{"key":"groundhold-capability","value":"other"},` +
					`{"key":"groundhold-environment","value":"prod"}]}]}`))
			case "DeleteCluster":
				t.Errorf("DeleteCluster must NOT be called on a foreign cluster")
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := ecsTestDriver(t, srv)
	res := d.deleteECS("app", "prod", "ecs:eu-central-1:app-abcd1234")
	if res.Status != "succeeded" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("service retired but foreign cluster must be left standing (succeeded), got %+v", res)
	}
}

// RDS delete 3xx (review #2): a 3xx (e.g. 301 PermanentRedirect) on DeleteDBInstance
// is NOT a confirmed accepted delete — it must be failed, never a silent succeeded.
func TestDeleteRDS3xxIsFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, r.ContentLength)
			r.Body.Read(b)
			if strings.Contains(string(b), "DescribeDBInstances") {
				_, _ = w.Write([]byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>` +
					`<DBInstanceIdentifier>db-abcd1234</DBInstanceIdentifier><DBInstanceStatus>available</DBInstanceStatus>` +
					`<DeletionProtection>false</DeletionProtection>` +
					`<TagList><Tag><Key>groundhold-capability</Key><Value>db</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag></TagList>` +
					`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
				return
			}
			w.WriteHeader(301) // DeleteDBInstance answered with a redirect
		}))
	defer srv.Close()
	d := rdsTestDriver(t, srv)
	res := d.deleteRDS("db", "prod", "rds:eu-central-1:db-abcd1234")
	if res.Status != "failed" {
		t.Fatalf("a 3xx on delete is not an accepted delete — must be failed, got %+v", res)
	}
}

// Validate refuses a missing region (review #2): the builders don't all enforce
// regionOK, so Validate refuses an invalid/missing location.region up front
// (refuse-before-mutate), mirroring createScope at apply.
func TestValidateRefusesMissingRegion(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	attrs := map[string]any{"engine.protocol": "postgresql/16", "encryption.atRest": true, "service.managed": true}
	err := d.Validate("rds", "db", "prod", attrs, rdsImpl(), 1)
	if err == nil || !strings.Contains(err.Error(), "location.region") {
		t.Fatalf("Validate must refuse a missing region, got %v", err)
	}
}
