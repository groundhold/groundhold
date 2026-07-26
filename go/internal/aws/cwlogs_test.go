package aws

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func cwLogsAttrs() map[string]any {
	return map[string]any{
		"location.region": "eu-central-1",
		"retention.days":  "90d",
		"service.managed": true,
	}
}

func TestBuildCWLogsHonors(t *testing.T) {
	p, err := BuildCWLogs("prod", "app-logs", cwLogsAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.LogGroupName, "pv-app-logs-prod-") {
		t.Fatalf("name = %q", p.LogGroupName)
	}
	if p.RetentionDays != 90 || p.Region != "eu-central-1" {
		t.Fatalf("plan = %+v", p)
	}
	// "2160h" (90 days in hours) must map identically to "90d".
	a := cwLogsAttrs()
	a["retention.days"] = "2160h"
	if p2, err := BuildCWLogs("prod", "app-logs", a, nil, 1); err != nil || p2.RetentionDays != 90 {
		t.Fatalf("hours form: %+v err=%v", p2, err)
	}
}

func TestBuildCWLogsRetentionSetEnforced(t *testing.T) {
	// 100 days is a valid duration but NOT in CloudWatch's allowed set — refuse,
	// never silently round to 90 or 120.
	a := cwLogsAttrs()
	a["retention.days"] = "100d"
	if _, err := BuildCWLogs("prod", "app-logs", a, nil, 1); err == nil {
		t.Fatal("retention day count outside the allowed set must refuse")
	}
	// a fractional-day duration must refuse.
	a["retention.days"] = "36h"
	if _, err := BuildCWLogs("prod", "app-logs", a, nil, 1); err == nil {
		t.Fatal("fractional-day retention must refuse")
	}
	// an allowed value passes.
	a["retention.days"] = "365d"
	if p, err := BuildCWLogs("prod", "app-logs", a, nil, 1); err != nil || p.RetentionDays != 365 {
		t.Fatalf("365d: %+v err=%v", p, err)
	}
}

func TestBuildCWLogsRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"no-retention": {"retention.days": nil},
		"bad-region":   {"location.region": "nope"},
		"unmanaged":    {"service.managed": false},
		"unknown-attr": {"log.format": "json"},
		"bad-duration": {"retention.days": "nope"},
	}
	for name, extra := range cases {
		a := cwLogsAttrs()
		for k, v := range extra {
			if v == nil {
				delete(a, k)
			} else {
				a[k] = v
			}
		}
		if _, err := BuildCWLogs("prod", "app-logs", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

func TestBuildCWLogsCMKRequiresArn(t *testing.T) {
	a := cwLogsAttrs()
	a["encryption.customerManagedKeys"] = true
	if _, err := BuildCWLogs("prod", "app-logs", a, nil, 1); err == nil {
		t.Fatal("cmk without impl.kmsKeyArn must refuse")
	}
	p, err := BuildCWLogs("prod", "app-logs", a,
		map[string]any{"kmsKeyArn": "arn:aws:kms:eu-central-1:0:key/k"}, 1)
	if err != nil || !p.CMK || p.KmsKeyArn == "" {
		t.Fatalf("cmk: %+v err=%v", p, err)
	}
}

func TestBuildCWLogsNameOperand(t *testing.T) {
	p, err := BuildCWLogs("prod", "app-logs", cwLogsAttrs(),
		map[string]any{"log_group": "/aws/vpc/flowlogs"}, 1)
	if err != nil || p.LogGroupName != "/aws/vpc/flowlogs" {
		t.Fatalf("pinned name operand: %+v err=%v", p, err)
	}
}

func TestClassifyCWLogsChange(t *testing.T) {
	if k, _ := classifyCWLogsChange("retention.days"); k != "mutable" {
		t.Fatalf("retention.days should be mutable, got %q", k)
	}
	if k, _ := classifyCWLogsChange("encryption.customerManagedKeys"); k != "mutable" {
		t.Fatalf("cmk should be mutable, got %q", k)
	}
	if k, _ := classifyCWLogsChange("location.region"); k != "immutable" {
		t.Fatalf("region should be immutable, got %q", k)
	}
}

// cwLogsServer is a CloudWatch Logs JSON double dispatching on X-Amz-Target.
// DescribeLogGroups reflects the exact group with the given retention/kms;
// ListTagsForResource reflects the owner tags.
func cwLogsServer(t *testing.T, name, capLabel string, retentionDays int, kmsKeyId string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			target := r.Header.Get("X-Amz-Target")
			action := target[strings.LastIndex(target, ".")+1:]
			switch action {
			case "DescribeLogGroups":
				arn := "arn:aws:logs:eu-central-1:000000000000:log-group:" + name + ":*"
				grp := map[string]any{"logGroupName": name, "arn": arn}
				if retentionDays > 0 {
					grp["retentionInDays"] = retentionDays
				}
				if kmsKeyId != "" {
					grp["kmsKeyId"] = kmsKeyId
				}
				out, _ := json.Marshal(map[string]any{"logGroups": []any{grp}})
				_, _ = w.Write(out)
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"` + capLabel +
					`","groundhold-environment":"prod"}}`))
			case "CreateLogGroup", "PutRetentionPolicy", "AssociateKmsKey",
				"DisassociateKmsKey", "DeleteLogGroup":
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func cwLogsDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	d.LogsBaseURL = srv.URL
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteCWLogs(t *testing.T) {
	name := CWLogGroupName("prod", "app-logs", 1)
	srv := cwLogsServer(t, name, "app-logs", 90, "")
	defer srv.Close()
	d := cwLogsDriver(t, srv)

	res := d.createCWLogs("eu-central-1", "prod", "app-logs", cwLogsAttrs(), nil, 1)
	if res.Status != "succeeded" || res.ProviderID != cwLogsProviderID("eu-central-1", name) {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeCWLogs("app-logs", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["retention.days"] != "2160h" || got["location.region"] != "eu-central-1" ||
		got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if _, has := got["encryption.customerManagedKeys"]; has {
		t.Fatalf("no CMK associated — must not emit encryption.customerManagedKeys: %+v", got)
	}
	if del := d.deleteCWLogs("app-logs", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestObserveCWLogsCMK(t *testing.T) {
	name := "cmk-group"
	srv := cwLogsServer(t, name, "app-logs", 365, "arn:aws:kms:eu-central-1:000000000000:key/abc")
	defer srv.Close()
	d := cwLogsDriver(t, srv)
	obs, _, err := d.observeCWLogs("app-logs", cwLogsProviderID("eu-central-1", name))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["encryption.customerManagedKeys"] != true || got["retention.days"] != "8760h" {
		t.Fatalf("cmk observe: %+v", got)
	}
}

func TestDeleteCWLogsForeignRefused(t *testing.T) {
	name := CWLogGroupName("prod", "app-logs", 1)
	srv := cwLogsServer(t, name, "someone-else", 90, "")
	defer srv.Close()
	d := cwLogsDriver(t, srv)
	res := d.deleteCWLogs("app-logs", "prod", cwLogsProviderID("eu-central-1", name))
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign log group must refuse delete, got %+v", res)
	}
}

func TestUpdateCWLogsRetention(t *testing.T) {
	name := CWLogGroupName("prod", "app-logs", 1)
	srv := cwLogsServer(t, name, "app-logs", 90, "")
	defer srv.Close()
	d := cwLogsDriver(t, srv)
	a := cwLogsAttrs()
	a["retention.days"] = "365d"
	res := d.updateCWLogs("app-logs", "prod", cwLogsProviderID("eu-central-1", name),
		a, nil, []string{"retention.days"})
	if res.Status != "succeeded" {
		t.Fatalf("update retention: %+v", res)
	}
}

func TestDiscoverCWLogs(t *testing.T) {
	srv := cwLogsServer(t, "any-group", "app-logs", 30, "")
	defer srv.Close()
	d := cwLogsDriver(t, srv)
	found, _, err := d.discoverCWLogs("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ResourceType != "capability.monitoring.logs" ||
		found[0].ProviderID != cwLogsProviderID("eu-central-1", "any-group") {
		t.Fatalf("discover: %+v", found)
	}
}
