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

const cloudTrailTestAccount = "000000000000"
const cloudTrailTestBucket = "acme-audit-logs-eu"
const cloudTrailTestKms = "arn:aws:kms:eu-central-1:000000000000:key/1234abcd-12ab-34cd-56ef-1234567890ab"

func cloudTrailAttrs() map[string]any {
	return map[string]any{
		"location.region":                "eu-central-1",
		"scope.multiRegion":              true,
		"integrity.logValidation":        true,
		"encryption.customerManagedKeys": true,
		"delivery.assured":               true,
		"service.managed":                true,
	}
}

func cloudTrailImpl() map[string]any {
	return map[string]any{
		"s3BucketName": cloudTrailTestBucket,
		"kmsKeyArn":    cloudTrailTestKms,
	}
}

func cloudTrailAction(r *http.Request) string {
	full := r.Header.Get("X-Amz-Target")
	return full[strings.LastIndex(full, ".")+1:]
}

func cloudTrailDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = cloudTrailTestAccount
	cloudTrailBaseURLOverride = srv.URL
	t.Cleanup(func() { cloudTrailBaseURLOverride = "" })
	d.Now = time.Now
	return d
}

func cloudTrailArn(name string) string {
	return "arn:aws:cloudtrail:eu-central-1:" + cloudTrailTestAccount + ":trail/" + name
}

// ---- pure-builder honors + refusals (refuse-before-mutate) ----------------

func TestBuildCloudTrailHonors(t *testing.T) {
	p, err := BuildCloudTrail("prod", "audit", cloudTrailAttrs(), cloudTrailImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.Name, "pv-audit-prod-") || !cloudTrailNameOK.MatchString(p.Name) {
		t.Fatalf("name = %q", p.Name)
	}
	if !p.MultiRegion || !p.LogValidation || !p.CMK || !p.DeliveryAssured ||
		p.KmsKeyArn != cloudTrailTestKms || p.S3BucketName != cloudTrailTestBucket ||
		!p.IncludeGlobalServiceEvents {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createTrailBody("audit", "prod")
	if body["S3BucketName"] != cloudTrailTestBucket || body["IsMultiRegionTrail"] != true ||
		body["EnableLogFileValidation"] != true || body["KmsKeyId"] != cloudTrailTestKms {
		t.Fatalf("create body = %+v", body)
	}
	if _, has := body["TagsList"]; !has {
		t.Fatal("create body must carry ownership TagsList")
	}
}

func TestBuildCloudTrailRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"unknown-attr": {"trail.rollover": true},
		"unmanaged":    {"service.managed": false},
		"bad-region":   {"location.region": "nope"},
		"bad-multi":    {"scope.multiRegion": "yes"},
	}
	for name, extra := range cases {
		a := cloudTrailAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildCloudTrail("prod", "audit", a, cloudTrailImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// missing destination bucket
	if _, err := BuildCloudTrail("prod", "audit", cloudTrailAttrs(), map[string]any{"kmsKeyArn": cloudTrailTestKms}, 1); err == nil {
		t.Error("missing s3BucketName must refuse")
	}
}

func TestBuildCloudTrailCMKRequiresArn(t *testing.T) {
	// CMK asked, no key
	if _, err := BuildCloudTrail("prod", "audit", cloudTrailAttrs(), map[string]any{"s3BucketName": cloudTrailTestBucket}, 1); err == nil {
		t.Fatal("CMK without kmsKeyArn must refuse")
	}
	// key given but CMK not asked -> ambiguous
	a := cloudTrailAttrs()
	a["encryption.customerManagedKeys"] = false
	if _, err := BuildCloudTrail("prod", "audit", a, cloudTrailImpl(), 1); err == nil {
		t.Fatal("kmsKeyArn given without CMK must refuse (ambiguous shape)")
	}
}

func TestBuildCloudTrailCWLogsNeedsRole(t *testing.T) {
	impl := cloudTrailImpl()
	impl["cloudWatchLogsGroupArn"] = "arn:aws:logs:eu-central-1:000000000000:log-group:/aws/cloudtrail/acme"
	if _, err := BuildCloudTrail("prod", "audit", cloudTrailAttrs(), impl, 1); err == nil {
		t.Fatal("cloudWatchLogsGroupArn without a role must refuse")
	}
	impl["cloudWatchLogsRoleArn"] = "arn:aws:iam::000000000000:role/cloudtrail-cwlogs"
	if _, err := BuildCloudTrail("prod", "audit", cloudTrailAttrs(), impl, 1); err != nil {
		t.Fatalf("group+role should build: %v", err)
	}
}

// ---- create: composite (CreateTrail + StartLogging), SigV4, body ----------

func TestCreateCloudTrail(t *testing.T) {
	var createBody []byte
	var createAuth string
	var started bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch cloudTrailAction(r) {
			case "GetTrail":
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"TrailNotFoundException","message":"no such trail"}`))
			case "CreateTrail":
				createBody = body
				createAuth = r.Header.Get("Authorization")
				_, _ = w.Write([]byte(`{"Trail":{"Name":"pv-x","TrailARN":"` + cloudTrailArn("pv-x") + `"}}`))
			case "StartLogging":
				started = true
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := cloudTrailDriver(t, srv)

	res := d.createCloudTrail("eu-central-1", "prod", "audit", cloudTrailAttrs(), cloudTrailImpl(), 1)
	if res.Status != "succeeded" || !started {
		t.Fatalf("create: %+v (started=%v)", res, started)
	}
	if !strings.HasPrefix(res.ProviderID, "cloudtrail:eu-central-1:pv-audit-prod-") {
		t.Fatalf("pid = %q", res.ProviderID)
	}
	if !strings.HasPrefix(createAuth, "AWS4-HMAC-SHA256") ||
		!strings.Contains(createAuth, "/eu-central-1/cloudtrail/aws4_request") {
		t.Fatalf("CreateTrail not SigV4-signed for eu-central-1/cloudtrail: %q", createAuth)
	}
	var cb struct {
		Name                    string `json:"Name"`
		S3BucketName            string `json:"S3BucketName"`
		IsMultiRegionTrail      bool   `json:"IsMultiRegionTrail"`
		EnableLogFileValidation bool   `json:"EnableLogFileValidation"`
		KmsKeyId                string `json:"KmsKeyId"`
		TagsList                []struct {
			Key, Value string
		} `json:"TagsList"`
	}
	if err := json.Unmarshal(createBody, &cb); err != nil {
		t.Fatal(err)
	}
	if cb.S3BucketName != cloudTrailTestBucket || !cb.IsMultiRegionTrail ||
		!cb.EnableLogFileValidation || cb.KmsKeyId != cloudTrailTestKms || len(cb.TagsList) != 2 {
		t.Fatalf("CreateTrail body = %s", createBody)
	}
}

func TestCreateCloudTrailStartLoggingPartial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch cloudTrailAction(r) {
			case "GetTrail":
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"TrailNotFoundException"}`))
			case "CreateTrail":
				_, _ = w.Write([]byte(`{"Trail":{"Name":"pv-x","TrailARN":"` + cloudTrailArn("pv-x") + `"}}`))
			case "StartLogging":
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"InvalidTrailNameException","message":"bad"}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := cloudTrailDriver(t, srv)
	res := d.createCloudTrail("eu-central-1", "prod", "audit", cloudTrailAttrs(), cloudTrailImpl(), 1)
	if res.Status != "unknown" {
		t.Fatalf("StartLogging failure must be unknown, got %+v", res)
	}
	if !strings.HasPrefix(res.ProviderID, "cloudtrail:eu-central-1:") {
		t.Fatalf("partial must carry the providerId, got %+v", res)
	}
}

func TestCreateCloudTrailForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch cloudTrailAction(r) {
			case "GetTrail":
				_, _ = w.Write([]byte(`{"Trail":{"Name":"pv-x","TrailARN":"` + cloudTrailArn("pv-x") + `"}}`))
			case "ListTags":
				_, _ = w.Write([]byte(`{"ResourceTagList":[{"ResourceId":"` + cloudTrailArn("pv-x") +
					`","TagsList":[{"Key":"groundhold-capability","Value":"someone-else"},{"Key":"groundhold-environment","Value":"prod"}]}]}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := cloudTrailDriver(t, srv)
	res := d.createCloudTrail("eu-central-1", "prod", "audit", cloudTrailAttrs(), cloudTrailImpl(), 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign trail at our name must refuse, got %+v", res)
	}
}

// ---- observe reverse-map --------------------------------------------------

func TestObserveCloudTrail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch cloudTrailAction(r) {
			case "GetTrail":
				_, _ = w.Write([]byte(`{"Trail":{"Name":"pv-x","TrailARN":"` + cloudTrailArn("pv-x") + `",` +
					`"HomeRegion":"eu-central-1","IsMultiRegionTrail":true,"LogFileValidationEnabled":true,` +
					`"KmsKeyId":"` + cloudTrailTestKms + `","S3BucketName":"` + cloudTrailTestBucket + `"}}`))
			case "GetTrailStatus":
				_, _ = w.Write([]byte(`{"IsLogging":true}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := cloudTrailDriver(t, srv)
	pid := cloudTrailProviderID("eu-central-1", CloudTrailName("prod", "audit", 1))
	obs, diags, err := d.observeCloudTrail("audit", pid)
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) != 0 {
		t.Fatalf("diags = %v", diags)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eu-central-1" || got["scope.multiRegion"] != true ||
		got["integrity.logValidation"] != true || got["encryption.customerManagedKeys"] != true ||
		got["delivery.assured"] != true || got["service.managed"] != true {
		t.Fatalf("observe = %+v", got)
	}
}

func TestObserveCloudTrailNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"__type":"TrailNotFoundException"}`))
		}))
	defer srv.Close()
	d := cloudTrailDriver(t, srv)
	pid := cloudTrailProviderID("eu-central-1", CloudTrailName("prod", "audit", 1))
	obs, diags, err := d.observeCloudTrail("audit", pid)
	if err != nil {
		t.Fatalf("not-found must not error: %v", err)
	}
	if len(obs) != 0 || len(diags) != 1 {
		t.Fatalf("not-found = obs %v diags %v", obs, diags)
	}
}

func TestObserveCloudTrailStatusUnreadableOmits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch cloudTrailAction(r) {
			case "GetTrail":
				_, _ = w.Write([]byte(`{"Trail":{"Name":"pv-x","TrailARN":"` + cloudTrailArn("pv-x") +
					`","IsMultiRegionTrail":false,"LogFileValidationEnabled":false}}`))
			default:
				w.WriteHeader(500) // GetTrailStatus unreadable
			}
		}))
	defer srv.Close()
	d := cloudTrailDriver(t, srv)
	pid := cloudTrailProviderID("eu-central-1", CloudTrailName("prod", "audit", 1))
	obs, diags, err := d.observeCloudTrail("audit", pid)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "delivery.assured" {
			t.Fatal("delivery.assured must be omitted when GetTrailStatus is unreadable, not fabricated")
		}
	}
	if len(diags) != 1 {
		t.Fatalf("expected one omission diagnostic, got %v", diags)
	}
}

// ---- update ---------------------------------------------------------------

func TestUpdateCloudTrail(t *testing.T) {
	var updated, started bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch cloudTrailAction(r) {
			case "GetTrail":
				_, _ = w.Write([]byte(`{"Trail":{"Name":"pv-x","TrailARN":"` + cloudTrailArn("pv-x") + `"}}`))
			case "ListTags":
				_, _ = w.Write([]byte(`{"ResourceTagList":[{"ResourceId":"` + cloudTrailArn("pv-x") +
					`","TagsList":[{"Key":"groundhold-capability","Value":"audit"},{"Key":"groundhold-environment","Value":"prod"}]}]}`))
			case "UpdateTrail":
				updated = true
				_, _ = w.Write([]byte(`{}`))
			case "StartLogging":
				started = true
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := cloudTrailDriver(t, srv)
	pid := cloudTrailProviderID("eu-central-1", CloudTrailName("prod", "audit", 1))
	res := d.updateCloudTrail("audit", "prod", pid, cloudTrailAttrs(), cloudTrailImpl(),
		[]string{"scope.multiRegion", "delivery.assured"})
	if res.Status != "succeeded" || !updated || !started {
		t.Fatalf("update: %+v (updated=%v started=%v)", res, updated, started)
	}
}

func TestUpdateCloudTrailForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch cloudTrailAction(r) {
			case "GetTrail":
				_, _ = w.Write([]byte(`{"Trail":{"Name":"pv-x","TrailARN":"` + cloudTrailArn("pv-x") + `"}}`))
			case "ListTags":
				_, _ = w.Write([]byte(`{"ResourceTagList":[{"ResourceId":"` + cloudTrailArn("pv-x") +
					`","TagsList":[{"Key":"groundhold-capability","Value":"someone-else"}]}]}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := cloudTrailDriver(t, srv)
	pid := cloudTrailProviderID("eu-central-1", CloudTrailName("prod", "audit", 1))
	res := d.updateCloudTrail("audit", "prod", pid, cloudTrailAttrs(), cloudTrailImpl(),
		[]string{"integrity.logValidation"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign trail update must refuse, got %+v", res)
	}
}

// ---- delete ---------------------------------------------------------------

func TestDeleteCloudTrail(t *testing.T) {
	var deleted bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch cloudTrailAction(r) {
			case "GetTrail":
				_, _ = w.Write([]byte(`{"Trail":{"Name":"pv-x","TrailARN":"` + cloudTrailArn("pv-x") + `"}}`))
			case "ListTags":
				_, _ = w.Write([]byte(`{"ResourceTagList":[{"ResourceId":"` + cloudTrailArn("pv-x") +
					`","TagsList":[{"Key":"groundhold-capability","Value":"audit"},{"Key":"groundhold-environment","Value":"prod"}]}]}`))
			case "DeleteTrail":
				deleted = true
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := cloudTrailDriver(t, srv)
	pid := cloudTrailProviderID("eu-central-1", CloudTrailName("prod", "audit", 1))
	res := d.deleteCloudTrail("audit", "prod", pid)
	if res.Status != "succeeded" || !deleted {
		t.Fatalf("delete: %+v (deleted=%v)", res, deleted)
	}
}

func TestDeleteCloudTrailForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch cloudTrailAction(r) {
			case "GetTrail":
				_, _ = w.Write([]byte(`{"Trail":{"Name":"pv-x","TrailARN":"` + cloudTrailArn("pv-x") + `"}}`))
			case "ListTags":
				_, _ = w.Write([]byte(`{"ResourceTagList":[{"ResourceId":"` + cloudTrailArn("pv-x") +
					`","TagsList":[{"Key":"groundhold-capability","Value":"someone-else"},{"Key":"groundhold-environment","Value":"prod"}]}]}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := cloudTrailDriver(t, srv)
	pid := cloudTrailProviderID("eu-central-1", CloudTrailName("prod", "audit", 1))
	res := d.deleteCloudTrail("audit", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign trail must refuse delete, got %+v", res)
	}
}

func TestDeleteCloudTrailIdempotentWhenGone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"__type":"TrailNotFoundException"}`))
		}))
	defer srv.Close()
	d := cloudTrailDriver(t, srv)
	pid := cloudTrailProviderID("eu-central-1", CloudTrailName("prod", "audit", 1))
	res := d.deleteCloudTrail("audit", "prod", pid)
	if res.Status != "succeeded" {
		t.Fatalf("gone trail must delete idempotently, got %+v", res)
	}
}

// ---- classify -------------------------------------------------------------

func TestClassifyCloudTrailChange(t *testing.T) {
	for _, path := range []string{"scope.multiRegion", "integrity.logValidation", "encryption.customerManagedKeys", "delivery.assured"} {
		if c, _ := classifyCloudTrailChange(path); c != "mutable" {
			t.Errorf("%s -> %s (want mutable)", path, c)
		}
	}
	if c, _ := classifyCloudTrailChange("location.region"); c != "immutable" {
		t.Errorf("location.region -> %s (want immutable)", c)
	}
	if c, _ := classifyCloudTrailChange("service.managed"); c != "unsupported" {
		t.Errorf("service.managed -> %s (want unsupported)", c)
	}
}

// ---- discover -------------------------------------------------------------

func TestDiscoverCloudTrail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch cloudTrailAction(r) {
			case "ListTrails":
				_, _ = w.Write([]byte(`{"Trails":[` +
					`{"Name":"pv-audit-prod-abcdefgh","TrailARN":"` + cloudTrailArn("pv-audit-prod-abcdefgh") + `","HomeRegion":"eu-central-1"},` +
					`{"Name":"shadow","TrailARN":"arn:aws:cloudtrail:us-east-1:000000000000:trail/shadow","HomeRegion":"us-east-1"}]}`))
			case "GetTrail":
				_, _ = w.Write([]byte(`{"Trail":{"Name":"pv-audit-prod-abcdefgh","TrailARN":"` + cloudTrailArn("pv-audit-prod-abcdefgh") +
					`","HomeRegion":"eu-central-1","IsMultiRegionTrail":true,"LogFileValidationEnabled":true}}`))
			case "GetTrailStatus":
				_, _ = w.Write([]byte(`{"IsLogging":true}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := cloudTrailDriver(t, srv)
	found, diags, err := d.discoverCloudTrail("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) != 0 {
		t.Fatalf("diags = %v", diags)
	}
	if len(found) != 1 || found[0].ResourceType != "capability.audit.trail" ||
		found[0].ProviderID != "cloudtrail:eu-central-1:pv-audit-prod-abcdefgh" {
		t.Fatalf("discover = %+v (shadow trail from another home region must be filtered)", found)
	}
}
