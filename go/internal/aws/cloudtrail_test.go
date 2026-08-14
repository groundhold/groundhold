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
				// D725: a HEALTHY trail has actually delivered. `IsLogging` alone only says
				// StartLogging was called, and a trail whose bucket refuses the writes
				// keeps it true forever.
				_, _ = w.Write([]byte(`{"IsLogging":true,"LatestDeliveryTime":1700000000}`))
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
	// Corrected with D520: this asserted SILENCE for an absent bound resource,
	// which is the defect F-LC3 exists to prevent — the compile sees an empty set,
	// plans nothing, and converge reports a world that no longer contains it.
	if !absentMarked(obs) || len(diags) != 1 {
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
				// D725: a HEALTHY trail has actually delivered. `IsLogging` alone only says
				// StartLogging was called, and a trail whose bucket refuses the writes
				// keeps it true forever.
				_, _ = w.Write([]byte(`{"IsLogging":true,"LatestDeliveryTime":1700000000}`))
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

func cloudTrailRole(req *http.Request, _ []byte) certifynet.Role {
	switch cloudTrailAction(req) {
	case "GetTrail", "GetTrailStatus", "ListTags", "DescribeTrails":
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingCloudTrail enrols cloudtrail in the D391 gate. The create reads the
// trail and its tags before writing (D391), so a trail of OURS standing at the name is
// adopted: logging is ensured and the binding returns succeeded. D804 replaced a fixture
// that modelled a RACE instead — see TestCloudTrailRaceConcludesUnknown below, which
// keeps that case rather than losing it.
// cloudtrailAdoptSrv builds a 409-adopt fixture: our trail already standing and
// logging, with the controls set however the case needs (D1062).
func cloudtrailAdoptSrv(multiRegion, logValidation, cmek bool) func() *httptest.Server {
	return func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch cloudTrailAction(r) {
			case "CreateTrail":
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"TrailAlreadyExistsException","Message":"exists"}`))
			case "GetTrail":
				kms := ""
				if cmek {
					kms = `"KmsKeyId":"` + cloudTrailTestKms + `",`
				}
				_, _ = w.Write([]byte(`{"Trail":{"Name":"pv-x","TrailARN":"` + cloudTrailArn("pv-x") +
					`","HomeRegion":"eu-central-1","IsMultiRegionTrail":` + boolStr(multiRegion) +
					`,"LogFileValidationEnabled":` + boolStr(logValidation) + `,` + kms +
					`"S3BucketName":"` + cloudTrailTestBucket + `"}}`))
			case "ListTags":
				_, _ = w.Write([]byte(`{"ResourceTagList":[{"ResourceId":"` + cloudTrailArn("pv-x") +
					`","TagsList":[{"Key":"groundhold-capability","Value":"audit"},` +
					`{"Key":"groundhold-environment","Value":"prod"}]}]}`))
			case "GetTrailStatus":
				_, _ = w.Write([]byte(`{"IsLogging":true,"LatestDeliveryTime":1700000000}`))
			case "StartLogging":
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
	}
}

func TestAdoptsExistingCloudTrail(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:     "aws/cloudtrail",
		Classify: cloudTrailRole,
		// D804: this fixture used to answer TrailNotFound to GetTrail and
		// TrailAlreadyExists to CreateTrail — a RACE (the trail appears between the read
		// and the write), not the ownership question this probe exists to ask. The
		// driver has read and checked tags since D391; the register listed it under
		// "creates that issue no read", which is a cause nobody measured here.
		//
		// The estate now SERVES the trail, carrying our tags, so the probe exercises the
		// real pre-read and the create adopts. The race keeps its own test below.
		ExistingServer: cloudtrailAdoptSrv(true, true, true),
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = cloudTrailTestAccount
			cloudTrailBaseURLOverride = happyURL
			t.Cleanup(func() { cloudTrailBaseURLOverride = "" })
			d.Now = time.Now
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("cloudtrail", "audit", "prod", cloudTrailAttrs(), cloudTrailImpl(), "audit", 1)
		},
		AllowedMutations: 1, // the refused CreateTrail
		// D1062: KMS key, log validation and multi-region scope are all re-assertable in
		// place (UpdateTrail), so a miss is unknown+bound and converge patches it.
		AdoptControls: cloudtrailAdoptControls,
		MissingControl: []certifynet.ControlCase{
			{Path: "encryption.customerManagedKeys", Server: cloudtrailAdoptSrv(true, true, false),
				WantStatus: "unknown", WantMutations: 1},
			{Path: "integrity.logValidation", Server: cloudtrailAdoptSrv(true, false, true),
				WantStatus: "unknown", WantMutations: 1},
			{Path: "scope.multiRegion", Server: cloudtrailAdoptSrv(false, true, true),
				WantStatus: "unknown", WantMutations: 1},
		},
		MoreSecure: cloudtrailAdoptSrv(true, true, true),
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// D725: the audit trail that is on and writes nothing. AWS keeps `IsLogging: true` when
// the destination bucket refuses the log files, and reports the refusal in
// `LatestDeliveryError` — "This error occurs only when there is a problem with the
// destination S3 bucket." A `delivery.assured: true` here tells an operator their audit
// record exists when it does not, which is the reading they would discover at incident
// time.
//
// The first version of this test asserted that the driver READ the error field. That is
// plumbing, and the mutation meter proved it: re-injecting the bug left it green. It
// asserts the OBSERVATION now — what a contract is judged against.
func TestCloudTrailDeliveryIsFalseWhenTheBucketRefusesTheWrites(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch cloudTrailAction(r) {
			case "GetTrail":
				_, _ = w.Write([]byte(`{"Trail":{"Name":"` + CloudTrailName("prod", "audit", 1) +
					`","TrailARN":"` + cloudTrailArn(CloudTrailName("prod", "audit", 1)) + `",` +
					`"HomeRegion":"eu-central-1","IsMultiRegionTrail":true,"LogFileValidationEnabled":true,` +
					`"KmsKeyId":"` + cloudTrailTestKms + `","S3BucketName":"` + cloudTrailTestBucket + `"}}`))
			case "GetTrailStatus":
				_, _ = w.Write([]byte(`{"IsLogging":true,"LatestDeliveryTime":1700000000,` +
					`"LatestDeliveryError":"AccessDenied. Check the S3 bucket policy"}`))
			default:
				_, _ = w.Write([]byte(`{}`))
			}
		}))
	defer srv.Close()
	d := cloudTrailDriver(t, srv)
	pid := cloudTrailProviderID("eu-central-1", CloudTrailName("prod", "audit", 1))

	obs, diags, err := d.observeCloudTrail("audit", pid)
	if err != nil {
		t.Fatal(err)
	}
	var got any
	for _, o := range obs {
		if o.Path == "delivery.assured" {
			got = o.Value
		}
	}
	if got != false {
		t.Fatalf("delivery.assured = %v — AWS reported that CloudTrail cannot write to "+
			"the destination bucket, so the audit record is not being kept", got)
	}
	var named bool
	for _, dg := range diags {
		if strings.Contains(dg, "AccessDenied") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the refusal reason must reach the operator; diags=%v", diags)
	}
}

// D804. The race the adopt probe used to model, kept as its own test: the ownership
// pre-read finds nothing, and CreateTrail then answers TrailAlreadyExists because
// something created the trail in between. Nothing was duplicated — the create was
// refused — but who owns it is unsettled, so this concludes UNKNOWN with the pid and
// leaves ownership to reconcile, rather than binding a trail it never read.
func TestCloudTrailRaceConcludesUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch cloudTrailAction(r) {
			case "GetTrail":
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"TrailNotFoundException","message":"no such trail"}`))
			case "CreateTrail":
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"TrailAlreadyExistsException","message":"TrailAlreadyExists"}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := cloudTrailDriver(t, srv)
	res := d.Create("cloudtrail", "audit", "prod", cloudTrailAttrs(), cloudTrailImpl(), "audit", 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a trail that appeared between the read and the write must conclude "+
			"unknown WITH the pid, got %+v", res)
	}
}
