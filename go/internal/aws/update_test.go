package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- ClassifyChange (PURE, per path per service) --------------------------

func TestClassifyChangeS3(t *testing.T) {
	d := NewDriver("eu-central-1")
	want := map[string]string{
		"versioning.enabled":             "mutable",
		"retention.maximum":              "mutable",
		"network.publicExposure":         "mutable",
		"encryption.customerManagedKeys": "mutable",
		"location.region":                "immutable",
		"durability.class":               "immutable",
		"encryption.atRest":              "unsupported",
		// WORM (Object Lock) is now honored at bucket birth (create-time only,
		// irreversible) — a change is a replacement, not an in-place patch.
		"retention.locked":  "immutable",
		"retention.minimum": "immutable",
	}
	for path, exp := range want {
		if got, _ := d.ClassifyChange("s3", path, nil, true, nil); got != exp {
			t.Errorf("s3 %s: got %q, want %q", path, got, exp)
		}
	}
}

func TestClassifyChangeSNS(t *testing.T) {
	d := NewDriver("eu-central-1")
	want := map[string]string{
		"network.publicExposure":         "mutable",
		"encryption.atRest":              "mutable",
		"encryption.customerManagedKeys": "mutable",
		"location.region":                "immutable",
		"service.managed":                "unsupported",
	}
	for path, exp := range want {
		if got, _ := d.ClassifyChange("sns", path, nil, true, nil); got != exp {
			t.Errorf("sns %s: got %q, want %q", path, got, exp)
		}
	}
}

func TestClassifyChangeSQS(t *testing.T) {
	d := NewDriver("eu-central-1")
	want := map[string]string{
		"retention.minimum":      "mutable",
		"network.publicExposure": "mutable",
		"encryption.atRest":      "mutable",
		"delivery.guarantee":     "immutable",
		"ordering.enabled":       "immutable",
		"location.region":        "immutable",
	}
	for path, exp := range want {
		if got, _ := d.ClassifyChange("sqs", path, nil, true, nil); got != exp {
			t.Errorf("sqs %s: got %q, want %q", path, got, exp)
		}
	}
}

func TestClassifyChangeRDS(t *testing.T) {
	d := NewDriver("eu-central-1")
	// availability.class is transition-dependent: zonal/regional caveated,
	// multi-regional unsupported.
	if got, _ := d.ClassifyChange("rds", "availability.class", nil, "regional", nil); got != "caveated" {
		t.Errorf("availability.class->regional: got %q, want caveated", got)
	}
	if got, _ := d.ClassifyChange("rds", "availability.class", nil, "multi-regional", nil); got != "unsupported" {
		t.Errorf("availability.class->multi-regional: got %q, want unsupported", got)
	}
	want := map[string]string{
		"network.publicExposure":         "mutable",
		"recovery.rpo":                   "mutable",
		"engine.protocol":                "immutable",
		"location.region":                "immutable",
		"encryption.atRest":              "unsupported",
		"encryption.customerManagedKeys": "unsupported",
	}
	for path, exp := range want {
		if got, _ := d.ClassifyChange("rds", path, nil, true, nil); got != exp {
			t.Errorf("rds %s: got %q, want %q", path, got, exp)
		}
	}
}

// ecs/vpc are deliberately not wired — honest "unsupported", never a silent
// claim of mutability.
func TestClassifyChangeUnwiredServices(t *testing.T) {
	d := NewDriver("eu-central-1")
	for _, svc := range []string{"ecs", "vpc"} {
		if got, _ := d.ClassifyChange(svc, "network.publicExposure", nil, true, nil); got != "immutable" {
			t.Errorf("%s (unwired) must classify a drift as immutable (replacement), got %q", svc, got)
		}
	}
}

// ---- S3 Update -------------------------------------------------------------

// s3UpdateServer serves OUR ownership tags on GET ?tagging (no prior PUT needed)
// and records which sub-resources the update touched.
func s3UpdateServer(t *testing.T, cap, env string, patchStatus int, hit map[string]bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		switch {
		case r.Method == "GET" && q == "tagging":
			_, _ = w.Write([]byte(`<Tagging><TagSet>` +
				`<Tag><Key>groundhold-capability</Key><Value>` + sanitizeTag(cap) + `</Value></Tag>` +
				`<Tag><Key>groundhold-environment</Key><Value>` + sanitizeTag(env) + `</Value></Tag>` +
				`</TagSet></Tagging>`))
		case r.Method == "DELETE" && q == "policy":
			hit["delete-policy"] = true
			w.WriteHeader(404)
			_, _ = w.Write([]byte("<Error><Code>NoSuchBucketPolicy</Code></Error>"))
		case r.Method == "PUT":
			hit[q] = true
			if patchStatus != 0 {
				w.WriteHeader(patchStatus)
				return
			}
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestUpdateS3VersioningPatchesOnlyVersioning(t *testing.T) {
	hit := map[string]bool{}
	srv := s3UpdateServer(t, "assets", "prod", 0, hit)
	defer srv.Close()
	d := s3TestDriver(t, srv)
	res := d.updateS3("assets", "prod", "s3:eu-central-1:pv-assets-abcd1234",
		s3Attrs(), nil, []string{"versioning.enabled"})
	if res.Status != "succeeded" {
		t.Fatalf("versioning update must succeed, got %+v", res)
	}
	if !hit["versioning"] {
		t.Errorf("versioning PUT was not issued")
	}
	if hit["tagging"] || hit["lifecycle"] || hit["encryption"] {
		t.Errorf("update patched paths it was not asked to: %v", hit)
	}
}

func TestUpdateS3RemovesPublicPolicyWhenPrivate(t *testing.T) {
	hit := map[string]bool{}
	srv := s3UpdateServer(t, "assets", "prod", 0, hit)
	defer srv.Close()
	d := s3TestDriver(t, srv)
	// s3Attrs has network.publicExposure=false -> the private transition must
	// re-assert the block AND remove any public policy.
	res := d.updateS3("assets", "prod", "s3:eu-central-1:pv-assets-abcd1234",
		s3Attrs(), nil, []string{"network.publicExposure"})
	if res.Status != "succeeded" {
		t.Fatalf("private transition must succeed, got %+v", res)
	}
	if !hit["publicAccessBlock"] || !hit["delete-policy"] {
		t.Errorf("private transition must block + remove policy, hit=%v", hit)
	}
}

func TestUpdateS3ForeignTagsRefuses(t *testing.T) {
	hit := map[string]bool{}
	srv := s3UpdateServer(t, "someone-else", "prod", 0, hit)
	defer srv.Close()
	d := s3TestDriver(t, srv)
	res := d.updateS3("assets", "prod", "s3:eu-central-1:pv-assets-abcd1234",
		s3Attrs(), nil, []string{"versioning.enabled"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a not-ours bucket must be refused, got %+v", res)
	}
	if hit["versioning"] {
		t.Errorf("update must NOT patch after an ownership mismatch")
	}
}

func TestUpdateS3ServerErrorIsUnknownWithPid(t *testing.T) {
	hit := map[string]bool{}
	srv := s3UpdateServer(t, "assets", "prod", 500, hit)
	defer srv.Close()
	d := s3TestDriver(t, srv)
	res := d.updateS3("assets", "prod", "s3:eu-central-1:pv-assets-abcd1234",
		s3Attrs(), nil, []string{"versioning.enabled"})
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a 5xx patch must be unknown WITH pid (may have landed), got %+v", res)
	}
}

// ---- SNS Update ------------------------------------------------------------

func snsUpdateServer(t *testing.T, cap, env string, setStatus int, seen *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch queryAction(body) {
		case "ListTagsForResource":
			_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><Tags>` +
				`<member><Key>groundhold-capability</Key><Value>` + sanitizeTag(cap) + `</Value></member>` +
				`<member><Key>groundhold-environment</Key><Value>` + sanitizeTag(env) + `</Value></member>` +
				`</Tags></ListTagsForResourceResult></ListTagsForResourceResponse>`))
		case "SetTopicAttributes":
			if seen != nil {
				*seen = string(body)
			}
			if setStatus != 0 {
				w.WriteHeader(setStatus)
				return
			}
			_, _ = w.Write([]byte(`<SetTopicAttributesResponse></SetTopicAttributesResponse>`))
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestUpdateSNSEncryptionPatchesKmsKey(t *testing.T) {
	var seen string
	srv := snsUpdateServer(t, "events", "prod", 0, &seen)
	defer srv.Close()
	d := snsTestDriver(t, srv)
	res := d.updateSNS("events", "prod", "sns:eu-central-1:000000000000:events-x",
		snsAttrs(), nil, []string{"encryption.atRest"})
	if res.Status != "succeeded" {
		t.Fatalf("encryption update must succeed, got %+v", res)
	}
	if !strings.Contains(seen, "KmsMasterKeyId") {
		t.Errorf("SetTopicAttributes must carry KmsMasterKeyId, body=%q", seen)
	}
}

func TestUpdateSNSForeignRefuses(t *testing.T) {
	srv := snsUpdateServer(t, "someone-else", "prod", 0, nil)
	defer srv.Close()
	d := snsTestDriver(t, srv)
	res := d.updateSNS("events", "prod", "sns:eu-central-1:000000000000:events-x",
		snsAttrs(), nil, []string{"encryption.atRest"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a not-ours topic must be refused, got %+v", res)
	}
}

func TestUpdateSNSServerErrorIsUnknownWithPid(t *testing.T) {
	srv := snsUpdateServer(t, "events", "prod", 500, nil)
	defer srv.Close()
	d := snsTestDriver(t, srv)
	res := d.updateSNS("events", "prod", "sns:eu-central-1:000000000000:events-x",
		snsAttrs(), nil, []string{"network.publicExposure"})
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a 5xx SetTopicAttributes must be unknown WITH pid, got %+v", res)
	}
}

// ---- SQS Update ------------------------------------------------------------

func sqsUpdateServer(t *testing.T, cap, env string, setStatus int, seen *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch queryAction(body) {
		case "ListQueueTags":
			_, _ = w.Write([]byte(`<ListQueueTagsResponse><ListQueueTagsResult>` +
				`<Tag><Key>groundhold-capability</Key><Value>` + sanitizeTag(cap) + `</Value></Tag>` +
				`<Tag><Key>groundhold-environment</Key><Value>` + sanitizeTag(env) + `</Value></Tag>` +
				`</ListQueueTagsResult></ListQueueTagsResponse>`))
		case "SetQueueAttributes":
			if seen != nil {
				*seen = string(body)
			}
			if setStatus != 0 {
				w.WriteHeader(setStatus)
				return
			}
			_, _ = w.Write([]byte(`<SetQueueAttributesResponse></SetQueueAttributesResponse>`))
		default:
			w.WriteHeader(404)
		}
	}))
}

func sqsRetentionAttrs() map[string]any {
	return map[string]any{
		"location.region":   "eu-central-1",
		"retention.minimum": "300s",
		"service.managed":   true,
	}
}

func TestUpdateSQSRetentionPatchesRetentionPeriod(t *testing.T) {
	var seen string
	srv := sqsUpdateServer(t, "orders", "prod", 0, &seen)
	defer srv.Close()
	d := sqsTestDriver(t, srv)
	res := d.updateSQS("orders", "prod", "sqs:eu-central-1:000000000000:orders-x",
		sqsRetentionAttrs(), nil, []string{"retention.minimum"})
	if res.Status != "succeeded" {
		t.Fatalf("retention update must succeed, got %+v", res)
	}
	if !strings.Contains(seen, "MessageRetentionPeriod") || !strings.Contains(seen, "300") {
		t.Errorf("SetQueueAttributes must carry MessageRetentionPeriod=300, body=%q", seen)
	}
}

// desired encryption OFF must explicitly clear the managed-SSE flag (never leave
// a stale mechanism behind).
func TestUpdateSQSEncryptionOffClearsSSE(t *testing.T) {
	var seen string
	srv := sqsUpdateServer(t, "orders", "prod", 0, &seen)
	defer srv.Close()
	d := sqsTestDriver(t, srv)
	attrs := map[string]any{
		"location.region":   "eu-central-1",
		"encryption.atRest": false,
		"service.managed":   true,
	}
	res := d.updateSQS("orders", "prod", "sqs:eu-central-1:000000000000:orders-x",
		attrs, nil, []string{"encryption.atRest"})
	if res.Status != "succeeded" {
		t.Fatalf("encryption-off update must succeed, got %+v", res)
	}
	if !strings.Contains(seen, "SqsManagedSseEnabled") {
		t.Errorf("encryption-off must set SqsManagedSseEnabled, body=%q", seen)
	}
}

func TestUpdateSQSForeignRefuses(t *testing.T) {
	srv := sqsUpdateServer(t, "someone-else", "prod", 0, nil)
	defer srv.Close()
	d := sqsTestDriver(t, srv)
	res := d.updateSQS("orders", "prod", "sqs:eu-central-1:000000000000:orders-x",
		sqsRetentionAttrs(), nil, []string{"retention.minimum"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a not-ours queue must be refused, got %+v", res)
	}
}

func TestUpdateSQSClientErrorIsFailed(t *testing.T) {
	srv := sqsUpdateServer(t, "orders", "prod", 400, nil)
	defer srv.Close()
	d := sqsTestDriver(t, srv)
	res := d.updateSQS("orders", "prod", "sqs:eu-central-1:000000000000:orders-x",
		sqsRetentionAttrs(), nil, []string{"retention.minimum"})
	if res.Status != "failed" {
		t.Fatalf("a 4xx patch must be failed (never silent success), got %+v", res)
	}
}

// ---- RDS Update ------------------------------------------------------------

func rdsUpdateServer(t *testing.T, cap, env string, modifyStatus int, seen *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = io.ReadFull(r.Body, body)
		switch queryAction(body) {
		case "DescribeDBInstances":
			_, _ = w.Write([]byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>` +
				`<DBInstanceIdentifier>db-x</DBInstanceIdentifier><DBInstanceStatus>available</DBInstanceStatus>` +
				`<Engine>postgres</Engine><EngineVersion>16.3</EngineVersion>` +
				`<StorageEncrypted>true</StorageEncrypted><PubliclyAccessible>false</PubliclyAccessible>` +
				`<MultiAZ>false</MultiAZ><DeletionProtection>false</DeletionProtection>` +
				`<TagList><Tag><Key>groundhold-capability</Key><Value>` + sanitizeTag(cap) + `</Value></Tag>` +
				`<Tag><Key>groundhold-environment</Key><Value>` + sanitizeTag(env) + `</Value></Tag></TagList>` +
				`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
		case "ModifyDBInstance":
			if seen != nil {
				*seen = string(body)
			}
			if modifyStatus != 0 {
				w.WriteHeader(modifyStatus)
				return
			}
			_, _ = w.Write([]byte(`<ModifyDBInstanceResponse></ModifyDBInstanceResponse>`))
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestUpdateRDSPublicExposurePatchesPubliclyAccessible(t *testing.T) {
	var seen string
	srv := rdsUpdateServer(t, "db", "prod", 0, &seen)
	defer srv.Close()
	d := rdsTestDriver(t, srv)
	attrs := rdsAttrs()
	attrs["network.publicExposure"] = true
	res := d.updateRDS("db", "prod", "rds:eu-central-1:db-x", attrs, rdsImpl(),
		[]string{"network.publicExposure"})
	if res.Status != "succeeded" {
		t.Fatalf("publicExposure update must succeed (accepted async), got %+v", res)
	}
	if !strings.Contains(seen, "PubliclyAccessible") || !strings.Contains(seen, "ApplyImmediately") {
		t.Errorf("ModifyDBInstance must carry PubliclyAccessible + ApplyImmediately, body=%q", seen)
	}
}

func TestUpdateRDSAvailabilityPatchesMultiAZ(t *testing.T) {
	var seen string
	srv := rdsUpdateServer(t, "db", "prod", 0, &seen)
	defer srv.Close()
	d := rdsTestDriver(t, srv)
	attrs := rdsAttrs()
	attrs["availability.class"] = "regional"
	res := d.updateRDS("db", "prod", "rds:eu-central-1:db-x", attrs, rdsImpl(),
		[]string{"availability.class"})
	if res.Status != "succeeded" || !strings.Contains(seen, "MultiAZ") {
		t.Fatalf("regional must set MultiAZ, got %+v body=%q", res, seen)
	}
}

func TestUpdateRDSForeignRefuses(t *testing.T) {
	srv := rdsUpdateServer(t, "someone-else", "prod", 0, nil)
	defer srv.Close()
	d := rdsTestDriver(t, srv)
	res := d.updateRDS("db", "prod", "rds:eu-central-1:db-x", rdsAttrs(), rdsImpl(),
		[]string{"network.publicExposure"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a not-ours instance must be refused, got %+v", res)
	}
}

func TestUpdateRDSServerErrorIsUnknownWithPid(t *testing.T) {
	srv := rdsUpdateServer(t, "db", "prod", 500, nil)
	defer srv.Close()
	d := rdsTestDriver(t, srv)
	res := d.updateRDS("db", "prod", "rds:eu-central-1:db-x", rdsAttrs(), rdsImpl(),
		[]string{"network.publicExposure"})
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a 5xx modify must be unknown WITH pid, got %+v", res)
	}
}
