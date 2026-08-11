package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// encryption.customerManagedKeys (Slice A): S3 default SSE-KMS with a customer
// key (PUT /?encryption) and RDS KmsKeyId on CreateDBInstance. S3 observe is
// reliable (aws:kms + a key id); RDS observe is NOT (DescribeDBInstances cannot
// tell a customer key from the account-default aws/rds key), so it emits a
// diagnostic, never a false measured value.

func TestBuildS3CustomerManagedKeys(t *testing.T) {
	a := s3Attrs()
	a["encryption.customerManagedKeys"] = true
	impl := map[string]any{"kms_key_id": "arn:aws:kms:eu-central-1:000000000000:key/abc-123"}
	plan, err := BuildS3Requests("000000000000", "prod", "assets", a, impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Encryption == nil {
		t.Fatal("customerManagedKeys must emit a default-encryption PUT")
	}
	if plan.Encryption.Path != "/?encryption" {
		t.Fatalf("encryption path = %q", plan.Encryption.Path)
	}
	for _, want := range []string{"<SSEAlgorithm>aws:kms</SSEAlgorithm>",
		"<KMSMasterKeyID>arn:aws:kms:eu-central-1:000000000000:key/abc-123</KMSMasterKeyID>"} {
		if !strings.Contains(plan.Encryption.Body, want) {
			t.Fatalf("encryption body missing %q: %s", want, plan.Encryption.Body)
		}
	}
}

func TestBuildS3CustomerManagedKeysRequiresKeyID(t *testing.T) {
	a := s3Attrs()
	a["encryption.customerManagedKeys"] = true
	if _, err := BuildS3Requests("000000000000", "prod", "assets", a, nil, 1); err == nil {
		t.Fatal("customerManagedKeys=true without implementation.kms_key_id must be refused")
	}
}

func TestBuildS3CustomerManagedKeysFalseIsNoop(t *testing.T) {
	a := s3Attrs()
	a["encryption.customerManagedKeys"] = false
	plan, err := BuildS3Requests("000000000000", "prod", "assets", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Encryption != nil {
		t.Fatal("customerManagedKeys=false is the provider default — no encryption PUT")
	}
}

func TestObserveS3CustomerManagedKeys(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "HEAD" && r.URL.RawQuery == "" { // HeadBucket (D520)
				w.WriteHeader(http.StatusOK)
				return
			}
			switch r.URL.RawQuery {
			case "versioning":
				_, _ = w.Write([]byte(`<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>`))
			case "encryption":
				_, _ = w.Write([]byte(`<ServerSideEncryptionConfiguration><Rule>` +
					`<ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm>` +
					`<KMSMasterKeyID>arn:aws:kms:eu-central-1:000000000000:key/abc-123</KMSMasterKeyID>` +
					`</ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`))
			case "policyStatus":
				w.WriteHeader(404)
				_, _ = w.Write([]byte("<Error><Code>NoSuchBucketPolicy</Code></Error>"))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := s3TestDriver(t, srv)
	obs, _, err := d.observeS3("assets", "s3:eu-central-1:pv-assets-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	got := false
	for _, o := range obs {
		if o.Path == "encryption.customerManagedKeys" {
			got, _ = o.Value.(bool)
		}
	}
	if !got {
		t.Fatal("aws:kms + a customer key id must observe customerManagedKeys=true")
	}
}

func TestObserveS3SSES3IsNotCustomerManaged(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.RawQuery {
			case "versioning":
				_, _ = w.Write([]byte(`<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>`))
			case "encryption":
				// SSE-S3 (AES256) is NOT a CMEK, and aws:kms with no key is the aws/s3 default.
				_, _ = w.Write([]byte(`<ServerSideEncryptionConfiguration><Rule>` +
					`<ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm>` +
					`</ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`))
			case "policyStatus":
				w.WriteHeader(404)
				_, _ = w.Write([]byte("<Error><Code>NoSuchBucketPolicy</Code></Error>"))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := s3TestDriver(t, srv)
	obs, _, err := d.observeS3("assets", "s3:eu-central-1:pv-assets-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "encryption.customerManagedKeys" {
			t.Fatalf("SSE-S3 must NOT observe customerManagedKeys, got %v", o.Value)
		}
	}
}

func TestBuildRDSCustomerManagedKeys(t *testing.T) {
	a := rdsAttrs()
	a["encryption.customerManagedKeys"] = true
	impl := rdsImpl()
	impl["kms_key_id"] = "arn:aws:kms:eu-central-1:000000000000:key/abc-123"
	_, body, err := BuildRDSCreate("000000000000", "prod", "db", a, impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "KmsKeyId=arn") || !strings.Contains(body, "StorageEncrypted=true") {
		t.Fatalf("RDS CMEK must set KmsKeyId with StorageEncrypted: %s", body)
	}
}

func TestBuildRDSCustomerManagedKeysRequiresKeyID(t *testing.T) {
	a := rdsAttrs()
	a["encryption.customerManagedKeys"] = true
	if _, _, err := BuildRDSCreate("000000000000", "prod", "db", a, rdsImpl(), 1); err == nil {
		t.Fatal("customerManagedKeys=true without implementation.kms_key_id must be refused")
	}
}

// RDS observe emits a DIAGNOSTIC (not a measured value): an encrypted instance
// always reports a KmsKeyId ARN, so presence cannot prove a customer key.
func TestObserveRDSCustomerManagedKeysIsDiagnosticOnly(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>` +
				`<DBInstanceIdentifier>db-x</DBInstanceIdentifier><DBInstanceStatus>available</DBInstanceStatus>` +
				`<Engine>postgres</Engine><EngineVersion>16.3</EngineVersion>` +
				`<StorageEncrypted>true</StorageEncrypted><PubliclyAccessible>false</PubliclyAccessible>` +
				`<MultiAZ>false</MultiAZ><DeletionProtection>false</DeletionProtection>` +
				`<KmsKeyId>arn:aws:kms:eu-central-1:000000000000:key/abc-123</KmsKeyId>` +
				`<TagList><Tag><Key>groundhold-capability</Key><Value>db</Value></Tag>` +
				`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag></TagList>` +
				`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
		}))
	defer srv.Close()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	d := NewDriver("eu-central-1")
	d.RDSBaseURL = srv.URL
	d.Account = "000000000000"
	d.PollInterval = time.Millisecond
	obs, diags, err := d.observeRDS("db", "rds:eu-central-1:db-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "encryption.customerManagedKeys" {
			t.Fatalf("RDS must NOT emit a measured customerManagedKeys value, got %v", o.Value)
		}
	}
	found := false
	for _, dg := range diags {
		if strings.Contains(dg, "customerManagedKeys") {
			found = true
		}
	}
	if !found {
		t.Fatalf("RDS with a KmsKeyId must emit a customerManagedKeys diagnostic, got %v", diags)
	}
}
