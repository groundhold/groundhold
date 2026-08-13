package gcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// encryption.customerManagedKeys (Slice A): Cloud SQL
// settings.diskEncryptionConfiguration.kmsKeyName and GCS
// encryption.defaultKmsKeyName, both create-time fields on the SAME insert.
// Both clouds observe reliably (a kmsKeyName is present iff a CMEK is set;
// absent means the Google-managed default, which does not satisfy the constraint).

func TestBuildCloudSQLCustomerManagedKeys(t *testing.T) {
	a := map[string]any{
		"engine.protocol":                "postgresql/16",
		"location.region":                "europe-west1",
		"encryption.customerManagedKeys": true,
	}
	im := map[string]any{"tier": "db-custom-1-3840",
		"kms_key_name": "projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k"}
	req, err := BuildCreateRequest("acme-prod", "prod", "db", a, im, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := req.Body["settings"].(map[string]any)
	dek, ok := s["diskEncryptionConfiguration"].(map[string]any)
	if !ok {
		t.Fatalf("no diskEncryptionConfiguration: %+v", s)
	}
	if dek["kmsKeyName"] != "projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k" {
		t.Fatalf("kmsKeyName = %v", dek["kmsKeyName"])
	}
}

func TestBuildCloudSQLCustomerManagedKeysRequiresKeyName(t *testing.T) {
	a := map[string]any{
		"engine.protocol":                "postgresql/16",
		"location.region":                "europe-west1",
		"encryption.customerManagedKeys": true,
	}
	if _, err := BuildCreateRequest("p", "e", "db", a, map[string]any{"tier": "t"}, 1); err == nil {
		t.Fatal("customerManagedKeys=true without implementation.kms_key_name must be refused")
	}
}

func TestBuildGCSCustomerManagedKeys(t *testing.T) {
	a := gcsAttrs()
	a["encryption.customerManagedKeys"] = true
	im := map[string]any{"kms_key_name": "projects/p/locations/eu/keyRings/r/cryptoKeys/k"}
	req, err := BuildGCSCreateRequest("acme-prod", "prod", "assets", a, im, 1)
	if err != nil {
		t.Fatal(err)
	}
	enc, ok := req.Body["encryption"].(map[string]any)
	if !ok {
		t.Fatalf("no encryption in body: %+v", req.Body)
	}
	if enc["defaultKmsKeyName"] != "projects/p/locations/eu/keyRings/r/cryptoKeys/k" {
		t.Fatalf("defaultKmsKeyName = %v", enc["defaultKmsKeyName"])
	}
}

func TestBuildGCSCustomerManagedKeysRequiresKeyName(t *testing.T) {
	a := gcsAttrs()
	a["encryption.customerManagedKeys"] = true
	if _, err := BuildGCSCreateRequest("p", "e", "assets", a, nil, 1); err == nil {
		t.Fatal("customerManagedKeys=true without implementation.kms_key_name must be refused")
	}
}

func TestObserveCloudSQLCustomerManagedKeys(t *testing.T) {
	inst := map[string]any{
		"databaseVersion": "POSTGRES_16",
		"region":          "europe-west1",
		"settings": map[string]any{
			"diskEncryptionConfiguration": map[string]any{
				"kmsKeyName": "projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k",
			},
		},
	}
	out, _ := MapInstance(inst)
	got := false
	for _, o := range out {
		if o.Path == "encryption.customerManagedKeys" {
			got, _ = o.Value.(bool)
		}
	}
	if !got {
		t.Fatal("diskEncryptionConfiguration.kmsKeyName must observe customerManagedKeys=true")
	}
}

// D1040: a Google-managed-key (default) instance reads a MEASURED
// customerManagedKeys=false, not an omitted observation — omitting it let a
// `customerManagedKeys: true` candidate be adopted over it (was
// TestObserveCloudSQLNoCMEKEmitsNothing, which asserted the omit bug).
func TestObserveCloudSQLDefaultKeyIsMeasuredFalse(t *testing.T) {
	inst := map[string]any{
		"databaseVersion": "POSTGRES_16",
		"region":          "europe-west1",
		"settings":        map[string]any{},
	}
	out, _ := MapInstance(inst)
	found := false
	for _, o := range out {
		if o.Path == "encryption.customerManagedKeys" {
			found = true
			if o.Value != false {
				t.Fatalf("a default-key instance must observe customerManagedKeys=false, got %v", o.Value)
			}
		}
	}
	if !found {
		t.Fatal("customerManagedKeys must be emitted (measured false), not omitted")
	}
}

func TestObserveGCSCustomerManagedKeys(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"location":"EUROPE-CENTRAL2","labels":{"groundhold-capability":"assets"},` +
				`"iamConfiguration":{"publicAccessPrevention":"enforced","uniformBucketLevelAccess":{"enabled":true}},` +
				`"encryption":{"defaultKmsKeyName":"projects/p/locations/eu/keyRings/r/cryptoKeys/k"}}`))
		}))
	defer srv.Close()
	d := NewDriver("acme-prod")
	d.GcsBaseURL = srv.URL
	d.ProjNumber = "111"
	obs, _, err := d.observeGCS("assets", "gcs:acme-prod:pv-assets-abcd1234")
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
		t.Fatal("defaultKmsKeyName must observe customerManagedKeys=true")
	}
}
