package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// D1226. The vault observe used to append, unconditionally, the diagnostic
// "encryption.customerManagedKeys not observed: Backup and DR vaults use
// Google-managed encryption" — and then withhold the attribute.
//
// Two things were wrong with that. The claim is contradicted by the provider's own
// published API: `BackupVault.encryptionConfig.kmsKeyName` is documented as "The
// Cloud KMS key name to encrypt backups in this backup vault", so the service does
// support customer-managed keys. And the sentence explained a silence with a fact
// nothing in the function measured — the D1225 shape, found by sweeping for it.
//
// It also contradicted ITSELF: a withheld attribute makes a hard constraint
// `unknown`, which blocks, while the prose beside it asserted the answer was known.
// A tool that says "I know this" and returns "I cannot say" has one of the two wrong.

// bkdrServerWithEncryption serves a vault GET carrying (or omitting) an
// encryptionConfig, so BOTH directions of the read are exercised. The shared
// bkdrServer omits it entirely, which is the fixture blind spot that let the
// unconditional diagnostic look correct.
func bkdrServerWithEncryption(t *testing.T, kmsKeyName string) *httptest.Server {
	t.Helper()
	enc := ""
	if kmsKeyName != "" {
		enc = `,"encryptionConfig":{"kmsKeyName":"` + kmsKeyName + `"}`
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"archive",` +
					`"groundhold-environment":"prod"},` +
					`"backupMinimumEnforcedRetentionDuration":"7776000s"` + enc + `}`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func bkdrObserve(t *testing.T, kmsKeyName string) (map[string]any, []string) {
	t.Helper()
	srv := bkdrServerWithEncryption(t, kmsKeyName)
	defer srv.Close()
	d := NewDriver("acme-prod")
	d.BackupDRBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	obs, diags, err := d.observeBackupDR("archive",
		"gbkv:acme-prod:europe-west1:archive-prod-2bcec2b5")
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	return got, diags
}

// A vault WITH a customer key must say so — the reassuring direction, resting on the
// provider's own field rather than on this driver's opinion of the service.
func TestBackupVaultWithAKMSKeyReportsCustomerManagedKeys(t *testing.T) {
	got, _ := bkdrObserve(t,
		"projects/acme-prod/locations/europe-west1/keyRings/r/cryptoKeys/k")
	if got["encryption.customerManagedKeys"] != true {
		t.Fatalf("a vault whose encryptionConfig names a KMS key uses CMEK, got %v",
			got["encryption.customerManagedKeys"])
	}
}

// A vault WITHOUT one must say that too, rather than withholding: the optional field
// being unset is a measurement, and it is the alarming direction.
func TestBackupVaultWithoutAKMSKeyReportsNoCustomerManagedKeys(t *testing.T) {
	got, diags := bkdrObserve(t, "")
	v, present := got["encryption.customerManagedKeys"]
	if !present {
		t.Fatalf("encryption.customerManagedKeys must be observed, not withheld: %v", diags)
	}
	if v != false {
		t.Fatalf("an unset encryptionConfig is no customer key, got %v", v)
	}
}

// The property that outlives any wording: nothing may tell the operator this service
// has no customer-managed encryption, because the provider's API says it does.
func TestBackupVaultNeverClaimsTheServiceLacksCMEK(t *testing.T) {
	for _, key := range []string{"", "projects/p/locations/l/keyRings/r/cryptoKeys/k"} {
		_, diags := bkdrObserve(t, key)
		for _, d := range diags {
			if strings.Contains(d, "encryption.customerManagedKeys not observed") {
				t.Fatalf("customerManagedKeys is readable from encryptionConfig — "+
					"it must not be reported as unobservable: %q", d)
			}
		}
	}
}
