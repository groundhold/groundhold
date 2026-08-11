package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D469: the object-storage compliance hold, refused before the delete — parity with the
// GCS twin, which has read retentionPolicy.isLocked since it was written.

func s3LockServer(t *testing.T, lockBody string, lockStatus int, deleted *bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "tagging"):
			_, _ = w.Write([]byte(`<Tagging><TagSet>` +
				`<Tag><Key>groundhold-capability</Key><Value>assets</Value></Tag>` +
				`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
				`</TagSet></Tagging>`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "object-lock"):
			w.WriteHeader(lockStatus)
			_, _ = w.Write([]byte(lockBody))
		case r.Method == http.MethodDelete:
			*deleted = true
			w.WriteHeader(204)
		default:
			w.WriteHeader(200)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func s3LockDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.S3BaseURL = srv.URL
	d.Account = "000000000000"
	return d
}

func TestDeleteS3RefusesComplianceHold(t *testing.T) {
	var deleted bool
	srv := s3LockServer(t, `<ObjectLockConfiguration><ObjectLockEnabled>Enabled`+
		`</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode>`+
		`<Days>365</Days></DefaultRetention></Rule></ObjectLockConfiguration>`, 200, &deleted)
	d := s3LockDriver(t, srv)
	res := d.Delete("s3", "assets", "prod", "s3:eu-central-1:pv-assets-abcd1234", "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "compliance hold") {
		t.Fatalf("a COMPLIANCE-mode bucket must be refused up front, got %+v", res)
	}
	if deleted {
		t.Fatal("the DELETE was issued against a bucket under a WORM hold")
	}
}

// GOVERNANCE is bypassable by design and observe reverse-maps it to locked=false.
// Refusing on it would claim a hold that is not there.
func TestDeleteS3AllowsGovernanceMode(t *testing.T) {
	var deleted bool
	srv := s3LockServer(t, `<ObjectLockConfiguration><ObjectLockEnabled>Enabled`+
		`</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode>`+
		`<Days>7</Days></DefaultRetention></Rule></ObjectLockConfiguration>`, 200, &deleted)
	d := s3LockDriver(t, srv)
	if res := d.Delete("s3", "assets", "prod", "s3:eu-central-1:pv-assets-abcd1234", "k"); res.Status != "succeeded" {
		t.Fatalf("GOVERNANCE mode is not a hold: %+v", res)
	}
	if !deleted {
		t.Fatal("the delete never reached the API")
	}
}

func TestDeleteS3AmbiguousLockReadIsUnknown(t *testing.T) {
	var deleted bool
	srv := s3LockServer(t, `<ObjectLock`, 200, &deleted) // truncated body
	d := s3LockDriver(t, srv)
	res := d.Delete("s3", "assets", "prod", "s3:eu-central-1:pv-assets-abcd1234", "k")
	if res.Status != "unknown" {
		t.Fatalf("an unparseable lock read must be unknown, not a delete: %+v", res)
	}
	if deleted {
		t.Fatal("deleted on an ambiguous read — a zero value is not 'not locked'")
	}
}

// A bucket that is not object-lock-enabled at all must delete normally.
func TestDeleteS3NoObjectLockDeletes(t *testing.T) {
	var deleted bool
	srv := s3LockServer(t, `<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>`,
		404, &deleted)
	d := s3LockDriver(t, srv)
	if res := d.Delete("s3", "assets", "prod", "s3:eu-central-1:pv-assets-abcd1234", "k"); res.Status != "succeeded" {
		t.Fatalf("a bucket with no Object Lock must delete: %+v", res)
	}
	if !deleted {
		t.Fatal("the delete never reached the API")
	}
}
