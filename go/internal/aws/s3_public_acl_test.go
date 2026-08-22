package aws

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"groundhold/internal/provider"
)

// s3ExposureServer serves the reads publicExposure consults: HEAD (presence),
// policyStatus, acl, and publicAccessBlock. Each response is caller-supplied so a
// test can pose an exact policy/ACL/BPA combination. A status of 0 for a leg means
// "fail it" (an HTTP 403), to exercise the unreadable path.
func s3ExposureServer(t *testing.T, policyStatusBody, aclBody, pabBody string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" && r.URL.RawQuery == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		serve := func(body string) {
			if body == "" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("<Error><Code>AccessDenied</Code></Error>"))
				return
			}
			_, _ = w.Write([]byte(body))
		}
		switch r.URL.RawQuery {
		case "policyStatus":
			serve(policyStatusBody)
		case "acl":
			serve(aclBody)
		case "publicAccessBlock":
			serve(pabBody)
		default:
			w.WriteHeader(404)
		}
	}))
}

func exposureOf(obs []provider.Observation) (val any, present bool) {
	for _, o := range obs {
		if o.Path == "network.publicExposure" {
			return o.Value, true
		}
	}
	return nil, false
}

const (
	aclAllUsersRead = `<AccessControlPolicy><Owner><ID>o</ID></Owner><AccessControlList>` +
		`<Grant><Grantee><ID>o</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>` +
		`<Grant><Grantee xsi:type="Group"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee>` +
		`<Permission>READ</Permission></Grant>` +
		`</AccessControlList></AccessControlPolicy>`
	aclAuthUsersWrite = `<AccessControlPolicy><Owner><ID>o</ID></Owner><AccessControlList>` +
		`<Grant><Grantee xsi:type="Group"><URI>http://acs.amazonaws.com/groups/global/AuthenticatedUsers</URI></Grantee>` +
		`<Permission>WRITE</Permission></Grant>` +
		`</AccessControlList></AccessControlPolicy>`
	aclLogDeliveryOnly = `<AccessControlPolicy><Owner><ID>o</ID></Owner><AccessControlList>` +
		`<Grant><Grantee xsi:type="Group"><URI>http://acs.amazonaws.com/groups/s3/LogDelivery</URI></Grantee>` +
		`<Permission>WRITE</Permission></Grant>` +
		`</AccessControlList></AccessControlPolicy>`
	aclPrivateOnly = `<AccessControlPolicy><Owner><ID>o</ID></Owner><AccessControlList>` +
		`<Grant><Grantee><ID>o</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>` +
		`</AccessControlList></AccessControlPolicy>`
	psNotPublic = `<PolicyStatus><IsPublic>false</IsPublic></PolicyStatus>`
	psPublic    = `<PolicyStatus><IsPublic>true</IsPublic></PolicyStatus>`
	pabRestrict = `<PublicAccessBlockConfiguration><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`
)

// THE MUTANT-DEFECT TEST: a bucket public via ACL with NO public policy. The old
// observe read only GetBucketPolicyStatus and emitted publicExposure=false — a
// false-green over a publicly readable bucket. The ACL leg must make it true.
func TestPublicExposureAclPublicNoPolicy(t *testing.T) {
	srv := s3ExposureServer(t, psNotPublic, aclAllUsersRead, "")
	defer srv.Close()
	d := s3TestDriver(t, srv)
	obs, _, err := d.observeS3("assets", "s3:eu-central-1:pv-assets-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := exposureOf(obs); !ok || v != true {
		t.Fatalf("a public bucket ACL (AllUsers READ) with no policy must read publicExposure=true, got %v present=%v", v, ok)
	}
}

// AuthenticatedUsers = any AWS account holder = public. A WRITE grant to it is still
// public (AWS meaning-of-public; a public write is an exposure too).
func TestPublicExposureAuthenticatedUsersIsPublic(t *testing.T) {
	srv := s3ExposureServer(t, psNotPublic, aclAuthUsersWrite, "")
	defer srv.Close()
	d := s3TestDriver(t, srv)
	obs, _, err := d.observeS3("assets", "s3:eu-central-1:pv-assets-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := exposureOf(obs); !ok || v != true {
		t.Fatalf("AuthenticatedUsers WRITE must read publicExposure=true, got %v present=%v", v, ok)
	}
}

// LogDelivery is a service group, NOT public — an exact-URI match must not count it.
func TestPublicExposureLogDeliveryNotPublic(t *testing.T) {
	srv := s3ExposureServer(t, psNotPublic, aclLogDeliveryOnly, "")
	defer srv.Close()
	d := s3TestDriver(t, srv)
	obs, _, err := d.observeS3("assets", "s3:eu-central-1:pv-assets-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := exposureOf(obs); !ok || v != false {
		t.Fatalf("a LogDelivery-only ACL is not public — expected false, got %v present=%v", v, ok)
	}
}

// Unreadable ACL + non-public policy: a non-public verdict needs BOTH legs, so the
// observation is WITHHELD (never a fabricated false over an ACL we could not read).
func TestPublicExposureAclUnreadableWithholds(t *testing.T) {
	srv := s3ExposureServer(t, psNotPublic, "", "") // acl 403
	defer srv.Close()
	d := s3TestDriver(t, srv)
	obs, diags, err := d.observeS3("assets", "s3:eu-central-1:pv-assets-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := exposureOf(obs); ok {
		t.Fatalf("an unreadable ACL must WITHHOLD publicExposure, not emit %v", v)
	}
	if !hasDiag(diags, "withheld") {
		t.Fatalf("a withheld verdict must say why, diags=%v", diags)
	}
}

// A masked public policy (RestrictPublicBuckets enforced) must NOT short-circuit to
// false: if a public ACL is also present, the bucket is public. The old single
// branch emitted false here — a secondary false-green closed by the fall-through.
func TestPublicExposureMaskedPolicyStillPublicViaAcl(t *testing.T) {
	srv := s3ExposureServer(t, psPublic, aclAllUsersRead, pabRestrict)
	defer srv.Close()
	d := s3TestDriver(t, srv)
	obs, _, err := d.observeS3("assets", "s3:eu-central-1:pv-assets-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := exposureOf(obs); !ok || v != true {
		t.Fatalf("a masked public policy WITH a public ACL is still public=true, got %v present=%v", v, ok)
	}
}

// A masked public policy with a PRIVATE ACL settles to false (the masked policy is a
// latent exposure — surfaced as a diag — but the bucket is currently private).
func TestPublicExposureMaskedPolicyPrivateAcl(t *testing.T) {
	srv := s3ExposureServer(t, psPublic, aclPrivateOnly, pabRestrict)
	defer srv.Close()
	d := s3TestDriver(t, srv)
	obs, diags, err := d.observeS3("assets", "s3:eu-central-1:pv-assets-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := exposureOf(obs); !ok || v != false {
		t.Fatalf("masked policy + private ACL settles to false, got %v present=%v", v, ok)
	}
	if !hasDiag(diags, "masked") {
		t.Fatalf("the masked public policy must be surfaced as a latent-exposure diag, diags=%v", diags)
	}
}
