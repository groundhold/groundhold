package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D1229. The caveat riding a measured `network.publicExposure=false` now READS the
// effective IgnorePublicAcls and names which residual is open for THIS bucket.
//
// D1227 had reworded the caveat to stop PRESCRIBING that flag on a path that never
// read it (nine of ten real buckets already had it enforced and were told to enable
// it), and deferred the read itself as too costly. Two independent reviews corrected
// the premise: both required permissions ship inside AWS's own ReadOnlyAccess and
// SecurityAudit, and reading the ACCOUNT level once per run bounds a hardened estate
// to a single request. So the prescription is allowed again — but only in the branch
// that MEASURED the flag off. That is the invariant these gates hold.

const pabBothXML = `<PublicAccessBlockConfiguration>` +
	`<RestrictPublicBuckets>%R</RestrictPublicBuckets>` +
	`<IgnorePublicAcls>%I</IgnorePublicAcls>` +
	`</PublicAccessBlockConfiguration>`

type pabCounts struct{ account, bucket int }

// ipaServer serves a private policy + private ACL (so publicExposure measures false)
// and answers the two PublicAccessBlock endpoints independently. "skip" means the
// endpoint answers NoSuchPublicAccessBlockConfiguration (a definitive not-set),
// "deny" a 403 (unreadable).
func ipaServer(t *testing.T, accountIPA, bucketIPA string, n *pabCounts) *httptest.Server {
	t.Helper()
	write := func(w http.ResponseWriter, kind string) {
		switch kind {
		case "true", "false":
			body := strings.ReplaceAll(pabBothXML, "%I", kind)
			_, _ = w.Write([]byte(strings.ReplaceAll(body, "%R", "false")))
		case "skip":
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`<Error><Code>NoSuchPublicAccessBlockConfiguration</Code></Error>`))
		case "deny":
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code></Error>`))
		}
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, p := r.URL.RawQuery, r.URL.Path
		switch {
		case r.Method == "HEAD" && q == "":
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(p, "/v20180820/configuration/publicAccessBlock"):
			n.account++
			write(w, accountIPA)
		case q == "publicAccessBlock":
			n.bucket++
			write(w, bucketIPA)
		case q == "policyStatus":
			_, _ = w.Write([]byte(`<PolicyStatus><IsPublic>false</IsPublic></PolicyStatus>`))
		case q == "acl":
			_, _ = w.Write([]byte(s3PrivateACL))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`<Error><Code>NoSuch</Code></Error>`))
		}
	}))
}

func ipaObserve(t *testing.T, accountIPA, bucketIPA string) (string, *pabCounts) {
	t.Helper()
	n := &pabCounts{}
	srv := ipaServer(t, accountIPA, bucketIPA, n)
	defer srv.Close()
	d := bpaDriver(t, srv)
	val, present, diags := observeExposure(t, d)
	if !present || val != false {
		t.Fatalf("fixture must measure publicExposure=false, got present=%v val=%v", present, val)
	}
	for _, dg := range diags {
		if strings.HasPrefix(dg, "network.publicExposure=false covers") {
			return dg, n
		}
	}
	t.Fatalf("no residual caveat among %v", diags)
	return "", n
}

// Account-level enforcement closes the residual for every bucket — AND must not cost
// a per-bucket request. This is the tiering that makes the read affordable at estate
// scale; without it the answer would be one request per bucket.
func TestAccountIgnorePublicAclsClosesResidualWithoutAPerBucketCall(t *testing.T) {
	c, n := ipaObserve(t, "true", "deny")
	if !strings.Contains(c, "CLOSED") {
		t.Fatalf("account-level IgnorePublicAcls closes the object-ACL residual: %q", c)
	}
	if n.bucket != 0 {
		t.Fatalf("account-level enforcement must short-circuit the per-bucket read, "+
			"got %d bucket PAB calls", n.bucket)
	}
}

// The account answer is memoized for the run: a second bucket must not re-ask.
func TestAccountIgnorePublicAclsIsReadOncePerRun(t *testing.T) {
	n := &pabCounts{}
	srv := ipaServer(t, "true", "deny", n)
	defer srv.Close()
	d := bpaDriver(t, srv)
	for _, pid := range []string{
		"s3:eu-central-1:pv-assets-abcd1234",
		"s3:eu-central-1:pv-assets-abcd1234",
	} {
		if _, _, err := d.observeS3("assets", pid); err != nil {
			t.Fatal(err)
		}
	}
	if n.account != 1 {
		t.Fatalf("the account PublicAccessBlock must be read ONCE per run, got %d", n.account)
	}
}

// Bucket-level enforcement, with the account not enforcing, also closes it.
func TestBucketIgnorePublicAclsClosesResidual(t *testing.T) {
	c, n := ipaObserve(t, "false", "true")
	if !strings.Contains(c, "CLOSED") {
		t.Fatalf("bucket-level IgnorePublicAcls closes the object-ACL residual: %q", c)
	}
	if n.bucket == 0 {
		t.Fatalf("the bucket read must happen when the account does not enforce")
	}
}

// Neither enforces: the residual is OPEN, and NOW the caveat may say so and prescribe
// the fix — because it measured it. This is what D1227 forbade on an unread flag.
func TestUnenforcedIgnorePublicAclsIsNamedAsTheOpenResidual(t *testing.T) {
	c, _ := ipaObserve(t, "skip", "skip")
	if !strings.Contains(c, "NOT enforced") {
		t.Fatalf("a measured-off flag must be named as the open residual: %q", c)
	}
	if strings.Contains(c, "CLOSED") {
		t.Fatalf("nothing may read as closed when the flag is off: %q", c)
	}
}

// Unreadable must never read as closed — the reassuring half needs positive evidence.
func TestUnreadableIgnorePublicAclsTreatsTheResidualAsOpen(t *testing.T) {
	c, _ := ipaObserve(t, "deny", "deny")
	if strings.Contains(c, "CLOSED") {
		t.Fatalf("an unreadable flag must not close the residual: %q", c)
	}
	if !strings.Contains(c, "could not be ruled out") || !strings.Contains(c, "OPEN") {
		t.Fatalf("an unreadable flag must be named as such and treated as open: %q", c)
	}
}

// D1227's caveat asserted both residuals were "not enumerable at bucket scope". That
// is false for access points — ListAccessPoints takes a bucket filter, confirmed
// against the live API — and this pins the correction so it cannot creep back.
func TestAccessPointResidualIsNotDescribedAsUnenumerable(t *testing.T) {
	for _, tc := range [][2]string{{"true", "deny"}, {"skip", "skip"}, {"deny", "deny"}} {
		c, _ := ipaObserve(t, tc[0], tc[1])
		if strings.Contains(c, "not enumerable") {
			t.Fatalf("access points ARE enumerable per bucket (ListAccessPoints --bucket); "+
				"the honest claim is that they are not READ here: %q", c)
		}
		if !strings.Contains(c, "Access Point") {
			t.Fatalf("the access-point residual must still be disclosed: %q", c)
		}
	}
}
