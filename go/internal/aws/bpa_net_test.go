package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D240: observeS3 must fold the EFFECTIVE Block Public Access into publicExposure.
// A public bucket policy (GetBucketPolicyStatus IsPublic=true) under an effective
// RestrictPublicBuckets=true is effectively private; an unreadable BPA keeps the
// conservative public verdict (never a fabricated private).

const rpbXML = `<PublicAccessBlockConfiguration><RestrictPublicBuckets>%s</RestrictPublicBuckets></PublicAccessBlockConfiguration>`
const noBlockErr = `<Error><Code>NoSuchPublicAccessBlockConfiguration</Code></Error>`

// bpaServer routes the three reads observeS3's publicExposure path makes.
// bucketBPA / accountBPA are one of: "true", "false" (RPB value in a 200),
// "notset" (404 NoSuchPublicAccessBlockConfiguration), "err" (403), "err500"
// (500), or "omit" (200 with no RestrictPublicBuckets element). isPublic drives
// GetBucketPolicyStatus. accountHits counts s3-control calls.
func bpaServer(t *testing.T, isPublic bool, bucketBPA, accountBPA string, accountHits *int) *httptest.Server {
	t.Helper()
	rpb := func(w http.ResponseWriter, kind string) {
		switch kind {
		case "true", "false":
			_, _ = w.Write([]byte(strings.Replace(rpbXML, "%s", kind, 1)))
		case "omit":
			_, _ = w.Write([]byte(`<PublicAccessBlockConfiguration></PublicAccessBlockConfiguration>`))
		case "notset":
			w.WriteHeader(404)
			_, _ = w.Write([]byte(noBlockErr))
		case "err":
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code></Error>`))
		case "err500":
			w.WriteHeader(500)
		}
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		p := r.URL.Path
		switch {
		// HeadBucket: real S3 answers it, and observe now asks before reporting
		// anything about a bucket (D520 — it used to describe a DELETED bucket as
		// a healthy one). A fixture that 404s every unmodelled request would make
		// the bucket read as gone.
		case r.Method == "HEAD" && q == "":
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(p, "/v20180820/configuration/publicAccessBlock"):
			if accountHits != nil {
				*accountHits++
			}
			rpb(w, accountBPA)
		case q == "publicAccessBlock":
			rpb(w, bucketBPA)
		case q == "policyStatus":
			v := "false"
			if isPublic {
				v = "true"
			}
			_, _ = w.Write([]byte("<PolicyStatus><IsPublic>" + v + "</IsPublic></PolicyStatus>"))
		case q == "acl":
			// these fixtures exercise the POLICY+BPA legs; the ACL leg reads a
			// private (owner-only) ACL so the OR-combine turns on the policy verdict.
			_, _ = w.Write([]byte(s3PrivateACL))
		default:
			// every other observe read (versioning, object-lock, lifecycle,
			// encryption, replication, tagging, buckets.get): benign not-found so
			// observe completes; we only assert publicExposure here.
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`<Error><Code>NoSuch</Code></Error>`))
		}
	}))
}

func bpaDriver(t *testing.T, srv *httptest.Server) *Driver {
	d := s3TestDriver(t, srv)
	d.S3ControlBaseURL = srv.URL // hermetic: account BPA hits the test server, not real AWS
	return d
}

func observeExposure(t *testing.T, d *Driver) (val any, present bool, diags []string) {
	t.Helper()
	obs, dg, err := d.observeS3("assets", "s3:eu-central-1:pv-assets-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "network.publicExposure" {
			return o.Value, true, dg
		}
	}
	return nil, false, dg
}

func hasDiag(diags []string, sub string) bool {
	for _, d := range diags {
		if strings.Contains(d, sub) {
			return true
		}
	}
	return false
}

func TestBPABucketRestrictedDowngrades(t *testing.T) {
	// (a) bucket RPB=true -> false, and the RPB RESOLUTION short-circuits without an
	// account call. D1229 note: this used to assert zero account hits across the whole
	// observe. It no longer can, because a downgraded verdict IS a measured false and
	// the residual caveat then reads the account's IgnorePublicAcls (once per run).
	// The short-circuit itself is unchanged and is asserted directly below, on the
	// function that owns it, rather than inferred from a whole-observe call count —
	// which is the sharper test anyway: it cannot be satisfied by an unrelated caller
	// happening not to run.
	hits := 0
	srv := bpaServer(t, true, "true", "true", &hits)
	defer srv.Close()
	d := bpaDriver(t, srv)
	val, present, diags := observeExposure(t, d)
	if !present || val != false {
		t.Fatalf("bucket RestrictPublicBuckets=true must downgrade to false, got present=%v val=%v", present, val)
	}
	if !hasDiag(diags, "masked") {
		t.Errorf("a downgrade must warn the policy is masked, got %v", diags)
	}

	// the short-circuit, asserted on effectiveRestrictPublicBuckets itself
	hits = 0
	d2 := bpaDriver(t, srv)
	restricted, err := d2.effectiveRestrictPublicBuckets("eu-central-1", "pv-assets-abcd1234")
	if err != nil || !restricted {
		t.Fatalf("bucket RPB=true must resolve restricted, got %v err=%v", restricted, err)
	}
	if hits != 0 {
		t.Errorf("bucket-level true must short-circuit — account endpoint hit %d times", hits)
	}
}

func TestBPAAccountRestrictedDowngrades(t *testing.T) {
	// (b) bucket not-set + account RPB=true -> false.
	srv := bpaServer(t, true, "notset", "true", nil)
	defer srv.Close()
	val, present, _ := observeExposure(t, bpaDriver(t, srv))
	if !present || val != false {
		t.Fatalf("account RestrictPublicBuckets=true must downgrade to false, got present=%v val=%v", present, val)
	}
}

func TestBPABothNotSetStaysPublic(t *testing.T) {
	// (c) both not-set (definitive readable false) -> public=true, no unreadable diag.
	srv := bpaServer(t, true, "notset", "notset", nil)
	defer srv.Close()
	val, present, diags := observeExposure(t, bpaDriver(t, srv))
	if !present || val != true {
		t.Fatalf("both BPA not-set must keep public=true, got present=%v val=%v", present, val)
	}
	if hasDiag(diags, "RestrictPublicBuckets") {
		t.Errorf("a definitive not-set must NOT emit a RestrictPublicBuckets-unreadable diag, got %v", diags)
	}
}

func TestBPAOmittedElementIsFalse(t *testing.T) {
	// (g) 200 with no RestrictPublicBuckets element = false; account not-set -> public=true.
	srv := bpaServer(t, true, "omit", "notset", nil)
	defer srv.Close()
	val, present, _ := observeExposure(t, bpaDriver(t, srv))
	if !present || val != true {
		t.Fatalf("omitted RestrictPublicBuckets = false; must stay public=true, got present=%v val=%v", present, val)
	}
}

func TestBPAUnreadableStaysConservativePublic(t *testing.T) {
	// (d) bucket 403 + account 403, and (e) bucket false + account 500: no positive
	// evidence and a needed read unreadable -> conservative public=true + diag.
	for _, tc := range []struct{ name, bucket, account string }{
		{"bucket-403", "err", "err"},
		{"bucket-false-account-500", "false", "err500"},
	} {
		srv := bpaServer(t, true, tc.bucket, tc.account, nil)
		val, present, diags := observeExposure(t, bpaDriver(t, srv))
		srv.Close()
		if !present || val != true {
			t.Errorf("%s: unreadable BPA must keep conservative public=true, got present=%v val=%v", tc.name, present, val)
		}
		// the diagnostic must name the BPA read AND why it gave no answer (D296:
		// a diagnosis, not the bare word "unreadable").
		if !hasDiag(diags, "RestrictPublicBuckets") || !hasDiag(diags, "gave no answer") {
			t.Errorf("%s: want a BPA-gave-no-answer diagnostic, got %v", tc.name, diags)
		}
	}
}

func TestBPANotQueriedWhenPolicyPrivate(t *testing.T) {
	// (f) IsPublic=false -> publicExposure=false.
	//
	// D1229 NARROWED this invariant, deliberately, and the narrowing is the point of
	// the entry: the RestrictPublicBuckets resolution is still lazy — it fires only
	// when the policy already reads public, asserted directly below — but the residual
	// caveat on a measured FALSE now reads IgnorePublicAcls, which is a different flag
	// answering a different question on the opposite branch. What bounds its cost is
	// that the ACCOUNT read is memoized for the run (one request, not one per bucket);
	// s3_residual_gate_test.go holds that, and holds that account-level enforcement
	// skips the per-bucket read entirely.
	hits := 0
	srv := bpaServer(t, false, "true", "true", &hits)
	defer srv.Close()
	val, present, _ := observeExposure(t, bpaDriver(t, srv))
	if !present || val != false {
		t.Fatalf("a non-public policy must be publicExposure=false, got present=%v val=%v", present, val)
	}
	if hits > 1 {
		t.Errorf("at most ONE account read per run is permitted on the private-policy path "+
			"(D1229's memoized IgnorePublicAcls); got %d", hits)
	}
}

// The half of D240's laziness D1229 did NOT touch: RestrictPublicBuckets is resolved
// only when the policy reads public.
//
// This is asserted on the LEG that owns the decision, not on a whole-observe request
// count — because both flags come from the SAME endpoint, so counting hits there
// cannot tell an RPB resolution from D1229's IgnorePublicAcls read. A gate that
// cannot distinguish its two cases is not a gate; this one runs the private and the
// public policy through the same code and requires opposite answers.
func TestRestrictPublicBucketsResolvedOnlyForAPublicPolicy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		isPublic bool
		wantPAB  int
	}{
		{"private policy resolves no RPB", false, 0},
		{"public policy resolves RPB", true, 1},
	} {
		pabHits := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.RawQuery {
			case "publicAccessBlock":
				pabHits++
				w.WriteHeader(403)
				_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code></Error>`))
			case "policyStatus":
				v := "false"
				if tc.isPublic {
					v = "true"
				}
				_, _ = w.Write([]byte("<PolicyStatus><IsPublic>" + v + "</IsPublic></PolicyStatus>"))
			default:
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`<Error><Code>NoSuch</Code></Error>`))
			}
		}))
		d := s3TestDriver(t, srv)
		d.S3ControlBaseURL = srv.URL
		_, _, _ = d.s3PolicyExposureLeg("eu-central-1", "pv-assets-abcd1234")
		srv.Close()
		if pabHits != tc.wantPAB {
			t.Errorf("%s: want %d PublicAccessBlock reads, got %d", tc.name, tc.wantPAB, pabHits)
		}
	}
}
