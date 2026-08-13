package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// s3Server routes path-style S3 sub-resource calls (the driver uses path-style
// when S3BaseURL is set). It asserts the SHA-256 body checksum is present on body PUTs
// (x-amz-checksum-sha256, field-verified live) and tracks tag state so a create sequence and an
// ownership check see consistent tags.
func s3Server(t *testing.T, createStatus int, createErrCode string) *httptest.Server {
	t.Helper()
	tagged := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "HEAD" && r.URL.RawQuery == "" { // HeadBucket (D520)
				w.WriteHeader(http.StatusOK)
				return
			}
			q := r.URL.RawQuery
			switch {
			case r.Method == "PUT" && q == "":
				// create bucket
				if createStatus != 0 && createStatus != 200 {
					w.WriteHeader(createStatus)
					_, _ = w.Write([]byte("<Error><Code>" + createErrCode + "</Code></Error>"))
					return
				}
				w.WriteHeader(200)
			case r.Method == "PUT" && q == "tagging":
				if r.Header.Get("X-Amz-Checksum-Sha256") == "" {
					t.Errorf("PutBucketTagging must carry x-amz-checksum-sha256")
				}
				tagged = true
				w.WriteHeader(200)
			case r.Method == "PUT": // public-access-block, versioning, policy
				if r.Body != nil && r.Header.Get("X-Amz-Checksum-Sha256") == "" {
					t.Errorf("body PUT %q must carry x-amz-checksum-sha256", q)
				}
				w.WriteHeader(200)
			case r.Method == "GET" && q == "tagging":
				if tagged {
					_, _ = w.Write([]byte(`<Tagging><TagSet>` +
						`<Tag><Key>groundhold-capability</Key><Value>assets</Value></Tag>` +
						`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
						`</TagSet></Tagging>`))
				} else {
					w.WriteHeader(404)
					_, _ = w.Write([]byte("<Error><Code>NoSuchTagSet</Code></Error>"))
				}
			case r.Method == "GET" && q == "versioning":
				_, _ = w.Write([]byte(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`))
			case r.Method == "GET" && q == "replication":
				w.WriteHeader(404)
				_, _ = w.Write([]byte("<Error><Code>ReplicationConfigurationNotFoundError</Code></Error>"))
			case r.Method == "GET" && q == "policyStatus":
				w.WriteHeader(404)
				_, _ = w.Write([]byte("<Error><Code>NoSuchBucketPolicy</Code></Error>"))
			case r.Method == "DELETE":
				w.WriteHeader(204)
			default:
				w.WriteHeader(404)
			}
		}))
}

func s3TestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.S3BaseURL = srv.URL
	d.Account = "000000000000" // avoid the STS resolve in tests
	return d
}

func TestCreateS3HappyPath(t *testing.T) {
	srv := s3Server(t, 200, "")
	defer srv.Close()
	d := s3TestDriver(t, srv)
	res := d.createS3("000000000000", "prod", "assets", s3Attrs(), nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "s3:eu-central-1:") {
		t.Fatalf("got %+v, want succeeded + s3-prefixed id", res)
	}
}

// A create that fails at tagging keeps the pid (bucket exists) and is failed,
// never succeeded (D29 partial honesty).
func TestCreateS3TaggingFailKeepsPid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "HEAD" && r.URL.RawQuery == "" { // HeadBucket (D520)
				w.WriteHeader(http.StatusOK)
				return
			}
			switch {
			case r.Method == "PUT" && r.URL.RawQuery == "":
				w.WriteHeader(200) // bucket created
			case r.Method == "PUT" && r.URL.RawQuery == "tagging":
				w.WriteHeader(400)
				_, _ = w.Write([]byte("<Error><Code>InvalidRequest</Code></Error>"))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := s3TestDriver(t, srv)
	res := d.createS3("000000000000", "prod", "assets", s3Attrs(), nil, 1)
	if res.Status != "failed" || res.ProviderID == "" {
		t.Fatalf("a tagging failure must be failed WITH a pid, got %+v", res)
	}
}

// BucketAlreadyExists (a foreign account, global namespace) is refused (D82).
func TestCreateS3ForeignAccountRefused(t *testing.T) {
	srv := s3Server(t, http.StatusConflict, "BucketAlreadyExists")
	defer srv.Close()
	d := s3TestDriver(t, srv)
	res := d.createS3("000000000000", "prod", "assets", s3Attrs(), nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "cross-account") {
		t.Fatalf("a foreign-account bucket must be refused, got %+v", res)
	}
}

// BucketAlreadyOwnedByYou + no groundhold tag = an untagged leftover -> resume.
// An untagged same-account bucket is NOT provably ours. Both adversarial review
// passes flagged auto-adopting it as a silent-takeover hole, so a name conflict on
// an UNTAGGED bucket must surface as unknown (carrying the pid for reconcile), not
// succeed. Only a tags-match bucket resumes to success (covered live).
func TestCreateS3UntaggedLeftoverRefusesToAdopt(t *testing.T) {
	srv := s3Server(t, http.StatusConflict, "BucketAlreadyOwnedByYou")
	defer srv.Close()
	d := s3TestDriver(t, srv)
	res := d.createS3("000000000000", "prod", "assets", s3Attrs(), nil, 1)
	if res.Status != "unknown" {
		t.Fatalf("an untagged same-account leftover must NOT be silently adopted (unknown), got %+v", res)
	}
	if res.ProviderID == "" {
		t.Fatalf("unknown must still carry the deterministic pid for reconcile, got %+v", res)
	}
}

func TestObserveS3(t *testing.T) {
	srv := s3Server(t, 200, "")
	defer srv.Close()
	d := s3TestDriver(t, srv)
	obs, _, err := d.observeS3("assets", "s3:eu-central-1:pv-assets-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eu-central-1" {
		t.Fatalf("region = %v", got["location.region"])
	}
	if got["versioning.enabled"] != true {
		t.Fatalf("versioning = %v", got["versioning.enabled"])
	}
	if got["network.publicExposure"] != false {
		t.Fatalf("no policy => not public, got %v", got["network.publicExposure"])
	}
}

// A create WITH CRR issues the replication step and succeeds (four-valued: the
// step is applied through s3Step, so a failure would keep the pid).
func TestCreateS3ReplicationHappyPath(t *testing.T) {
	srv := s3Server(t, 200, "")
	defer srv.Close()
	d := s3TestDriver(t, srv)
	a := s3Attrs()
	a["replication.enabled"] = true
	res := d.createS3("000000000000", "prod", "assets", a, map[string]any{
		"replication_destination_bucket_arn": "arn:aws:s3:::pv-assets-replica-abcd1234",
		"replication_role_arn":               "arn:aws:iam::000000000000:role/groundhold-crr",
	}, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create with CRR must succeed, got %+v", res)
	}
}

// observe MEASURES the destination region via GetBucketLocation on the replica
// named by the rule's ARN — never from an operand (residency measured).
func TestObserveS3Replication(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "HEAD" && r.URL.RawQuery == "" { // HeadBucket (D520)
				w.WriteHeader(http.StatusOK)
				return
			}
			switch r.URL.RawQuery {
			case "replication":
				_, _ = w.Write([]byte(`<ReplicationConfiguration>` +
					`<Role>arn:aws:iam::000000000000:role/groundhold-crr</Role>` +
					`<Rule><Status>Enabled</Status>` +
					`<Destination><Bucket>arn:aws:s3:::pv-replica-eu-abcd1234</Bucket></Destination>` +
					`</Rule></ReplicationConfiguration>`))
			case "location":
				_, _ = w.Write([]byte(`<LocationConstraint>eu-west-3</LocationConstraint>`))
			case "versioning":
				_, _ = w.Write([]byte(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`))
			case "policyStatus":
				w.WriteHeader(404)
				_, _ = w.Write([]byte("<Error><Code>NoSuchBucketPolicy</Code></Error>"))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := s3TestDriver(t, srv)
	obs, diags, err := d.observeS3("assets", "s3:eu-central-1:pv-assets-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["replication.enabled"] != true {
		t.Fatalf("replication.enabled = %v", got["replication.enabled"])
	}
	if got["replication.destinationRegion"] != "eu-west-3" {
		t.Fatalf("destinationRegion must be MEASURED via GetBucketLocation, got %v (diags %v)",
			got["replication.destinationRegion"], diags)
	}
}

// No replication config => replication.enabled observed as a measured false.
func TestObserveS3ReplicationDisabled(t *testing.T) {
	srv := s3Server(t, 200, "")
	defer srv.Close()
	d := s3TestDriver(t, srv)
	obs, _, err := d.observeS3("assets", "s3:eu-central-1:pv-assets-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "replication.enabled" {
			if o.Value != false {
				t.Fatalf("no config => replication.enabled false, got %v", o.Value)
			}
			return
		}
	}
	t.Fatal("replication.enabled must be observed (measured false) when no config")
}

// A create WITH Object Lock issues the object-lock config step (after versioning)
// and succeeds; the create call carries the object-lock-enable header.
func TestCreateS3ObjectLockHappyPath(t *testing.T) {
	gotLockHeader := false
	gotLockPut := false
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "HEAD" && r.URL.RawQuery == "" { // HeadBucket (D520)
				w.WriteHeader(http.StatusOK)
				return
			}
			q := r.URL.RawQuery
			switch {
			case r.Method == "PUT" && q == "":
				if r.Header.Get("X-Amz-Bucket-Object-Lock-Enabled") == "true" {
					gotLockHeader = true
				}
				w.WriteHeader(200)
			case r.Method == "PUT" && q == "object-lock":
				if r.Header.Get("X-Amz-Checksum-Sha256") == "" {
					t.Errorf("PutObjectLockConfiguration must carry x-amz-checksum-sha256")
				}
				gotLockPut = true
				w.WriteHeader(200)
			case r.Method == "PUT":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := s3TestDriver(t, srv)
	a := s3Attrs()
	a["retention.minimum"] = "3650d"
	a["retention.locked"] = true
	res := d.createS3("000000000000", "prod", "vault", a, nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create with object lock must succeed, got %+v", res)
	}
	if !gotLockHeader {
		t.Fatal("CreateBucket must carry x-amz-bucket-object-lock-enabled: true")
	}
	if !gotLockPut {
		t.Fatal("create must issue PutObjectLockConfiguration")
	}
}

// observe reverse-maps GetObjectLockConfiguration: COMPLIANCE => retention.locked
// true, Days => retention.minimum as a duration.
func TestObserveS3ObjectLock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "HEAD" && r.URL.RawQuery == "" { // HeadBucket (D520)
				w.WriteHeader(http.StatusOK)
				return
			}
			switch r.URL.RawQuery {
			case "object-lock":
				_, _ = w.Write([]byte(`<ObjectLockConfiguration>` +
					`<ObjectLockEnabled>Enabled</ObjectLockEnabled>` +
					`<Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>3650</Days></DefaultRetention></Rule>` +
					`</ObjectLockConfiguration>`))
			case "versioning":
				_, _ = w.Write([]byte(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`))
			case "replication":
				w.WriteHeader(404)
				_, _ = w.Write([]byte("<Error><Code>ReplicationConfigurationNotFoundError</Code></Error>"))
			case "policyStatus":
				w.WriteHeader(404)
				_, _ = w.Write([]byte("<Error><Code>NoSuchBucketPolicy</Code></Error>"))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := s3TestDriver(t, srv)
	obs, diags, err := d.observeS3("vault", "s3:eu-central-1:pv-vault-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["retention.locked"] != true {
		t.Fatalf("COMPLIANCE => retention.locked true, got %v (diags %v)", got["retention.locked"], diags)
	}
	if got["retention.minimum"] != "3650d" {
		t.Fatalf("retention.minimum = %v, want 3650d (diags %v)", got["retention.minimum"], diags)
	}
}

// classifyS3Change: enabling WORM is a create-time foundation. D824 split the FLOOR out of
// that case — PutObjectLockConfiguration re-PUTs the DefaultRetention on an object-locked
// bucket, so pinning "immutable" here pinned destroying a bucket and every object in it to
// lengthen a retention period AWS raises in place.
func TestClassifyS3ObjectLockImmutable(t *testing.T) {
	if kind, reason := classifyS3Change("retention.locked", nil, nil); kind != "immutable" {
		t.Fatalf("retention.locked: want immutable, got %q (%s)", kind, reason)
	}
	if kind, reason := classifyS3Change("retention.minimum", nil, nil); kind != "unsupported" || reason == "" {
		t.Fatalf("retention.minimum: want unsupported with a reason, got %q (%s)", kind, reason)
	}
}

func TestDeleteS3Ours(t *testing.T) {
	srv := s3Server(t, 200, "")
	defer srv.Close()
	d := s3TestDriver(t, srv)
	// server must report our tags for the ownership pre-read
	d.s3Do("PUT", "eu-central-1", "pv-assets-abcd1234", "/?tagging", s3Tag("assets", "prod"))
	res := d.deleteS3("assets", "prod", "s3:eu-central-1:pv-assets-abcd1234")
	if res.Status != "succeeded" {
		t.Fatalf("delete of an owned bucket must succeed, got %+v", res)
	}
}

func TestSplitS3ProviderID(t *testing.T) {
	if _, _, err := splitS3ProviderID("s3:eu-central-1:pv-assets-abcd1234"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	for _, bad := range []string{"eu:b", "gcs:eu-central-1:b", "s3:eu-central-1:B", "s3:badregion:b"} {
		if _, _, err := splitS3ProviderID(bad); err == nil {
			t.Errorf("accepted malformed s3 id %q", bad)
		}
	}
}

// s3ExistingOursServer: the bucket already exists in OUR account and already carries our
// ownership tags — the case the comment above records as "covered live". Live coverage
// ended when the pilot paused (2026-07-24), so it is covered here now.
func s3ExistingOursServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "HEAD" && r.URL.RawQuery == "" { // HeadBucket (D520)
				w.WriteHeader(http.StatusOK)
				return
			}
			q := r.URL.RawQuery
			switch {
			case r.Method == "PUT" && q == "":
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte("<Error><Code>BucketAlreadyOwnedByYou</Code></Error>"))
			case r.Method == "GET" && q == "tagging":
				_, _ = w.Write([]byte(`<Tagging><TagSet>` +
					`<Tag><Key>groundhold-capability</Key><Value>assets</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
					`</TagSet></Tagging>`))
			case r.Method == "GET" && q == "versioning":
				_, _ = w.Write([]byte(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`))
			case r.Method == "GET" && q == "replication":
				w.WriteHeader(404)
				_, _ = w.Write([]byte("<Error><Code>ReplicationConfigurationNotFoundError</Code></Error>"))
			case r.Method == "GET" && q == "policyStatus":
				w.WriteHeader(404)
				_, _ = w.Write([]byte("<Error><Code>NoSuchBucketPolicy</Code></Error>"))
			case r.Method == "PUT":
				// configuration writes onto a bucket we already own (tags, PAB,
				// versioning) — convergence onto an adopted bucket, not a duplicate.
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func s3Role(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingS3 enrols S3 in the D391 gate. S3 adopts reactively: the PUT is
// answered BucketAlreadyOwnedByYou, and only a TAGS-MATCH bucket may resume to success
// (an untagged one is not provably ours — both adversarial reviews called auto-adopting
// it a silent-takeover hole). The bucket is name-addressed, so the load-bearing proof
// here is the pid, and the mutation allowance covers the configuration writes that
// converge an adopted bucket rather than creating anything.
func TestAdoptsExistingS3(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:           "aws/s3",
		Classify:       s3Role,
		ExistingServer: func() *httptest.Server { return s3ExistingOursServer(t) },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.S3BaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("s3", "assets", "prod", s3Attrs(), nil, "assets", 1)
		},
		AllowedMutations: 8, // the refused PUT + convergence writes onto the adopted bucket
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// TestRefusesForeignDeleteS3 enrols s3 in the D439 gate. An untagged bucket is NOT
// provably ours (D82) and a bucket delete takes its contents; the existing review test
// asserts the refusal, this asserts it as a class and counts the wire.
func TestRefusesForeignDeleteS3(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ForeignProbe{
		Name:     "aws/s3",
		Classify: s3Role,
		ForeignServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet && r.URL.RawQuery == "tagging" {
						_, _ = w.Write([]byte(`<Tagging><TagSet>` +
							`<Tag><Key>groundhold-capability</Key><Value>someone-else</Value></Tag>` +
							`</TagSet></Tagging>`))
						return
					}
					w.WriteHeader(200)
				}))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.S3BaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			return d
		},
		Delete: func(pr provider.Provider) provider.CreateResult {
			return pr.Delete("s3", "assets", "prod", "s3:eu-central-1:pv-assets-abcd1234", "k")
		},
	}
	certifynet.CertifyDeleteRefusesForeign(t, p)
}
