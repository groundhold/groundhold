package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file extends gcs_net_test.go / gcs_update_test.go / gcs_effpap_test.go,
// which pin the happy paths + the D238 effective-PAP rescue. These tests pin
// the remaining branches: the pure helpers normalizePAP/sameDualRegion,
// ourProjectNumber's CRM resolution + caching + error paths, createGCS's
// 409-conflict sub-branches (dual-region/location/PAP mismatch, foreign,
// unreadable-follow-up), the D237 transient routing on setBucketPublic, and
// updateGCS/deleteGCS/lockGcsRetention's remaining error branches.

// --- pure helpers -------------------------------------------------------

func TestNormalizePAP(t *testing.T) {
	cases := map[string]string{
		"":            "inherited",
		"unspecified": "inherited",
		"enforced":    "enforced",
		"inherited":   "inherited",
	}
	for in, want := range cases {
		if got := normalizePAP(in); got != want {
			t.Errorf("normalizePAP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSameDualRegion(t *testing.T) {
	cases := []struct {
		locs          []string
		primary, dest string
		want          bool
	}{
		{[]string{"EUROPE-WEST1", "EUROPE-NORTH1"}, "europe-west1", "europe-north1", true},
		{[]string{"EUROPE-WEST1", "EUROPE-NORTH1"}, "europe-north1", "europe-west1", true}, // order-independent
		{[]string{"EUROPE-WEST1", "EUROPE-NORTH1"}, "europe-west1", "asia-east1", false},
		{[]string{"EUROPE-WEST1"}, "europe-west1", "europe-north1", false}, // wrong cardinality
		{nil, "", "", false},
		{[]string{"a", "b"}, "", "b", false}, // empty primary refuses a match
	}
	for _, c := range cases {
		if got := sameDualRegion(c.locs, c.primary, c.dest); got != c.want {
			t.Errorf("sameDualRegion(%v, %q, %q) = %v, want %v", c.locs, c.primary, c.dest, got, c.want)
		}
	}
}

// --- ourProjectNumber (CRM resolution) -----------------------------------

func gcsDriverNoProjNumber(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.CRMBaseURL = srv.URL
	return d
}

func TestOurProjectNumberResolvesAndCaches(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"projectNumber":"555"}`))
	}))
	defer srv.Close()
	d := gcsDriverNoProjNumber(t, srv)
	n, err := d.ourProjectNumber()
	if err != nil || n != "555" {
		t.Fatalf("ourProjectNumber = %q, %v", n, err)
	}
	if _, err := d.ourProjectNumber(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("the resolved project number must be CACHED, got %d CRM calls", calls)
	}
}

func TestOurProjectNumberErrorBranches(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := gcsDriverNoProjNumber(t, srv)
		srv.Close()
		if _, err := d.ourProjectNumber(); err == nil {
			t.Fatal("expected a transport error")
		}
	})
	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		d := gcsDriverNoProjNumber(t, srv)
		if _, err := d.ourProjectNumber(); err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("expected an HTTP 403 error, got %v", err)
		}
	})
	t.Run("empty projectNumber", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{}`))
		}))
		defer srv.Close()
		d := gcsDriverNoProjNumber(t, srv)
		if _, err := d.ourProjectNumber(); err == nil || !strings.Contains(err.Error(), "returned none") {
			t.Fatalf("expected 'returned none', got %v", err)
		}
	})
}

// --- createGCS 409-conflict sub-branches ----------------------------------

// gcsConflictServer always 409s the POST /b create; the bucket GET reflects
// bucketStatus/bucketJSON so each sub-branch of the conflict ladder can be
// exercised independently.
func gcsConflictServer(t *testing.T, bucketStatus int, bucketJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/b"):
			w.WriteHeader(http.StatusConflict)
		case r.Method == "GET":
			if bucketStatus != 0 && bucketStatus != 200 {
				w.WriteHeader(bucketStatus)
				return
			}
			_, _ = w.Write([]byte(bucketJSON))
		default:
			w.WriteHeader(500)
		}
	}))
}

func TestGCSCreateConflictReadUnreadable(t *testing.T) {
	srv := gcsConflictServer(t, http.StatusInternalServerError, "")
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.createGCS("assets", "prod", gcsAttrs(), nil, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("an unreadable follow-up must be unknown, got %+v", res)
	}
}

func TestGCSCreateConflictGoneOnFollowup(t *testing.T) {
	srv := gcsConflictServer(t, http.StatusNotFound, "")
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.createGCS("assets", "prod", gcsAttrs(), nil, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gone on the follow-up read") {
		t.Fatalf("a vanished conflicting bucket must be unknown, got %+v", res)
	}
}

func TestGCSCreateConflictNotOurs(t *testing.T) {
	bucket := `{"projectNumber":"111","labels":{"groundhold-capability":"other","groundhold-environment":"prod"}}`
	srv := gcsConflictServer(t, 200, bucket)
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.createGCS("assets", "prod", gcsAttrs(), nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign-labeled conflict must be failed, got %+v", res)
	}
}

func TestGCSCreateConflictForeignProjectNumber(t *testing.T) {
	bucket := `{"projectNumber":"999","labels":{"groundhold-capability":"assets","groundhold-environment":"prod"}}`
	srv := gcsConflictServer(t, 200, bucket)
	defer srv.Close()
	d := gcsDriver(t, srv) // ProjNumber "111"
	res := d.createGCS("assets", "prod", gcsAttrs(), nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "cross-project") {
		t.Fatalf("a foreign-project-number conflict must be failed, got %+v", res)
	}
}

func TestGCSCreateConflictDualRegionMismatch(t *testing.T) {
	bucket := `{"projectNumber":"111","labels":{"groundhold-capability":"assets","groundhold-environment":"prod"},` +
		`"customPlacementConfig":{"dataLocations":["EUROPE-WEST1","EUROPE-NORTH1"]}}`
	srv := gcsConflictServer(t, 200, bucket)
	defer srv.Close()
	d := gcsDriver(t, srv)
	attrs := gcsAttrs()
	attrs["replication.enabled"] = true
	// same continent (EU) as location.region so the BUILDER accepts the pair;
	// it differs from the LIVE dataLocations pair, so this is a live mismatch.
	attrs["replication.destinationRegion"] = "europe-west4"
	res := d.createGCS("assets", "prod", attrs, nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "dual-region placement") {
		t.Fatalf("a dual-region mismatch must be failed, got %+v", res)
	}
}

func TestGCSCreateConflictLocationMismatch(t *testing.T) {
	bucket := `{"projectNumber":"111","labels":{"groundhold-capability":"assets","groundhold-environment":"prod"},` +
		`"location":"US-EAST1"}`
	srv := gcsConflictServer(t, 200, bucket)
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.createGCS("assets", "prod", gcsAttrs(), nil, 1) // wants europe-central2
	if res.Status != "failed" || !strings.Contains(res.Reason, "does not match desired") {
		t.Fatalf("a location mismatch must be failed, got %+v", res)
	}
}

func TestGCSCreateConflictPAPMismatch(t *testing.T) {
	bucket := `{"projectNumber":"111","labels":{"groundhold-capability":"assets","groundhold-environment":"prod"},` +
		`"location":"EUROPE-CENTRAL2","iamConfiguration":{"publicAccessPrevention":"inherited"}}`
	srv := gcsConflictServer(t, 200, bucket)
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.createGCS("assets", "prod", gcsAttrs(), nil, 1) // wants enforced (private)
	if res.Status != "failed" || !strings.Contains(res.Reason, "public-access-prevention") {
		t.Fatalf("a PAP mismatch must be failed, got %+v", res)
	}
}

func TestGCSCreateConflictIdempotentMatch(t *testing.T) {
	bucket := `{"projectNumber":"111","labels":{"groundhold-capability":"assets","groundhold-environment":"prod"},` +
		`"location":"EUROPE-CENTRAL2","iamConfiguration":{"publicAccessPrevention":"enforced"}}`
	srv := gcsConflictServer(t, 200, bucket)
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.createGCS("assets", "prod", gcsAttrs(), nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("a matching conflict (idempotent adopt) must succeed, got %+v", res)
	}
}

// --- createGCS transport / 5xx / empty-body branches ----------------------

func TestGCSCreateTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d := gcsDriver(t, srv)
	srv.Close()
	res := d.createGCS("assets", "prod", gcsAttrs(), nil, 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a transport error must be unknown WITH the deterministic pid, got %+v", res)
	}
}

func TestGCSCreate5xxIsUnknownWithPID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.createGCS("assets", "prod", gcsAttrs(), nil, 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a 503 must be unknown WITH the deterministic pid, got %+v", res)
	}
}

func TestGCSCreateEmptyBodyIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`)) // 200 but no bucket name echoed
	}))
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.createGCS("assets", "prod", gcsAttrs(), nil, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "carried no bucket") {
		t.Fatalf("an empty create response must be unknown, got %+v", res)
	}
}

// --- setBucketPublic D237 transient routing --------------------------------

func TestGCSSetBucketPublicTransientIsUnknown(t *testing.T) {
	srv := gcsServer(t, "", 429, `{"error":{"message":"rate limited"}}`, 0)
	defer srv.Close()
	d := gcsDriver(t, srv)
	attrs := gcsAttrs()
	attrs["network.publicExposure"] = true
	res := d.createGCS("assets", "prod", attrs, nil, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "transient/denied") {
		t.Fatalf("a 429 on setIamPolicy must be unknown, got %+v", res)
	}
}

func TestGCSSetBucketPublic5xxIsUnknown(t *testing.T) {
	srv := gcsServer(t, "", 500, `{"error":{"message":"boom"}}`, 0)
	defer srv.Close()
	d := gcsDriver(t, srv)
	attrs := gcsAttrs()
	attrs["network.publicExposure"] = true
	res := d.createGCS("assets", "prod", attrs, nil, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "server error") {
		t.Fatalf("a 500 on setIamPolicy must be unknown, got %+v", res)
	}
}

func TestGCSSetBucketPublicTerminalDenied(t *testing.T) {
	// a clean 400 (not DRS, not a recognized transient/denied code) is a terminal
	// failed — the honest boundary of the D237 widening.
	srv := gcsServer(t, "", 400, `{"error":{"message":"malformed policy"}}`, 0)
	defer srv.Close()
	d := gcsDriver(t, srv)
	attrs := gcsAttrs()
	attrs["network.publicExposure"] = true
	res := d.createGCS("assets", "prod", attrs, nil, 1)
	if res.Status != "failed" {
		t.Fatalf("a clean 400 must be a terminal failed, got %+v", res)
	}
}

// --- gcsGetBucket read error branches ---------------------------------------

func TestGcsGetBucketErrorBranches(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := gcsDriver(t, srv)
		srv.Close()
		if _, _, _, err := d.gcsGetBucket("x", "assets", "prod"); err == nil {
			t.Fatal("expected a transport error")
		}
	})
	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		d := gcsDriver(t, srv)
		if _, _, _, err := d.gcsGetBucket("x", "assets", "prod"); err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("expected an HTTP 403 error, got %v", err)
		}
	})
	t.Run("unparseable body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()
		d := gcsDriver(t, srv)
		if _, _, _, err := d.gcsGetBucket("x", "assets", "prod"); err == nil {
			t.Fatal("expected a body-parse error")
		}
	})
	t.Run("404 is a clean absence, not an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		d := gcsDriver(t, srv)
		_, _, found, err := d.gcsGetBucket("x", "assets", "prod")
		if err != nil || found {
			t.Fatalf("a 404 must be found=false, err=nil, got found=%v err=%v", found, err)
		}
	})
}

// --- lockGcsRetention branches ------------------------------------------

func TestLockGcsRetentionBranches(t *testing.T) {
	t.Run("pre-lock read transport error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := gcsDriver(t, srv)
		srv.Close()
		unknown, err := d.lockGcsRetention("x")
		if err == nil || !unknown {
			t.Fatalf("a lost pre-lock read must be unknown, got unknown=%v err=%v", unknown, err)
		}
	})
	t.Run("pre-lock read non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		d := gcsDriver(t, srv)
		unknown, err := d.lockGcsRetention("x")
		if err == nil || unknown {
			t.Fatalf("a non-200 pre-lock read must be a definitive failure, got unknown=%v err=%v", unknown, err)
		}
	})
	t.Run("no retention policy to lock", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"metageneration":"1"}`))
		}))
		defer srv.Close()
		d := gcsDriver(t, srv)
		_, err := d.lockGcsRetention("x")
		if err == nil || !strings.Contains(err.Error(), "no retention policy") {
			t.Fatalf("expected a no-retention-policy refusal, got %v", err)
		}
	})
	t.Run("already locked is idempotent", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"metageneration":"1","retentionPolicy":{"retentionPeriod":"600","isLocked":true}}`))
		}))
		defer srv.Close()
		d := gcsDriver(t, srv)
		unknown, err := d.lockGcsRetention("x")
		if err != nil || unknown {
			t.Fatalf("an already-locked bucket must be a no-op success, got unknown=%v err=%v", unknown, err)
		}
	})
	t.Run("no metageneration refuses a CAS-less lock", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"retentionPolicy":{"retentionPeriod":"600"}}`))
		}))
		defer srv.Close()
		d := gcsDriver(t, srv)
		_, err := d.lockGcsRetention("x")
		if err == nil || !strings.Contains(err.Error(), "no metageneration") {
			t.Fatalf("expected a no-metageneration refusal, got %v", err)
		}
	})
	t.Run("lock 5xx is unknown", func(t *testing.T) {
		n := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n++
			if n == 1 {
				_, _ = w.Write([]byte(`{"metageneration":"1","retentionPolicy":{"retentionPeriod":"600"}}`))
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		d := gcsDriver(t, srv)
		unknown, err := d.lockGcsRetention("x")
		if err == nil || !unknown {
			t.Fatalf("a 5xx on the lock call must be unknown, got unknown=%v err=%v", unknown, err)
		}
	})
	t.Run("lock returns 200 but isLocked not confirmed", func(t *testing.T) {
		n := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n++
			if n == 1 {
				_, _ = w.Write([]byte(`{"metageneration":"1","retentionPolicy":{"retentionPeriod":"600"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"retentionPolicy":{"isLocked":false}}`)) // did not take
		}))
		defer srv.Close()
		d := gcsDriver(t, srv)
		unknown, err := d.lockGcsRetention("x")
		if err == nil || !unknown || !strings.Contains(err.Error(), "not confirmed") {
			t.Fatalf("an unconfirmed lock must be unknown, got unknown=%v err=%v", unknown, err)
		}
	})
}

// --- deleteGCS error branches ----------------------------------------------

func TestGCSDeleteTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d := gcsDriver(t, srv)
	srv.Close()
	res := d.deleteGCS("assets", "prod", "gcs:acme-prod:the-bucket")
	if res.Status != "unknown" {
		t.Fatalf("a lost pre-delete read must be unknown, got %+v", res)
	}
}

func TestGCSDeletePreDeleteReadNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.deleteGCS("assets", "prod", "gcs:acme-prod:the-bucket")
	if res.Status != "failed" {
		t.Fatalf("a definitive non-200 pre-delete read must be failed, got %+v", res)
	}
}

func TestGCSDeleteUnparseableBodyRefusesAmbiguously(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.deleteGCS("assets", "prod", "gcs:acme-prod:the-bucket")
	if res.Status != "unknown" || !strings.Contains(res.Reason, "ambiguous") {
		t.Fatalf("an unparseable pre-delete read must refuse ambiguously, got %+v", res)
	}
}

func TestGCSDeleteNoMetagenerationRefuses(t *testing.T) {
	bucket := `{"projectNumber":"111","labels":{"groundhold-capability":"assets","groundhold-environment":"prod"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(bucket))
	}))
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.deleteGCS("assets", "prod", "gcs:acme-prod:the-bucket")
	if res.Status != "unknown" || !strings.Contains(res.Reason, "no metageneration") {
		t.Fatalf("a missing metageneration must refuse the CAS-less delete, got %+v", res)
	}
}

func TestGCSDeleteOutcomeUnknownAfterMetagenerationRead(t *testing.T) {
	bucket := `{"metageneration":"1","projectNumber":"111","labels":{"groundhold-capability":"assets","groundhold-environment":"prod"}}`
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 { // pre-delete read
			_, _ = w.Write([]byte(bucket))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable) // the DELETE itself
	}))
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.deleteGCS("assets", "prod", "gcs:acme-prod:the-bucket")
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a 5xx on the delete call must be unknown WITH the pid, got %+v", res)
	}
}

// --- updateGCS error branches ------------------------------------------

func TestUpdateGCSUnsupportedPathRefuses(t *testing.T) {
	var patched string
	srv := gcsUpdateServer(t, "assets", &patched)
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.Update("gcs", "assets", "prod", "gcs:acme-prod:pv-assets-abcd1234",
		map[string]any{"location.region": "us"}, nil, []string{"location.region"}, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not patchable in place") {
		t.Fatalf("an unsupported path must refuse, got %+v", res)
	}
}

func TestUpdateGCSNotFoundRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.Update("gcs", "assets", "prod", "gcs:acme-prod:pv-assets-abcd1234",
		map[string]any{"versioning.enabled": true}, nil, []string{"versioning.enabled"}, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "no longer exists") {
		t.Fatalf("a vanished bucket must refuse the update, got %+v", res)
	}
}

func TestUpdateGCSCrossProjectRefused(t *testing.T) {
	d := gcsDriverNoProjNumber(t, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	res := d.Update("gcs", "assets", "prod", "gcs:other-proj:the-bucket",
		map[string]any{"versioning.enabled": true}, nil, []string{"versioning.enabled"}, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "cross-project") {
		t.Fatalf("a cross-project pid must refuse before any read, got %+v", res)
	}
}

func TestUpdateGCSPreconditionFailedRefuses(t *testing.T) {
	doc := `{"name":"pv-assets-abcd1234","metageneration":"7","projectNumber":"111",` +
		`"labels":{"groundhold-capability":"assets","groundhold-environment":"prod"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PATCH":
			w.WriteHeader(http.StatusPreconditionFailed)
		case "GET":
			_, _ = w.Write([]byte(doc))
		}
	}))
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.Update("gcs", "assets", "prod", "gcs:acme-prod:pv-assets-abcd1234",
		map[string]any{"versioning.enabled": true}, nil, []string{"versioning.enabled"}, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "metageneration conflict") {
		t.Fatalf("a 412 on patch must refuse with a conflict reason, got %+v", res)
	}
}

func TestUpdateGCSPatch5xxIsUnknown(t *testing.T) {
	doc := `{"name":"pv-assets-abcd1234","metageneration":"7","projectNumber":"111",` +
		`"labels":{"groundhold-capability":"assets","groundhold-environment":"prod"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PATCH":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "GET":
			_, _ = w.Write([]byte(doc))
		}
	}))
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.Update("gcs", "assets", "prod", "gcs:acme-prod:pv-assets-abcd1234",
		map[string]any{"versioning.enabled": true}, nil, []string{"versioning.enabled"}, "k")
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a 503 on patch must be unknown WITH the pid, got %+v", res)
	}
}

func TestUpdateGCSPreUpdateReadTransportErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d := gcsDriver(t, srv)
	srv.Close()
	res := d.Update("gcs", "assets", "prod", "gcs:acme-prod:pv-assets-abcd1234",
		map[string]any{"versioning.enabled": true}, nil, []string{"versioning.enabled"}, "k")
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("a lost pre-update read must be unknown, got %+v", res)
	}
}
