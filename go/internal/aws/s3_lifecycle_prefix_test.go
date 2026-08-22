package aws

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func lifePrefixAttrs(prefix ...any) map[string]any {
	a := s3Attrs()
	a["retention.maximumByPrefix"] = prefix
	return a
}

// TestBuildS3LifecycleByPrefix: per-prefix rules merge into ONE lifecycle document,
// malformed/duplicate elements refuse fail-closed, declared-empty removes the document.
func TestBuildS3LifecycleByPrefix(t *testing.T) {
	p, err := BuildS3Requests("pv", "prod", "media", lifePrefixAttrs("ingress/=1d", "retain/=365d"), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Lifecycle == nil || p.Lifecycle.Method != "PUT" || p.Lifecycle.Path != "/?lifecycle" {
		t.Fatalf("declared per-prefix retention must build a PUT /?lifecycle, got %+v", p.Lifecycle)
	}
	if !strings.Contains(p.Lifecycle.Body, "<Prefix>ingress/</Prefix>") || !strings.Contains(p.Lifecycle.Body, "<Days>365</Days>") {
		t.Fatalf("the lifecycle body must carry the per-prefix rules, got %q", p.Lifecycle.Body)
	}
	// malformed element (not <prefix>=<N>d) refuses rather than being silently dropped
	if _, err := BuildS3Requests("pv", "prod", "media", lifePrefixAttrs("retain/-365"), nil, 1); err == nil {
		t.Error("a malformed retention.maximumByPrefix element must refuse")
	}
	// duplicate prefix refuses (one ceiling per prefix)
	if _, err := BuildS3Requests("pv", "prod", "media", lifePrefixAttrs("retain/=1d", "retain/=2d"), nil, 1); err == nil {
		t.Error("a duplicate prefix must refuse")
	}
	// declared empty -> DeleteBucketLifecycle
	pe, err := BuildS3Requests("pv", "prod", "media", lifePrefixAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if pe.Lifecycle == nil || pe.Lifecycle.Method != "DELETE" {
		t.Fatalf("retention.maximumByPrefix: [] with no bucket-wide rule must DELETE, got %+v", pe.Lifecycle)
	}
	if class, _ := classifyS3Change("retention.maximumByPrefix", nil, nil); class != "mutable" {
		t.Fatalf("a per-prefix retention change must be in-place, got %q", class)
	}
}

// TestBuildS3LifecycleCoherenceGates pins G1 (per-prefix <= bucket-wide, S3 earliest-wins)
// and G2 (per-prefix >= WORM floor) — the two refusals that stop the contract asserting a
// retention S3 will not deliver, or one that undercuts Object-Lock.
func TestBuildS3LifecycleCoherenceGates(t *testing.T) {
	// G1: a per-prefix ceiling LONGER than the bucket-wide maximum refuses
	g1 := lifePrefixAttrs("retain/=365d")
	g1["retention.maximum"] = "30d"
	if _, err := BuildS3Requests("pv", "prod", "media", g1, nil, 1); err == nil {
		t.Error("G1: a per-prefix ceiling exceeding the bucket-wide maximum must refuse (earliest-wins)")
	}
	// <= bucket-wide is fine
	ok := lifePrefixAttrs("ingress/=1d")
	ok["retention.maximum"] = "30d"
	if _, err := BuildS3Requests("pv", "prod", "media", ok, nil, 1); err != nil {
		t.Errorf("a per-prefix ceiling below the bucket-wide max must build, got %v", err)
	}
	// G2: a per-prefix ceiling BELOW the WORM floor refuses
	g2 := lifePrefixAttrs("ingress/=1d")
	g2["retention.minimum"] = "365d"
	if _, err := BuildS3Requests("pv", "prod", "media", g2, nil, 1); err == nil {
		t.Error("G2: a per-prefix ceiling below retention.minimum must refuse (WORM keeps, lifecycle deletes)")
	}
}

// TestObserveS3LifecycleByPrefix pins the FAIL-CLOSED projection — the whole point of the
// design: only Enabled, whole-day, PURE-prefix rules count; a Disabled, Date, or
// tag-filtered rule is EXCLUDED (so a declared element reads missing -> RED, never a
// false-green over a rule that does not do what it looks like); measured absence is [].
func TestObserveS3LifecycleByPrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" && r.URL.RawQuery == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.RawQuery == "lifecycle" {
			_, _ = w.Write([]byte(`<LifecycleConfiguration>` +
				`<Rule><Status>Enabled</Status><Filter></Filter><Expiration><Days>30</Days></Expiration></Rule>` +
				`<Rule><Status>Enabled</Status><Filter><Prefix>retain/</Prefix></Filter><Expiration><Days>365</Days></Expiration></Rule>` +
				`<Rule><Status>Disabled</Status><Filter><Prefix>old/</Prefix></Filter><Expiration><Days>7</Days></Expiration></Rule>` +
				`<Rule><Status>Enabled</Status><Filter><Prefix>archive/</Prefix></Filter><Expiration><Date>2030-01-01T00:00:00Z</Date></Expiration></Rule>` +
				`</LifecycleConfiguration>`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	d := s3TestDriver(t, srv)
	obs, _, err := d.observeS3("media", "s3:eu-central-1:pv-media")
	if err != nil {
		t.Fatal(err)
	}
	// D1177 EFFECTIVE precedence: the retain/ rule declares 365d, but the bucket-wide
	// 30d rule ALSO matches retain/ objects and S3 applies the EARLIEST expiration — so
	// retain/ objects actually die at 30d. Observe must emit the effective 30d, not the
	// raw 365d (emitting 365d is the precedence false-green: green over a vanishing file).
	if got := valueOf(obs, "retention.maximumByPrefix"); !reflect.DeepEqual(got, []any{"retain/=30d"}) {
		t.Fatalf("fail-closed + effective: retain/ capped by the bucket-wide 30d rule (Disabled + Date excluded), got %v", got)
	}
	if got := valueOf(obs, "retention.maximum"); got != "30d" {
		t.Fatalf("the no-filter rule must map to bucket-wide retention.maximum, got %v", got)
	}

	// D1177 EFFECTIVE precedence over BOTH overlap directions. A naive projection emits the
	// raw rule days and a contract constraining only the per-prefix set goes GREEN — while the
	// object actually dies at the EARLIEST matching expiration. bucket-wide 30d caps retain/
	// (365d -> 30d); a shorter prefix rule data/=5d caps a longer one under it (data/logs/=90d
	// -> 5d, and 30d bucket-wide would too).
	srvP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" && r.URL.RawQuery == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.RawQuery == "lifecycle" {
			_, _ = w.Write([]byte(`<LifecycleConfiguration>` +
				`<Rule><Status>Enabled</Status><Filter></Filter><Expiration><Days>30</Days></Expiration></Rule>` +
				`<Rule><Status>Enabled</Status><Filter><Prefix>retain/</Prefix></Filter><Expiration><Days>365</Days></Expiration></Rule>` +
				`<Rule><Status>Enabled</Status><Filter><Prefix>data/</Prefix></Filter><Expiration><Days>5</Days></Expiration></Rule>` +
				`<Rule><Status>Enabled</Status><Filter><Prefix>data/logs/</Prefix></Filter><Expiration><Days>90</Days></Expiration></Rule>` +
				`</LifecycleConfiguration>`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srvP.Close()
	dP := s3TestDriver(t, srvP)
	obsP, _, err := dP.observeS3("media", "s3:eu-central-1:pv-media")
	if err != nil {
		t.Fatal(err)
	}
	// sorted-unique: data/=5d, data/logs/=5d (capped by data/), retain/=30d (capped by bucket-wide)
	if got := valueOf(obsP, "retention.maximumByPrefix"); !reflect.DeepEqual(got, []any{"data/=5d", "data/logs/=5d", "retain/=30d"}) {
		t.Fatalf("effective per-prefix retention (earliest-wins over overlapping rules), got %v", got)
	}

	// no lifecycle at all -> MEASURED empty set (a blind bucket reads [], equals blocks it)
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" && r.URL.RawQuery == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte("<Error><Code>NoSuchLifecycleConfiguration</Code></Error>"))
	}))
	defer srv2.Close()
	d2 := s3TestDriver(t, srv2)
	obs2, _, _ := d2.observeS3("media", "s3:eu-central-1:pv-media")
	if got := valueOf(obs2, "retention.maximumByPrefix"); !reflect.DeepEqual(got, []any{}) {
		t.Fatalf("a bucket with no lifecycle must observe a MEASURED [], got %v", got)
	}
}
