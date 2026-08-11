package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

const (
	gdCap        = "capability.security.threatdetection"
	gdRegion     = "eu-central-1"
	gdDetectorID = "0123456789abcdef0123456789abcdef" // a 32-hex AWS-assigned detector id
)

// fakeGuardDuty is a stateful fake GuardDuty (REST-JSON) endpoint. It serves
// ListDetectors / GetDetector / CreateDetector / UpdateDetector / DeleteDetector,
// records mutating order + captures the create body, and can inject an unreadable
// (500) read or a failing UpdateDetector to exercise the four-valued paths.
type fakeGuardDuty struct {
	detectorID string
	exists     bool
	status     string // ENABLED | DISABLED
	eks        bool   // EKS_AUDIT_LOGS enabled
	malware    bool   // EBS_MALWARE_PROTECTION enabled
	tags       map[string]string

	unreadable bool // 500 on GetDetector
	notFound   bool // 404 on GetDetector
	updateFail bool // 400 on UpdateDetector

	createBody string
	order      []string
}

func (f *fakeGuardDuty) detectorJSON() []byte {
	feat := func(name string, on bool) map[string]any {
		s := "DISABLED"
		if on {
			s = "ENABLED"
		}
		return map[string]any{"Name": name, "Status": s}
	}
	out, _ := json.Marshal(map[string]any{
		"Status": f.status,
		"Features": []map[string]any{
			feat(gdFeatureEKSAuditLogs, f.eks),
			feat(gdFeatureEBSMalware, f.malware),
		},
		"FindingPublishingFrequency": "SIX_HOURS",
		"Tags":                       f.tags,
	})
	return out
}

func (f *fakeGuardDuty) handler(t *testing.T, rec *capture) *httptest.Server {
	t.Helper()
	getPath := guardDutyDetectorPath + "/" + f.detectorID
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		if rec != nil {
			rec.record(r, body)
		}
		p, m := r.URL.Path, r.Method
		switch {
		case p == guardDutyDetectorPath && m == http.MethodGet: // ListDetectors
			ids := []string{}
			if f.exists {
				ids = append(ids, f.detectorID)
			}
			out, _ := json.Marshal(map[string]any{"DetectorIds": ids})
			_, _ = w.Write(out)
		case p == getPath && m == http.MethodGet: // GetDetector
			if f.unreadable {
				http.Error(w, `{"message":"InternalServerError"}`, http.StatusInternalServerError)
				return
			}
			if f.notFound || !f.exists {
				http.Error(w, `{"message":"ResourceNotFoundException"}`, http.StatusNotFound)
				return
			}
			_, _ = w.Write(f.detectorJSON())
		case p == guardDutyDetectorPath && m == http.MethodPost: // CreateDetector
			f.order = append(f.order, "CreateDetector")
			f.createBody = body
			f.exists = true
			f.detectorID = gdDetectorID
			out, _ := json.Marshal(map[string]any{"DetectorId": gdDetectorID})
			_, _ = w.Write(out)
		case p == getPath && m == http.MethodPost: // UpdateDetector
			f.order = append(f.order, "UpdateDetector")
			if f.updateFail {
				http.Error(w, `{"message":"BadRequestException"}`, http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{}`))
		case p == getPath && m == http.MethodDelete: // DeleteDetector
			f.order = append(f.order, "DeleteDetector")
			f.exists = false
			_, _ = w.Write([]byte(`{}`))
		default:
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
		}
	}))
}

func guardDutyDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	guarddutyBaseURLOverride = srv.URL
	t.Cleanup(func() { guarddutyBaseURLOverride = "" })
	return NewDriver(gdRegion)
}

// TestGuardDuty_BuildRefusesUnmapped: an attribute with no threatdetection mapping is
// REFUSED (never silently dropped).
func TestGuardDuty_BuildRefusesUnmapped(t *testing.T) {
	attrs := map[string]any{"location.region": gdRegion, "detection.enabled": true, "encryption.atRest": true}
	if _, err := BuildGuardDuty("prod", gdCap, attrs, nil, 1); err == nil {
		t.Fatal("an unmapped attribute must be refused, not silently dropped")
	}
}

// TestGuardDuty_BuildRequiresEnabled: detection.enabled is the core posture switch —
// its absence is a refusal, never a silent assumption.
func TestGuardDuty_BuildRequiresEnabled(t *testing.T) {
	attrs := map[string]any{"location.region": gdRegion, "protection.kubernetes": true}
	if _, err := BuildGuardDuty("prod", gdCap, attrs, nil, 1); err == nil {
		t.Fatal("a missing detection.enabled must be refused")
	}
}

// TestGuardDuty_BuildRefusesBadFrequency: the finding-publishing frequency operand is
// a closed enum — an unknown value is refused, never a silent default.
func TestGuardDuty_BuildRefusesBadFrequency(t *testing.T) {
	attrs := map[string]any{"location.region": gdRegion, "detection.enabled": true}
	impl := map[string]any{"findingPublishingFrequency": "EVERY_MINUTE"}
	if _, err := BuildGuardDuty("prod", gdCap, attrs, impl, 1); err == nil {
		t.Fatal("an invalid findingPublishingFrequency must be refused")
	}
}

// TestGuardDuty_CreateFresh: with no existing detector, create stands one up
// (CreateDetector), returns the AWS-assigned id in the pid, and writes ownership tags
// + the requested EKS protection feature in the body.
func TestGuardDuty_CreateFresh(t *testing.T) {
	f := &fakeGuardDuty{status: "ENABLED"}
	rec := newCapture()
	srv := f.handler(t, rec)
	defer srv.Close()
	d := guardDutyDriver(t, srv)

	attrs := map[string]any{
		"location.region":       gdRegion,
		"detection.enabled":     true,
		"protection.kubernetes": true,
		"service.managed":       true,
	}
	res := d.createGuardDuty(gdRegion, "prod", gdCap, attrs, nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if res.ProviderID != guardDutyProviderID(gdRegion, gdDetectorID) {
		t.Fatalf("create providerId = %q, want the AWS-assigned detector id", res.ProviderID)
	}
	var cb map[string]any
	if err := json.Unmarshal([]byte(f.createBody), &cb); err != nil {
		t.Fatalf("create body not JSON: %v", err)
	}
	// D735: GuardDuty's REST-JSON body is camelCase. These assertions read `Enable`,
	// `Tags`, `Features` and `Name`/`Status`, so they PASSED on a body AWS rejects with
	// "the JSON could not be processed" — the capability could never be created on a
	// real account. Superseded in place: the names are corrected to the contract they
	// were always supposed to be measured against, and the PascalCase spellings are
	// asserted ABSENT so the defect cannot come back wearing both spellings at once.
	for _, wrong := range []string{"Enable", "Tags", "Features", "FindingPublishingFrequency"} {
		if _, has := cb[wrong]; has {
			t.Fatalf("the create body carries %q — GuardDuty's field names are camelCase "+
				"and a PascalCase key is silently dropped, taking the REQUIRED `enable` "+
				"with it", wrong)
		}
	}
	if cb["enable"] != true {
		t.Fatalf("create must enable the detector, got %v", cb["enable"])
	}
	tags, _ := cb["tags"].(map[string]any)
	if tags["groundhold-capability"] == nil || tags["groundhold-environment"] == nil {
		t.Fatalf("create must carry ownership tags, got %v", cb["tags"])
	}
	feats, _ := cb["features"].([]any)
	var sawEKS bool
	for _, fe := range feats {
		m, _ := fe.(map[string]any)
		if m["name"] == gdFeatureEKSAuditLogs && m["status"] == "ENABLED" {
			sawEKS = true
		}
	}
	if !sawEKS {
		t.Fatalf("protection.kubernetes=true must enable EKS_AUDIT_LOGS in the create body, got %v", cb["Features"])
	}
	if rec.unsign != 0 {
		t.Fatalf("every GuardDuty request must be SigV4-signed; %d were not", rec.unsign)
	}
}

// TestGuardDuty_CreateForeignRefuses: the detector is a singleton — an existing,
// FOREIGN detector (tags do not match) HONEST-REFUSES, issuing no mutation (groundhold
// can never stand up a second, so it never pretends to).
func TestGuardDuty_CreateForeignRefuses(t *testing.T) {
	f := &fakeGuardDuty{
		detectorID: gdDetectorID, exists: true, status: "ENABLED",
		tags: map[string]string{"team": "someone-else"},
	}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := guardDutyDriver(t, srv)

	attrs := map[string]any{"location.region": gdRegion, "detection.enabled": true, "service.managed": true}
	res := d.createGuardDuty(gdRegion, "prod", gdCap, attrs, nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not groundhold-managed") {
		t.Fatalf("a foreign detector must honest-refuse, got %+v", res)
	}
	for _, o := range f.order {
		if o == "CreateDetector" || o == "UpdateDetector" {
			t.Fatalf("a foreign-detector refusal must issue no mutation; saw %v", f.order)
		}
	}
}

// TestGuardDuty_CreateConvergesOurs: an existing detector that is OURS (tags match) is
// converged in place (UpdateDetector), NOT re-created; the pid pins the existing id.
func TestGuardDuty_CreateConvergesOurs(t *testing.T) {
	f := &fakeGuardDuty{
		detectorID: gdDetectorID, exists: true, status: "ENABLED",
		tags: map[string]string{
			"groundhold-capability":  sanitizeTag(gdCap),
			"groundhold-environment": sanitizeTag("prod"),
		},
	}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := guardDutyDriver(t, srv)

	attrs := map[string]any{
		"location.region": gdRegion, "detection.enabled": true,
		"protection.malware": true, "service.managed": true,
	}
	res := d.createGuardDuty(gdRegion, "prod", gdCap, attrs, nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("converge status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if res.ProviderID != guardDutyProviderID(gdRegion, gdDetectorID) {
		t.Fatalf("converge pid = %q, want the existing detector id", res.ProviderID)
	}
	if strings.Join(f.order, ",") != "UpdateDetector" {
		t.Fatalf("converge must UpdateDetector (not CreateDetector), order = %v", f.order)
	}
}

// TestGuardDuty_ObserveReverseMap: a live detector reverse-maps to detection.enabled,
// protection.kubernetes/malware, location.region and service.managed.
func TestGuardDuty_ObserveReverseMap(t *testing.T) {
	f := &fakeGuardDuty{
		detectorID: gdDetectorID, exists: true, status: "ENABLED",
		eks: true, malware: false,
		tags: map[string]string{"groundhold-capability": sanitizeTag(gdCap)},
	}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := guardDutyDriver(t, srv)

	obs, _, err := d.observeGuardDuty(gdCap, guardDutyProviderID(gdRegion, gdDetectorID))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	if m["location.region"] != gdRegion {
		t.Fatalf("region = %v, want %s", m["location.region"], gdRegion)
	}
	if m["detection.enabled"] != true {
		t.Fatalf("detection.enabled = %v, want true", m["detection.enabled"])
	}
	if m["protection.kubernetes"] != true {
		t.Fatalf("protection.kubernetes = %v, want true (EKS_AUDIT_LOGS enabled)", m["protection.kubernetes"])
	}
	if m["protection.malware"] != false {
		t.Fatalf("protection.malware = %v, want false", m["protection.malware"])
	}
	if m["service.managed"] != true {
		t.Fatalf("service.managed missing")
	}
}

// TestGuardDuty_ObserveNotFound: a vanished detector is nothing-to-observe (readable,
// empty observations + a diagnostic), NOT an error.
func TestGuardDuty_ObserveNotFound(t *testing.T) {
	f := &fakeGuardDuty{detectorID: gdDetectorID, notFound: true}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := guardDutyDriver(t, srv)

	obs, diags, err := d.observeGuardDuty(gdCap, guardDutyProviderID(gdRegion, gdDetectorID))
	if err != nil {
		t.Fatalf("not-found must not error, got %v", err)
	}
	// Corrected with D520: this asserted SILENCE for an absent bound resource,
	// which is the defect F-LC3 exists to prevent — the compile sees an empty set,
	// plans nothing, and converge reports a world that no longer contains it.
	if !absentMarked(obs) {
		t.Fatalf("not-found must mark the resource absent, got %v", obs)
	}
	if len(diags) == 0 || !strings.Contains(diags[0], "bound resource is gone") {
		t.Fatalf("not-found must carry a gone diagnostic, got %v", diags)
	}
}

// TestGuardDuty_ObserveUnreadableErrors: an unreadable (500) detector read is UNKNOWN
// — an error, never a fabricated absence.
func TestGuardDuty_ObserveUnreadableErrors(t *testing.T) {
	f := &fakeGuardDuty{detectorID: gdDetectorID, exists: true, unreadable: true}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := guardDutyDriver(t, srv)

	if _, _, err := d.observeGuardDuty(gdCap, guardDutyProviderID(gdRegion, gdDetectorID)); err == nil {
		t.Fatal("an unreadable detector must return an error, not a fabricated absence")
	}
}

// TestGuardDuty_UpdateOwnershipGated: a protection toggle on an OURS detector patches
// in place (UpdateDetector); a FOREIGN detector refuses.
func TestGuardDuty_UpdateOwnershipGated(t *testing.T) {
	ownTags := map[string]string{
		"groundhold-capability":  sanitizeTag(gdCap),
		"groundhold-environment": sanitizeTag("prod"),
	}
	f := &fakeGuardDuty{detectorID: gdDetectorID, exists: true, status: "ENABLED", tags: ownTags}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := guardDutyDriver(t, srv)

	attrs := map[string]any{
		"location.region": gdRegion, "detection.enabled": true,
		"protection.kubernetes": true, "service.managed": true,
	}
	res := d.updateGuardDuty(gdCap, "prod", guardDutyProviderID(gdRegion, gdDetectorID),
		attrs, nil, []string{"protection.kubernetes"})
	if res.Status != "succeeded" {
		t.Fatalf("owned update = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if strings.Join(f.order, ",") != "UpdateDetector" {
		t.Fatalf("update order = %v, want [UpdateDetector]", f.order)
	}

	// foreign tags -> refuse.
	f2 := &fakeGuardDuty{detectorID: gdDetectorID, exists: true, status: "ENABLED",
		tags: map[string]string{"team": "other"}}
	srv2 := f2.handler(t, nil)
	defer srv2.Close()
	d2 := guardDutyDriver(t, srv2)
	res2 := d2.updateGuardDuty(gdCap, "prod", guardDutyProviderID(gdRegion, gdDetectorID),
		attrs, nil, []string{"protection.kubernetes"})
	if res2.Status != "failed" || !strings.Contains(res2.Reason, "not ours") {
		t.Fatalf("a foreign detector must refuse the update, got %+v", res2)
	}
}

// TestGuardDuty_UpdateRefusesRegionChange: location.region is unsupported in place (a
// detector is region-bound) — the update refuses before mutating.
func TestGuardDuty_UpdateRefusesRegionChange(t *testing.T) {
	f := &fakeGuardDuty{detectorID: gdDetectorID, exists: true, status: "ENABLED",
		tags: map[string]string{"groundhold-capability": sanitizeTag(gdCap)}}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := guardDutyDriver(t, srv)

	attrs := map[string]any{"location.region": gdRegion, "detection.enabled": true}
	res := d.updateGuardDuty(gdCap, "prod", guardDutyProviderID(gdRegion, gdDetectorID),
		attrs, nil, []string{"location.region"})
	if res.Status != "failed" {
		t.Fatalf("a region change must be refused, got %+v", res)
	}
	for _, o := range f.order {
		if o == "UpdateDetector" {
			t.Fatal("an unsupported change must issue no UpdateDetector")
		}
	}
}

// TestGuardDuty_UpdatePartialUnknownWithPid (four-valued): once a detector STANDS, a
// failing UpdateDetector is unknown WITH the pid (a partial posture to reconcile),
// never a bare "failed" that hides the standing detector.
func TestGuardDuty_UpdatePartialUnknownWithPid(t *testing.T) {
	f := &fakeGuardDuty{detectorID: gdDetectorID, exists: true, status: "ENABLED",
		updateFail: true,
		tags:       map[string]string{"groundhold-capability": sanitizeTag(gdCap), "groundhold-environment": sanitizeTag("prod")}}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := guardDutyDriver(t, srv)

	attrs := map[string]any{
		"location.region": gdRegion, "detection.enabled": true,
		"protection.malware": true, "service.managed": true,
	}
	pid := guardDutyProviderID(gdRegion, gdDetectorID)
	res := d.updateGuardDuty(gdCap, "prod", pid, attrs, nil, []string{"protection.malware"})
	if res.Status != "unknown" || res.ProviderID != pid {
		t.Fatalf("a failing UpdateDetector on a standing detector must be unknown WITH the pid, got %+v", res)
	}
}

// TestGuardDuty_DeleteOwnershipGated: an ours detector deletes (posture off); a
// foreign one refuses; a vanished one is an idempotent success.
func TestGuardDuty_DeleteOwnershipGated(t *testing.T) {
	f := &fakeGuardDuty{detectorID: gdDetectorID, exists: true, status: "ENABLED",
		tags: map[string]string{"groundhold-capability": sanitizeTag(gdCap), "groundhold-environment": sanitizeTag("prod")}}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := guardDutyDriver(t, srv)

	res := d.deleteGuardDuty(gdCap, "prod", guardDutyProviderID(gdRegion, gdDetectorID))
	if res.Status != "succeeded" {
		t.Fatalf("owned delete = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if strings.Join(f.order, ",") != "DeleteDetector" {
		t.Fatalf("delete order = %v, want [DeleteDetector]", f.order)
	}

	// foreign tags -> refuse, no delete.
	f2 := &fakeGuardDuty{detectorID: gdDetectorID, exists: true, status: "ENABLED",
		tags: map[string]string{"team": "other"}}
	srv2 := f2.handler(t, nil)
	defer srv2.Close()
	d2 := guardDutyDriver(t, srv2)
	res2 := d2.deleteGuardDuty(gdCap, "prod", guardDutyProviderID(gdRegion, gdDetectorID))
	if res2.Status != "failed" || !strings.Contains(res2.Reason, "not ours") {
		t.Fatalf("a foreign detector must refuse the delete, got %+v", res2)
	}
	for _, o := range f2.order {
		if o == "DeleteDetector" {
			t.Fatal("no delete may touch a foreign detector")
		}
	}

	// vanished -> idempotent success.
	f3 := &fakeGuardDuty{detectorID: gdDetectorID, notFound: true}
	srv3 := f3.handler(t, nil)
	defer srv3.Close()
	d3 := guardDutyDriver(t, srv3)
	res3 := d3.deleteGuardDuty(gdCap, "prod", guardDutyProviderID(gdRegion, gdDetectorID))
	if res3.Status != "succeeded" {
		t.Fatalf("a vanished detector delete must be an idempotent success, got %+v", res3)
	}
}

// TestGuardDuty_Discover enumerates the region's detector as
// capability.security.threatdetection, reverse-mapped.
func TestGuardDuty_Discover(t *testing.T) {
	f := &fakeGuardDuty{detectorID: gdDetectorID, exists: true, status: "ENABLED", eks: true,
		tags: map[string]string{"groundhold-capability": sanitizeTag(gdCap)}}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := guardDutyDriver(t, srv)

	found, _, err := d.discoverGuardDuty(gdRegion)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("discover found %d detectors, want 1", len(found))
	}
	if found[0].ResourceType != gdCap {
		t.Fatalf("resource type = %q, want %s", found[0].ResourceType, gdCap)
	}
	if found[0].ProviderID != guardDutyProviderID(gdRegion, gdDetectorID) {
		t.Fatalf("providerId = %q", found[0].ProviderID)
	}
}

// TestGuardDuty_ClassifyChange: the posture (detection.enabled, protection.*) is
// mutable; location.region is unsupported (region-bound); service/projection are
// unsupported. Every path carries a reason.
func TestGuardDuty_ClassifyChange(t *testing.T) {
	want := map[string]string{
		"detection.enabled":     "mutable",
		"protection.kubernetes": "mutable",
		"protection.malware":    "mutable",
		"location.region":       "unsupported",
		"service.managed":       "unsupported",
		"cost.monthly":          "unsupported",
	}
	for p, w := range want {
		got, reason := classifyGuardDutyChange(p)
		if got != w {
			t.Errorf("classify %s = %q, want %q", p, got, w)
		}
		if reason == "" {
			t.Errorf("classify %s must carry an honest reason", p)
		}
	}
}

func gdRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingGuardDuty enrols GuardDuty in the D391 gate. A detector is
// SINGLETON per region-account: a second CreateDetector does not stand up a second
// detector, it fails — so the damage of a missing adoption here is not a duplicate but
// a converge that cannot proceed at all against an estate that already has one. The
// existing test asserts the call ORDER (UpdateDetector, never CreateDetector); the gate
// asserts the same property as a class, through the public dispatch.
func TestAdoptsExistingGuardDuty(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:     "aws/guardduty",
		Classify: gdRole,
		ExistingServer: func() *httptest.Server {
			f := &fakeGuardDuty{
				detectorID: gdDetectorID, exists: true, status: "ENABLED",
				tags: map[string]string{
					"groundhold-capability":  sanitizeTag(gdCap),
					"groundhold-environment": sanitizeTag("prod"),
				},
			}
			return f.handler(t, nil)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			guarddutyBaseURLOverride = happyURL
			t.Cleanup(func() { guarddutyBaseURLOverride = "" })
			d := NewDriver(gdRegion)
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("guardduty", gdCap, "prod", map[string]any{
				"location.region": gdRegion, "detection.enabled": true,
				"protection.malware": true, "service.managed": true,
			}, nil, "gd", 1)
		},
		PID:              guardDutyProviderID(gdRegion, gdDetectorID),
		AllowedMutations: 1, // UpdateDetector converges the adopted detector
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
