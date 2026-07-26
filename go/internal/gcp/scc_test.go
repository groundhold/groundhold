package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/provider"
)

const (
	sccCap     = "capability.security.threatdetection"
	sccProject = "my-project"
)

// fakeSCC is a stateful fake Security Center Management endpoint. It serves
// GET/PATCH on the three governed securityCenterServices for one project scope,
// tracks intended vs effective enablement, records the PATCH order, and can inject
// an unreadable (500) read, a not-found module, or a tier gate (effective stays
// DISABLED even after an intended=ENABLED PATCH).
type fakeSCC struct {
	// intended[module] -> ENABLED|DISABLED ("" == module not present -> 404)
	intended map[string]string

	unreadable bool // 500 on every GET
	tierGate   bool // effective stays DISABLED regardless of intended (Standard-style)

	order []string // PATCHed module ids, in order
}

func newFakeSCC(event, container, vm string) *fakeSCC {
	return &fakeSCC{intended: map[string]string{
		sccModuleEventThreat:     event,
		sccModuleContainerThreat: container,
		sccModuleVMThreat:        vm,
	}}
}

// effective mirrors intended unless the tier gate holds it DISABLED.
func (f *fakeSCC) effective(module string) string {
	if f.tierGate {
		return "DISABLED"
	}
	return f.intended[module]
}

func (f *fakeSCC) moduleFromPath(path string) string {
	i := strings.LastIndexByte(path, '/')
	if i < 0 {
		return ""
	}
	return path[i+1:]
}

func (f *fakeSCC) handler(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		module := f.moduleFromPath(r.URL.Path)
		state, present := f.intended[module]
		switch r.Method {
		case http.MethodGet:
			if f.unreadable {
				http.Error(w, `{"error":{"message":"backend error"}}`, http.StatusInternalServerError)
				return
			}
			if !present || state == "" {
				http.Error(w, `{"error":{"message":"NOT_FOUND"}}`, http.StatusNotFound)
				return
			}
			out, _ := json.Marshal(map[string]any{
				"name":                     "projects/proj/locations/global/securityCenterServices/" + module,
				"intendedEnablementState":  state,
				"effectiveEnablementState": f.effective(module),
			})
			_, _ = w.Write(out)
		case http.MethodPatch:
			b, _ := io.ReadAll(r.Body)
			var body struct {
				IntendedEnablementState string `json:"intendedEnablementState"`
			}
			_ = json.Unmarshal(b, &body)
			f.order = append(f.order, module)
			f.intended[module] = body.IntendedEnablementState
			out, _ := json.Marshal(map[string]any{
				"name":                     "projects/proj/locations/global/securityCenterServices/" + module,
				"intendedEnablementState":  body.IntendedEnablementState,
				"effectiveEnablementState": f.effective(module),
			})
			_, _ = w.Write(out)
		default:
			http.Error(w, `{"error":{"message":"method"}}`, http.StatusMethodNotAllowed)
		}
	}))
}

func sccDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	sccBaseURLOverride = srv.URL
	t.Cleanup(func() { sccBaseURLOverride = "" })
	d := NewDriver(sccProject)
	d.PollInterval = time.Millisecond
	return d
}

func sccAttrs(enabled, k8s, malware bool) map[string]any {
	return map[string]any{
		"location.region":       "global",
		"detection.enabled":     enabled,
		"protection.kubernetes": k8s,
		"protection.malware":    malware,
		"service.managed":       true,
	}
}

func sccImpl() map[string]any { return map[string]any{"tier": "PREMIUM"} }

// --- pure builder refusals ---

// TestSCC_BuildRefusesUnmapped: an attribute with no threatdetection mapping is
// REFUSED (never silently dropped).
func TestSCC_BuildRefusesUnmapped(t *testing.T) {
	attrs := sccAttrs(true, true, false)
	attrs["encryption.atRest"] = true
	if _, err := BuildSCC(sccProject, "prod", sccCap, attrs, sccImpl(), 1); err == nil {
		t.Fatal("an unmapped attribute must be refused, not silently dropped")
	}
}

// TestSCC_BuildRequiresEnabled: detection.enabled is the core posture switch — its
// absence is a refusal, never a silent assumption.
func TestSCC_BuildRequiresEnabled(t *testing.T) {
	attrs := map[string]any{"location.region": "global", "protection.kubernetes": true, "service.managed": true}
	if _, err := BuildSCC(sccProject, "prod", sccCap, attrs, sccImpl(), 1); err == nil {
		t.Fatal("a missing detection.enabled must be refused")
	}
}

// TestSCC_BuildRequiresTier: tier is the operand that gates the modules — its
// absence is a refusal, never a silent default.
func TestSCC_BuildRequiresTier(t *testing.T) {
	if _, err := BuildSCC(sccProject, "prod", sccCap, sccAttrs(true, true, false), nil, 1); err == nil {
		t.Fatal("a missing implementation.tier must be refused")
	}
	bad := map[string]any{"tier": "GOLD"}
	if _, err := BuildSCC(sccProject, "prod", sccCap, sccAttrs(true, true, false), bad, 1); err == nil {
		t.Fatal("an invalid tier must be refused")
	}
}

// TestSCC_BuildStandardTierRefusesThreatModules: Standard includes none of the
// threat-detection modules — a request for any is refused, never a fake success.
func TestSCC_BuildStandardTierRefusesThreatModules(t *testing.T) {
	impl := map[string]any{"tier": "STANDARD"}
	if _, err := BuildSCC(sccProject, "prod", sccCap, sccAttrs(true, false, false), impl, 1); err == nil {
		t.Fatal("STANDARD tier with detection.enabled=true must be refused (no threat modules)")
	}
}

// TestSCC_BuildRefusesRegionalLocation: SCC is global — a real regional location has
// no mapping and is refused (never silently coerced).
func TestSCC_BuildRefusesRegionalLocation(t *testing.T) {
	attrs := sccAttrs(true, true, false)
	attrs["location.region"] = "us-central1"
	if _, err := BuildSCC(sccProject, "prod", sccCap, attrs, sccImpl(), 1); err == nil {
		t.Fatal("a regional location.region must be refused for a global service")
	}
}

// TestSCC_BuildContradictoryPosture: detection off + protection on is contradictory.
func TestSCC_BuildContradictoryPosture(t *testing.T) {
	if _, err := BuildSCC(sccProject, "prod", sccCap, sccAttrs(false, true, false), sccImpl(), 1); err == nil {
		t.Fatal("detection.enabled=false with protection true must be refused")
	}
}

// TestSCC_BuildScopeAmbiguous: organizationId AND projectId together is ambiguous.
func TestSCC_BuildScopeAmbiguous(t *testing.T) {
	impl := map[string]any{"tier": "PREMIUM", "organizationId": "123456", "projectId": "other-proj"}
	if _, err := BuildSCC(sccProject, "prod", sccCap, sccAttrs(true, false, false), impl, 1); err == nil {
		t.Fatal("organizationId + projectId together must be refused as ambiguous")
	}
}

// TestSCC_BuildOrgScope: an organizationId operand yields the org scope.
func TestSCC_BuildOrgScope(t *testing.T) {
	impl := map[string]any{"tier": "ENTERPRISE", "organizationId": "123456789"}
	p, err := BuildSCC(sccProject, "prod", sccCap, sccAttrs(true, true, true), impl, 1)
	if err != nil {
		t.Fatalf("org-scope build: %v", err)
	}
	if p.ScopeType != "organizations" || p.ScopeID != "123456789" {
		t.Fatalf("scope = %s/%s, want organizations/123456789", p.ScopeType, p.ScopeID)
	}
	dm := p.desiredModules()
	if dm[sccModuleEventThreat] != "ENABLED" || dm[sccModuleContainerThreat] != "ENABLED" || dm[sccModuleVMThreat] != "ENABLED" {
		t.Fatalf("desiredModules = %v, want all ENABLED", dm)
	}
}

// --- network shell (four-valued) ---

// TestSCC_CreateConverges: create PATCHes the governed modules to the desired
// intended state and pins the project-scope providerId.
func TestSCC_CreateConverges(t *testing.T) {
	f := newFakeSCC("DISABLED", "DISABLED", "DISABLED")
	srv := f.handler(t)
	defer srv.Close()
	d := sccDriver(t, srv)

	res := d.createSCC(sccCap, "prod", sccAttrs(true, true, false), sccImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("create = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if res.ProviderID != sccProviderID("projects", sccProject) {
		t.Fatalf("pid = %q, want %q", res.ProviderID, sccProviderID("projects", sccProject))
	}
	if f.intended[sccModuleEventThreat] != "ENABLED" || f.intended[sccModuleContainerThreat] != "ENABLED" {
		t.Fatalf("event/container not ENABLED after converge: %v", f.intended)
	}
	if f.intended[sccModuleVMThreat] != "DISABLED" {
		t.Fatalf("vm-threat should stay DISABLED (protection.malware=false), got %v", f.intended[sccModuleVMThreat])
	}
}

// TestSCC_CreateIdempotentNoOp: a posture already at the desired state issues NO
// PATCH (idempotent converge).
func TestSCC_CreateIdempotentNoOp(t *testing.T) {
	f := newFakeSCC("ENABLED", "ENABLED", "DISABLED")
	srv := f.handler(t)
	defer srv.Close()
	d := sccDriver(t, srv)

	res := d.createSCC(sccCap, "prod", sccAttrs(true, true, false), sccImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("idempotent create = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if len(f.order) != 0 {
		t.Fatalf("an already-converged posture must issue no PATCH, got %v", f.order)
	}
}

// TestSCC_CreateTierGateUnknown: an intended=ENABLED the tier cannot make effective
// is unknown WITH the pid (a partial posture to reconcile), never a fake success.
func TestSCC_CreateTierGateUnknown(t *testing.T) {
	f := newFakeSCC("DISABLED", "DISABLED", "DISABLED")
	f.tierGate = true // effective stays DISABLED
	srv := f.handler(t)
	defer srv.Close()
	d := sccDriver(t, srv)

	res := d.createSCC(sccCap, "prod", sccAttrs(true, false, false), sccImpl(), 1)
	if res.Status != "unknown" || res.ProviderID != sccProviderID("projects", sccProject) {
		t.Fatalf("tier-gated ENABLED must be unknown WITH the pid, got %+v", res)
	}
	if !strings.Contains(res.Reason, "effective") {
		t.Fatalf("reason must explain the effective/intended gap, got %q", res.Reason)
	}
}

// TestSCC_CreateModuleNotFoundUnknown: a governed module absent for the parent (SCC
// not provisioned) is unknown WITH the pid, never a fabricated success.
func TestSCC_CreateModuleNotFoundUnknown(t *testing.T) {
	f := newFakeSCC("", "", "") // all 404
	srv := f.handler(t)
	defer srv.Close()
	d := sccDriver(t, srv)

	res := d.createSCC(sccCap, "prod", sccAttrs(true, false, false), sccImpl(), 1)
	if res.Status != "unknown" {
		t.Fatalf("an absent module must be unknown, got %+v", res)
	}
}

// TestSCC_ObserveReverseMap: a live posture reverse-maps to detection.enabled,
// protection.kubernetes/malware (effective), location.region=global, service.managed.
func TestSCC_ObserveReverseMap(t *testing.T) {
	f := newFakeSCC("ENABLED", "ENABLED", "DISABLED")
	srv := f.handler(t)
	defer srv.Close()
	d := sccDriver(t, srv)

	obs, _, err := d.observeSCC(sccCap, sccProviderID("projects", sccProject))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	if m["location.region"] != "global" {
		t.Fatalf("region = %v, want global", m["location.region"])
	}
	if m["detection.enabled"] != true {
		t.Fatalf("detection.enabled = %v, want true", m["detection.enabled"])
	}
	if m["protection.kubernetes"] != true {
		t.Fatalf("protection.kubernetes = %v, want true", m["protection.kubernetes"])
	}
	if m["protection.malware"] != false {
		t.Fatalf("protection.malware = %v, want false", m["protection.malware"])
	}
	if m["service.managed"] != true {
		t.Fatalf("service.managed missing")
	}
}

// TestSCC_ObserveEffectiveTruth: intended=ENABLED but effective=DISABLED (tier gate)
// observes as detection.enabled=FALSE — the truth, never the intent.
func TestSCC_ObserveEffectiveTruth(t *testing.T) {
	f := newFakeSCC("ENABLED", "ENABLED", "ENABLED")
	f.tierGate = true
	srv := f.handler(t)
	defer srv.Close()
	d := sccDriver(t, srv)

	obs, _, err := d.observeSCC(sccCap, sccProviderID("projects", sccProject))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "detection.enabled" && o.Value != false {
			t.Fatalf("effective=DISABLED must observe detection.enabled=false, got %v", o.Value)
		}
	}
}

// TestSCC_ObserveNotFound: an absent core module is nothing-to-observe (readable,
// empty observations + a diagnostic), NOT an error.
func TestSCC_ObserveNotFound(t *testing.T) {
	f := newFakeSCC("", "", "")
	srv := f.handler(t)
	defer srv.Close()
	d := sccDriver(t, srv)

	obs, diags, err := d.observeSCC(sccCap, sccProviderID("projects", sccProject))
	if err != nil {
		t.Fatalf("not-found must not error, got %v", err)
	}
	if len(obs) != 0 {
		t.Fatalf("not-found must yield no observations, got %v", obs)
	}
	if len(diags) == 0 || !strings.Contains(diags[0], "nothing to observe") {
		t.Fatalf("not-found must carry a nothing-to-observe diagnostic, got %v", diags)
	}
}

// TestSCC_ObserveUnreadableErrors: an unreadable (500) read is UNKNOWN — an error,
// never a fabricated absence.
func TestSCC_ObserveUnreadableErrors(t *testing.T) {
	f := newFakeSCC("ENABLED", "ENABLED", "ENABLED")
	f.unreadable = true
	srv := f.handler(t)
	defer srv.Close()
	d := sccDriver(t, srv)

	if _, _, err := d.observeSCC(sccCap, sccProviderID("projects", sccProject)); err == nil {
		t.Fatal("an unreadable module must return an error, not a fabricated absence")
	}
}

// TestSCC_UpdateInPlace: a protection toggle patches in place; an unsupported change
// (location.region) refuses before mutating.
func TestSCC_UpdateInPlace(t *testing.T) {
	f := newFakeSCC("ENABLED", "DISABLED", "DISABLED")
	srv := f.handler(t)
	defer srv.Close()
	d := sccDriver(t, srv)

	res := d.updateSCC(sccCap, "prod", sccProviderID("projects", sccProject),
		sccAttrs(true, true, false), sccImpl(), []string{"protection.kubernetes"})
	if res.Status != "succeeded" {
		t.Fatalf("update = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if f.intended[sccModuleContainerThreat] != "ENABLED" {
		t.Fatalf("container-threat should be ENABLED after the toggle, got %v", f.intended[sccModuleContainerThreat])
	}

	// unsupported change refuses before mutating.
	f2 := newFakeSCC("ENABLED", "ENABLED", "DISABLED")
	srv2 := f2.handler(t)
	defer srv2.Close()
	d2 := sccDriver(t, srv2)
	res2 := d2.updateSCC(sccCap, "prod", sccProviderID("projects", sccProject),
		sccAttrs(true, true, false), sccImpl(), []string{"location.region"})
	if res2.Status != "failed" {
		t.Fatalf("an unsupported change must refuse, got %+v", res2)
	}
	if len(f2.order) != 0 {
		t.Fatalf("a refused change must issue no PATCH, got %v", f2.order)
	}
}

// TestSCC_UpdateRejectsScopeMismatch: a rebuilt scope that differs from the bound
// providerId is refused (a forged binding must not redirect the mutation).
func TestSCC_UpdateRejectsScopeMismatch(t *testing.T) {
	f := newFakeSCC("ENABLED", "ENABLED", "DISABLED")
	srv := f.handler(t)
	defer srv.Close()
	d := sccDriver(t, srv)

	// bound pid names the project scope, but the impl operand names an org scope.
	impl := map[string]any{"tier": "PREMIUM", "organizationId": "123456"}
	res := d.updateSCC(sccCap, "prod", sccProviderID("projects", sccProject),
		sccAttrs(true, true, false), impl, []string{"protection.kubernetes"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "does not match") {
		t.Fatalf("a scope mismatch must refuse, got %+v", res)
	}
}

// TestSCC_DeleteDisables: delete DISABLES the governed modules (posture off);
// an already-disabled/absent posture is an idempotent success.
func TestSCC_DeleteDisables(t *testing.T) {
	f := newFakeSCC("ENABLED", "ENABLED", "ENABLED")
	srv := f.handler(t)
	defer srv.Close()
	d := sccDriver(t, srv)

	res := d.deleteSCC(sccCap, "prod", sccProviderID("projects", sccProject))
	if res.Status != "succeeded" {
		t.Fatalf("delete = %q (%s), want succeeded", res.Status, res.Reason)
	}
	for _, m := range sccModulesSorted() {
		if f.intended[m] != "DISABLED" {
			t.Fatalf("module %q not DISABLED after delete: %v", m, f.intended[m])
		}
	}

	// already gone -> idempotent success, no PATCH.
	f2 := newFakeSCC("", "", "")
	srv2 := f2.handler(t)
	defer srv2.Close()
	d2 := sccDriver(t, srv2)
	res2 := d2.deleteSCC(sccCap, "prod", sccProviderID("projects", sccProject))
	if res2.Status != "succeeded" || len(f2.order) != 0 {
		t.Fatalf("an absent posture delete must be an idempotent no-op success, got %+v order=%v", res2, f2.order)
	}
}

// TestSCC_Discover surfaces the pinned project's posture as
// capability.security.threatdetection.
func TestSCC_Discover(t *testing.T) {
	f := newFakeSCC("ENABLED", "ENABLED", "DISABLED")
	srv := f.handler(t)
	defer srv.Close()
	d := sccDriver(t, srv)

	found, _, err := d.discoverSCC("")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("discover found %d, want 1", len(found))
	}
	if found[0].ResourceType != sccCap {
		t.Fatalf("resource type = %q, want %s", found[0].ResourceType, sccCap)
	}
	if found[0].ProviderID != sccProviderID("projects", sccProject) {
		t.Fatalf("pid = %q", found[0].ProviderID)
	}

	// no SCC provisioned -> discover surfaces nothing.
	f2 := newFakeSCC("", "", "")
	srv2 := f2.handler(t)
	defer srv2.Close()
	d2 := sccDriver(t, srv2)
	found2, _, err := d2.discoverSCC("")
	if err != nil || len(found2) != 0 {
		t.Fatalf("an unprovisioned SCC must discover nothing, got %v err=%v", found2, err)
	}
}

// TestSCC_ProviderIDRoundTrip: the providerId parser is a security boundary — it
// round-trips valid scopes and refuses malformed ones.
func TestSCC_ProviderIDRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		st, id string
	}{{"projects", "my-project"}, {"organizations", "123456789"}} {
		pid := sccProviderID(tc.st, tc.id)
		st, id, err := splitSCCProviderID(pid)
		if err != nil || st != tc.st || id != tc.id {
			t.Fatalf("round-trip %q: st=%q id=%q err=%v", pid, st, id, err)
		}
	}
	for _, bad := range []string{
		"scc:projects:x", "gcp-scc:folders:1", "gcp-scc:projects:BAD/../x",
		"gcp-scc:organizations:notnum", "gcp-scc:projects", "gcp-scc:projects:a:b",
	} {
		if _, _, err := splitSCCProviderID(bad); err == nil {
			t.Fatalf("malformed providerId %q must be refused", bad)
		}
	}
}

// TestSCC_ClassifyChange: the posture is mutable; location/service/projection are
// unsupported. Every path carries an honest reason.
func TestSCC_ClassifyChange(t *testing.T) {
	want := map[string]string{
		"detection.enabled":     "mutable",
		"protection.kubernetes": "mutable",
		"protection.malware":    "mutable",
		"location.region":       "unsupported",
		"service.managed":       "unsupported",
		"cost.monthly":          "unsupported",
	}
	for p, w := range want {
		got, reason := classifySCCChange(p)
		if got != w {
			t.Errorf("classify %s = %q, want %q", p, got, w)
		}
		if reason == "" {
			t.Errorf("classify %s must carry an honest reason", p)
		}
	}
}

// TestSCC_CrossProjectRefused: a project-scoped providerId whose project differs
// from the pinned project is refused (no cross-project redirection).
func TestSCC_CrossProjectRefused(t *testing.T) {
	f := newFakeSCC("ENABLED", "ENABLED", "ENABLED")
	srv := f.handler(t)
	defer srv.Close()
	d := sccDriver(t, srv)

	if _, _, err := d.observeSCC(sccCap, sccProviderID("projects", "other-project")); err == nil {
		t.Fatal("a cross-project observe must be refused")
	}
}

// compile-time: the SCC methods satisfy the shapes the dispatch will call.
var _ = func() {
	var d *Driver
	_ = d.createSCC
	_ = d.observeSCC
	_ = d.updateSCC
	_ = d.deleteSCC
	_ = d.discoverSCC
	_ = provider.CreateResult{}
}
