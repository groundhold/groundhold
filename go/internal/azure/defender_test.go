package azure

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

const defenderCap = "capability.security.threatdetection"

// fakePricing is one plan's stored state on the fake endpoint.
type fakePricing struct {
	tier    string // "" == plan not present -> 404
	subPlan string
	malware bool
}

// fakeDefender is a stateful fake Microsoft.Security/pricings endpoint. It serves
// GET/PUT on the three governed plans for one subscription, tracks tier/subPlan/malware,
// records the PUT order, and can inject an unreadable (500) read or a plan gate
// (Standard requested but the plan stays Free — the subscription does not offer it).
type fakeDefender struct {
	plans map[string]*fakePricing

	unreadable bool // 500 on every GET
	planGate   bool // a Standard PUT stays Free regardless (unavailable plan)

	order []string // PUT plan names, in order
}

func newFakeDefender(servers, containers, storage string) *fakeDefender {
	mk := func(tier string) *fakePricing {
		if tier == "" {
			return &fakePricing{} // 404
		}
		return &fakePricing{tier: tier}
	}
	return &fakeDefender{plans: map[string]*fakePricing{
		defenderPlanServers:    mk(servers),
		defenderPlanContainers: mk(containers),
		defenderPlanStorage:    mk(storage),
	}}
}

func (f *fakeDefender) planFromPath(path string) string {
	i := strings.LastIndexByte(path, '/')
	if i < 0 {
		return ""
	}
	return path[i+1:]
}

func (f *fakeDefender) marshal(plan string, p *fakePricing) []byte {
	props := map[string]any{"pricingTier": p.tier}
	if p.subPlan != "" {
		props["subPlan"] = p.subPlan
	}
	if p.malware {
		props["extensions"] = []map[string]any{
			{"name": defenderMalwareExtension, "isEnabled": "True"},
		}
	}
	out, _ := json.Marshal(map[string]any{"name": plan, "properties": props})
	return out
}

func (f *fakeDefender) handler(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plan := f.planFromPath(strings.SplitN(r.URL.Path, "?", 2)[0])
		p, ok := f.plans[plan]
		switch r.Method {
		case http.MethodGet:
			if f.unreadable {
				http.Error(w, `{"error":{"message":"backend"}}`, http.StatusInternalServerError)
				return
			}
			if !ok || p.tier == "" {
				http.Error(w, `{"error":{"message":"NotFound"}}`, http.StatusNotFound)
				return
			}
			_, _ = w.Write(f.marshal(plan, p))
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			var body struct {
				Properties struct {
					PricingTier string `json:"pricingTier"`
					SubPlan     string `json:"subPlan"`
					Extensions  []struct {
						Name      string `json:"name"`
						IsEnabled string `json:"isEnabled"`
					} `json:"extensions"`
				} `json:"properties"`
			}
			_ = json.Unmarshal(b, &body)
			f.order = append(f.order, plan)
			if !ok {
				p = &fakePricing{}
				f.plans[plan] = p
			}
			p.tier = body.Properties.PricingTier
			if f.planGate && p.tier == "Standard" {
				p.tier = "Free" // subscription does not offer this plan
			}
			p.subPlan = body.Properties.SubPlan
			p.malware = false
			for _, e := range body.Properties.Extensions {
				if e.Name == defenderMalwareExtension && strings.EqualFold(e.IsEnabled, "True") {
					p.malware = true
				}
			}
			_, _ = w.Write(f.marshal(plan, p))
		default:
			http.Error(w, `{"error":{"message":"method"}}`, http.StatusMethodNotAllowed)
		}
	}))
}

func defenderDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	return d
}

func defenderAttrs(enabled, k8s, malware bool) map[string]any {
	return map[string]any{
		"location.region":       "global",
		"detection.enabled":     enabled,
		"protection.kubernetes": k8s,
		"protection.malware":    malware,
		"service.managed":       true,
	}
}

// --- pure builder refusals ---

func TestDefender_BuildRefusesUnmapped(t *testing.T) {
	attrs := defenderAttrs(true, true, false)
	attrs["encryption.atRest"] = true
	if _, err := BuildDefender("prod", defenderCap, attrs, nil, 1); err == nil {
		t.Fatal("an unmapped attribute must be refused, not silently dropped")
	}
}

func TestDefender_BuildRequiresEnabled(t *testing.T) {
	attrs := map[string]any{"location.region": "global", "protection.kubernetes": true, "service.managed": true}
	if _, err := BuildDefender("prod", defenderCap, attrs, nil, 1); err == nil {
		t.Fatal("a missing detection.enabled must be refused")
	}
}

func TestDefender_BuildRefusesRegionalLocation(t *testing.T) {
	attrs := defenderAttrs(true, true, false)
	attrs["location.region"] = "eastus"
	if _, err := BuildDefender("prod", defenderCap, attrs, nil, 1); err == nil {
		t.Fatal("a regional location.region must be refused for a subscription-scoped service")
	}
}

func TestDefender_BuildContradictoryPosture(t *testing.T) {
	if _, err := BuildDefender("prod", defenderCap, defenderAttrs(false, true, false), nil, 1); err == nil {
		t.Fatal("detection.enabled=false with protection true must be refused")
	}
}

func TestDefender_BuildRefusesBadSubPlan(t *testing.T) {
	impl := map[string]any{"serversSubPlan": "P9"}
	if _, err := BuildDefender("prod", defenderCap, defenderAttrs(true, false, false), impl, 1); err == nil {
		t.Fatal("an invalid serversSubPlan operand must be refused")
	}
}

func TestDefender_BuildDesiredPlans(t *testing.T) {
	p, err := BuildDefender("prod", defenderCap, defenderAttrs(true, true, true), nil, 1)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	dp := p.desiredPlans()
	if dp[defenderPlanServers].tier != "Standard" || dp[defenderPlanServers].subPlan != "P2" {
		t.Fatalf("servers = %+v, want Standard/P2", dp[defenderPlanServers])
	}
	if dp[defenderPlanContainers].tier != "Standard" {
		t.Fatalf("containers = %+v, want Standard", dp[defenderPlanContainers])
	}
	if dp[defenderPlanStorage].tier != "Standard" || !dp[defenderPlanStorage].malware ||
		dp[defenderPlanStorage].subPlan != defenderStorageSubPlan {
		t.Fatalf("storage = %+v, want Standard+malware+subplan", dp[defenderPlanStorage])
	}

	// detection.enabled=true, protection off -> only servers Standard.
	p2, _ := BuildDefender("prod", defenderCap, defenderAttrs(true, false, false), nil, 1)
	dp2 := p2.desiredPlans()
	if dp2[defenderPlanServers].tier != "Standard" {
		t.Fatalf("servers should be Standard, got %+v", dp2[defenderPlanServers])
	}
	if dp2[defenderPlanContainers].tier != "Free" || dp2[defenderPlanStorage].tier != "Free" {
		t.Fatalf("protection surfaces should be Free, got containers=%+v storage=%+v",
			dp2[defenderPlanContainers], dp2[defenderPlanStorage])
	}
}

// --- network shell (four-valued) ---

func TestDefender_CreateConverges(t *testing.T) {
	f := newFakeDefender("Free", "Free", "Free")
	srv := f.handler(t)
	defer srv.Close()
	d := defenderDriver(t, srv)

	res := d.createDefender("prod", defenderCap, defenderAttrs(true, true, false), nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if res.ProviderID != defenderProviderID(testSub) {
		t.Fatalf("pid = %q, want %q", res.ProviderID, defenderProviderID(testSub))
	}
	if f.plans[defenderPlanServers].tier != "Standard" || f.plans[defenderPlanContainers].tier != "Standard" {
		t.Fatalf("servers/containers not Standard after converge: %+v", f.plans)
	}
	if f.plans[defenderPlanStorage].tier != "Free" {
		t.Fatalf("storage should stay Free (protection.malware=false), got %v", f.plans[defenderPlanStorage].tier)
	}
}

func TestDefender_CreateEnablesMalware(t *testing.T) {
	f := newFakeDefender("Free", "Free", "Free")
	srv := f.handler(t)
	defer srv.Close()
	d := defenderDriver(t, srv)

	res := d.createDefender("prod", defenderCap, defenderAttrs(true, false, true), nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if f.plans[defenderPlanStorage].tier != "Standard" || !f.plans[defenderPlanStorage].malware {
		t.Fatalf("storage should be Standard + malware, got %+v", f.plans[defenderPlanStorage])
	}
}

func TestDefender_CreateIdempotentNoOp(t *testing.T) {
	f := newFakeDefender("Standard", "Standard", "Free")
	f.plans[defenderPlanServers].subPlan = "P2"
	srv := f.handler(t)
	defer srv.Close()
	d := defenderDriver(t, srv)

	res := d.createDefender("prod", defenderCap, defenderAttrs(true, true, false), nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("idempotent create = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if len(f.order) != 0 {
		t.Fatalf("an already-converged posture must issue no PUT, got %v", f.order)
	}
}

func TestDefender_CreatePlanGateUnknown(t *testing.T) {
	f := newFakeDefender("Free", "Free", "Free")
	f.planGate = true
	srv := f.handler(t)
	defer srv.Close()
	d := defenderDriver(t, srv)

	res := d.createDefender("prod", defenderCap, defenderAttrs(true, false, false), nil, 1)
	if res.Status != "unknown" || res.ProviderID != defenderProviderID(testSub) {
		t.Fatalf("a plan-gated Standard must be unknown WITH the pid, got %+v", res)
	}
	if !strings.Contains(res.Reason, "Standard") {
		t.Fatalf("reason must explain the tier gap, got %q", res.Reason)
	}
}

func TestDefender_ObserveReverseMap(t *testing.T) {
	f := newFakeDefender("Standard", "Standard", "Standard")
	f.plans[defenderPlanStorage].malware = true
	srv := f.handler(t)
	defer srv.Close()
	d := defenderDriver(t, srv)

	obs, _, err := d.observeDefender(defenderCap, defenderProviderID(testSub))
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
	if m["detection.enabled"] != true || m["protection.kubernetes"] != true || m["protection.malware"] != true {
		t.Fatalf("posture reverse-map wrong: %v", m)
	}
	if m["service.managed"] != true {
		t.Fatalf("service.managed missing")
	}
}

// malware Standard but the extension NOT enabled must observe protection.malware=false.
func TestDefender_ObserveMalwareNeedsExtension(t *testing.T) {
	f := newFakeDefender("Standard", "Free", "Standard") // storage Standard, no extension
	srv := f.handler(t)
	defer srv.Close()
	d := defenderDriver(t, srv)

	obs, _, err := d.observeDefender(defenderCap, defenderProviderID(testSub))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "protection.malware" && o.Value != false {
			t.Fatalf("Standard storage without the malware extension must observe protection.malware=false, got %v", o.Value)
		}
	}
}

func TestDefender_ObserveNotFound(t *testing.T) {
	f := newFakeDefender("", "", "") // all 404
	srv := f.handler(t)
	defer srv.Close()
	d := defenderDriver(t, srv)

	obs, diags, err := d.observeDefender(defenderCap, defenderProviderID(testSub))
	if err != nil {
		t.Fatalf("not-found must not error, got %v", err)
	}
	// Corrected with D521: this asserted SILENCE for an absent bound resource,
	// which is the defect F-LC3 exists to prevent.
	if !absentMarked(obs) {
		t.Fatalf("not-found must mark the resource absent, got %v", obs)
	}
	if len(diags) == 0 || !strings.Contains(diags[0], "bound resource is gone") {
		t.Fatalf("not-found must carry a gone diagnostic, got %v", diags)
	}
}

func TestDefender_ObserveUnreadableErrors(t *testing.T) {
	f := newFakeDefender("Standard", "Standard", "Standard")
	f.unreadable = true
	srv := f.handler(t)
	defer srv.Close()
	d := defenderDriver(t, srv)

	if _, _, err := d.observeDefender(defenderCap, defenderProviderID(testSub)); err == nil {
		t.Fatal("an unreadable plan must return an error, not a fabricated absence")
	}
}

func TestDefender_UpdateInPlace(t *testing.T) {
	f := newFakeDefender("Standard", "Free", "Free")
	f.plans[defenderPlanServers].subPlan = "P2"
	srv := f.handler(t)
	defer srv.Close()
	d := defenderDriver(t, srv)

	res := d.updateDefender(defenderCap, "prod", defenderProviderID(testSub),
		defenderAttrs(true, true, false), nil, []string{"protection.kubernetes"})
	if res.Status != "succeeded" {
		t.Fatalf("update = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if f.plans[defenderPlanContainers].tier != "Standard" {
		t.Fatalf("containers should be Standard after the toggle, got %v", f.plans[defenderPlanContainers].tier)
	}

	// unsupported change refuses before mutating.
	f2 := newFakeDefender("Standard", "Standard", "Free")
	srv2 := f2.handler(t)
	defer srv2.Close()
	d2 := defenderDriver(t, srv2)
	res2 := d2.updateDefender(defenderCap, "prod", defenderProviderID(testSub),
		defenderAttrs(true, true, false), nil, []string{"location.region"})
	if res2.Status != "failed" {
		t.Fatalf("an unsupported change must refuse, got %+v", res2)
	}
	if len(f2.order) != 0 {
		t.Fatalf("a refused change must issue no PUT, got %v", f2.order)
	}
}

func TestDefender_DeleteDisables(t *testing.T) {
	f := newFakeDefender("Standard", "Standard", "Standard")
	srv := f.handler(t)
	defer srv.Close()
	d := defenderDriver(t, srv)

	res := d.deleteDefender(defenderCap, "prod", defenderProviderID(testSub))
	if res.Status != "succeeded" {
		t.Fatalf("delete = %q (%s), want succeeded", res.Status, res.Reason)
	}
	for _, plan := range defenderPlansSorted() {
		if f.plans[plan].tier != "Free" {
			t.Fatalf("plan %q not Free after delete: %v", plan, f.plans[plan].tier)
		}
	}

	// already off -> idempotent success, no PUT.
	f2 := newFakeDefender("Free", "Free", "Free")
	srv2 := f2.handler(t)
	defer srv2.Close()
	d2 := defenderDriver(t, srv2)
	res2 := d2.deleteDefender(defenderCap, "prod", defenderProviderID(testSub))
	if res2.Status != "succeeded" || len(f2.order) != 0 {
		t.Fatalf("an already-off posture delete must be an idempotent no-op success, got %+v order=%v", res2, f2.order)
	}
}

func TestDefender_Discover(t *testing.T) {
	f := newFakeDefender("Standard", "Standard", "Free")
	srv := f.handler(t)
	defer srv.Close()
	d := defenderDriver(t, srv)

	found, _, err := d.discoverDefender("")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("discover found %d, want 1", len(found))
	}
	if found[0].ResourceType != defenderCap || found[0].ProviderID != defenderProviderID(testSub) {
		t.Fatalf("discover shape wrong: %+v", found[0])
	}

	// no Defender provisioned -> discover surfaces nothing.
	f2 := newFakeDefender("", "", "")
	srv2 := f2.handler(t)
	defer srv2.Close()
	d2 := defenderDriver(t, srv2)
	found2, _, err := d2.discoverDefender("")
	if err != nil || len(found2) != 0 {
		t.Fatalf("an unprovisioned Defender must discover nothing, got %v err=%v", found2, err)
	}
}

func TestDefender_ProviderIDRoundTrip(t *testing.T) {
	pid := defenderProviderID(testSub)
	sub, err := splitDefenderProviderID(pid)
	if err != nil || sub != testSub {
		t.Fatalf("round-trip %q: sub=%q err=%v", pid, sub, err)
	}
	for _, bad := range []string{
		"scc:x", "defender:not-a-guid", "defender", "defender:a:b",
	} {
		if _, err := splitDefenderProviderID(bad); err == nil {
			t.Fatalf("malformed providerId %q must be refused", bad)
		}
	}
}

func TestDefender_CrossSubscriptionRefused(t *testing.T) {
	f := newFakeDefender("Standard", "Standard", "Standard")
	srv := f.handler(t)
	defer srv.Close()
	d := defenderDriver(t, srv)

	other := defenderProviderID("00000000-0000-0000-0000-0000000000ff")
	if _, _, err := d.observeDefender(defenderCap, other); err == nil {
		t.Fatal("a cross-subscription observe must be refused")
	}
}

func TestDefender_ClassifyChange(t *testing.T) {
	want := map[string]string{
		"detection.enabled":     "mutable",
		"protection.kubernetes": "mutable",
		"protection.malware":    "mutable",
		"location.region":       "unsupported",
		"service.managed":       "unsupported",
		"cost.monthly":          "unsupported",
	}
	for p, w := range want {
		got, reason := classifyDefenderChange(p)
		if got != w {
			t.Errorf("classify %s = %q, want %q", p, got, w)
		}
		if reason == "" {
			t.Errorf("classify %s must carry an honest reason", p)
		}
	}
}

// compile-time: the Defender methods satisfy the shapes the dispatch will call.
var _ = func() {
	var d *Driver
	_ = d.createDefender
	_ = d.observeDefender
	_ = d.updateDefender
	_ = d.deleteDefender
	_ = d.discoverDefender
	_ = provider.CreateResult{}
}
