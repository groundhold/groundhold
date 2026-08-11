package gcp

import (
	"encoding/json"
	"groundhold/internal/provider"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func gkeAddonAttrs() map[string]any {
	return map[string]any{
		"addon.name":      "gce-pd-csi-driver",
		"service.managed": true,
		"location.region": "us-central1",
	}
}

func gkeAddonImpl() map[string]any {
	return map[string]any{"clusterName": "acme-eks", "location": "us-central1"}
}

func TestBuildGKEAddonHonors(t *testing.T) {
	p, err := BuildGKEAddon("acme-prod", "prod", "csi", gkeAddonAttrs(), gkeAddonImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.AddonName != "gce-pd-csi-driver" || p.ClusterName != "acme-eks" || p.Location != "us-central1" {
		t.Fatalf("plan = %+v", p)
	}
	if p.Spec.field != "gcePersistentDiskCsiDriverConfig" || p.Spec.toggle != "enabled" {
		t.Fatalf("spec = %+v", p.Spec)
	}
}

// The load-bearing honest divergence from eks-addon: addon.version is REFUSED.
func TestBuildGKEAddonRefusesVersion(t *testing.T) {
	a := gkeAddonAttrs()
	a["addon.version"] = "v1.29.0"
	_, err := BuildGKEAddon("acme-prod", "prod", "csi", a, gkeAddonImpl(), 1)
	if err == nil || !strings.Contains(err.Error(), "not independently settable") {
		t.Fatalf("addon.version must be refused honestly, got %v", err)
	}
}

func TestBuildGKEAddonRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"unknown-addon": {"addon.name": "kube-proxy"}, // EKS name, not a GKE flag
		"empty-addon":   {"addon.name": ""},
		"unmanaged":     {"service.managed": false},
		"unknown-attr":  {"addon.tier": "x"},
	}
	for name, extra := range cases {
		a := gkeAddonAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildGKEAddon("acme-prod", "prod", "csi", a, gkeAddonImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// missing clusterName operand must refuse.
	if _, err := BuildGKEAddon("acme-prod", "prod", "csi", gkeAddonAttrs(), map[string]any{"location": "us-central1"}, 1); err == nil {
		t.Error("missing impl.clusterName must refuse")
	}
	// missing location (neither impl nor attr) must refuse.
	a := gkeAddonAttrs()
	delete(a, "location.region")
	if _, err := BuildGKEAddon("acme-prod", "prod", "csi", a, map[string]any{"clusterName": "c"}, 1); err == nil {
		t.Error("missing location must refuse")
	}
}

// Toggle polarity is the nuance a naive mapping would silently invert.
func TestGKEAddonTogglePolarity(t *testing.T) {
	// `enabled` polarity (CSI): enable -> {enabled:true}
	csi := gkeAddonRegistry["gce-pd-csi-driver"]
	frag := csi.configFragment(true)[csi.field].(map[string]any)
	if frag["enabled"] != true {
		t.Fatalf("csi enable fragment = %+v", frag)
	}
	// `disabled` polarity (HLB): enable -> {disabled:false}
	hlb := gkeAddonRegistry["http-load-balancing"]
	frag = hlb.configFragment(true)[hlb.field].(map[string]any)
	if frag["disabled"] != false {
		t.Fatalf("hlb enable fragment = %+v", frag)
	}
	// readState round-trips both polarities.
	ac := map[string]any{
		"gcePersistentDiskCsiDriverConfig": map[string]any{"enabled": true},
		"httpLoadBalancing":                map[string]any{"disabled": true}, // OFF
	}
	if got := csi.readState(ac); got != addonOn {
		t.Errorf("csi readState = %v", got)
	}
	if got := hlb.readState(ac); got != addonOff {
		t.Errorf("hlb readState = %v (disabled:true means OFF)", got)
	}
	// absent field -> absent (never blindly "disabled").
	if got := csi.readState(map[string]any{}); got != addonAbsent {
		t.Errorf("an absent field must be addonAbsent, got %v", got)
	}
}

// D801. Google serializes JSON the proto3 way and OMITS a field holding its default, so
// an addon that is ON through a `disabled` toggle comes back as an EMPTY OBJECT. Read as
// "not present", that made an enabled addon invisible to discover and made delete answer
// "never enabled" about a control that was still on.
func TestAddonEnabledThroughAnOmittedDisabledFlagIsRead(t *testing.T) {
	hlb := gkeAddonRegistry["http-load-balancing"]
	if got := hlb.readState(map[string]any{"httpLoadBalancing": map[string]any{}}); got != addonOn {
		t.Fatalf("an enabled addon (disabled:false omitted) read as %v", got)
	}
	// The same omission on an `enabled` toggle means the opposite, and must stay so.
	csi := gkeAddonRegistry["gce-pd-csi-driver"]
	if got := csi.readState(map[string]any{"gcePersistentDiskCsiDriverConfig": map[string]any{}}); got != addonOff {
		t.Fatalf("an addon with enabled:false omitted read as %v", got)
	}
}

func TestAddonUnreadableIsNotTheSameAsAbsent(t *testing.T) {
	hlb := gkeAddonRegistry["http-load-balancing"]
	if got := hlb.readState(map[string]any{"httpLoadBalancing": "yes"}); got != addonUnreadable {
		t.Errorf("a block that is not an object read as %v", got)
	}
	if got := hlb.readState(map[string]any{"httpLoadBalancing": map[string]any{"disabled": "no"}}); got != addonUnreadable {
		t.Errorf("a toggle that is not a bool read as %v", got)
	}
	if got := hlb.readState(map[string]any{}); got != addonAbsent {
		t.Errorf("a missing block read as %v", got)
	}
}

func TestClassifyGKEAddonChange(t *testing.T) {
	if cls, _ := classifyGKEAddonChange("addon.name"); cls != "immutable" {
		t.Errorf("addon.name = %q", cls)
	}
	if cls, _ := classifyGKEAddonChange("addon.version"); cls != "unsupported" {
		t.Errorf("addon.version must be unsupported (GKE has no per-addon version), got %q", cls)
	}
	if cls, _ := classifyGKEAddonChange("service.managed"); cls != "unsupported" {
		t.Errorf("service.managed = %q", cls)
	}
}

func TestSplitGKEAddonProviderID(t *testing.T) {
	pid := gkeAddonProviderID("acme-prod", "us-central1", "acme-eks", "gce-pd-csi-driver")
	p, l, c, a, err := splitGKEAddonProviderID(pid)
	if err != nil || p != "acme-prod" || l != "us-central1" || c != "acme-eks" || a != "gce-pd-csi-driver" {
		t.Fatalf("split = %q,%q,%q,%q err=%v", p, l, c, a, err)
	}
	// unknown addon component refuses.
	if _, _, _, _, err := splitGKEAddonProviderID("gke-addon:acme-prod:us-central1:c:not-an-addon"); err == nil {
		t.Error("unknown addon component must refuse")
	}
	if _, _, _, _, err := splitGKEAddonProviderID("eks-addon:x:y:z"); err == nil {
		t.Error("wrong prefix must refuse")
	}
}

// gkeAddonServer is a STATEFUL fake: setAddons records the CSI enable/disable,
// the cluster GET reflects it, operations poll DONE.
func gkeAddonServer(t *testing.T, initialEnabled bool, clusterFound bool) *httptest.Server {
	t.Helper()
	enabled := initialEnabled
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":setAddons"):
			body, _ := io.ReadAll(r.Body)
			var doc struct {
				AddonsConfig struct {
					CSI struct {
						Enabled bool `json:"enabled"`
					} `json:"gcePersistentDiskCsiDriverConfig"`
				} `json:"addonsConfig"`
			}
			_ = json.Unmarshal(body, &doc)
			enabled = doc.AddonsConfig.CSI.Enabled
			_, _ = w.Write([]byte(`{"name":"operation-abc"}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
			_, _ = w.Write([]byte(`{"status":"DONE"}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/clusters/"):
			if !clusterFound {
				w.WriteHeader(404)
				return
			}
			en := "false"
			if enabled {
				en = "true"
			}
			_, _ = w.Write([]byte(`{"name":"acme-eks","location":"us-central1","status":"RUNNING",` +
				`"addonsConfig":{"gcePersistentDiskCsiDriverConfig":{"enabled":` + en + `}}}`))
		default:
			w.WriteHeader(404)
		}
	}))
}

func gkeAddonDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	gkeAddonBaseOverride = srv.URL
	t.Cleanup(func() { gkeAddonBaseOverride = "" })
	d := NewDriver("acme-prod")
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	d.GKELROTimeout = 2 * time.Second // keep the GKE addon LRO poll fast (default is 60m)
	return d
}

func TestCreateObserveDeleteGKEAddon(t *testing.T) {
	srv := gkeAddonServer(t, false, true)
	defer srv.Close()
	d := gkeAddonDriver(t, srv)

	res := d.createGKEAddon("prod", "csi", gkeAddonAttrs(), gkeAddonImpl(), 1)
	if res.Status != "succeeded" || res.ProviderID != "gke-addon:acme-prod:us-central1:acme-eks:gce-pd-csi-driver" {
		t.Fatalf("create: %+v", res)
	}

	obs, diags, err := d.observeGKEAddon("csi", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["addon.name"] != "gce-pd-csi-driver" || got["service.managed"] != true || got["location.region"] != "us-central1" {
		t.Fatalf("observe: %+v", got)
	}
	// addon.version must NEVER be fabricated — only a diagnostic explains it.
	if _, has := got["addon.version"]; has {
		t.Fatalf("addon.version must not be observed, got %v", got["addon.version"])
	}
	if len(diags) == 0 || !strings.Contains(strings.Join(diags, " "), "cluster version") {
		t.Fatalf("expected a managed-by-cluster diag for addon.version, got %v", diags)
	}

	if del := d.deleteGKEAddon("csi", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
	// After disable the addon is not on the cluster, and D802 changed how that is SAID:
	// "nothing to observe" left the last reading taken while it was ON standing as the
	// freshest word, so posture kept calling it managed. The marker is the statement.
	obs, diags, _ = d.observeGKEAddon("csi", res.ProviderID)
	if len(diags) == 0 {
		t.Fatalf("after disable, expected a diagnostic, got obs=%v", obs)
	}
	gone := false
	for _, o := range obs {
		if o.Path == provider.ResourceAbsentPath && o.Value == true {
			gone = true
		}
	}
	if !gone {
		t.Fatalf("after disable, the addon was not marked absent: %v", obs)
	}
}

func TestCreateGKEAddonIdempotentWhenEnabled(t *testing.T) {
	srv := gkeAddonServer(t, true, true) // already enabled
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	res := d.createGKEAddon("prod", "csi", gkeAddonAttrs(), gkeAddonImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("idempotent create: %+v", res)
	}
}

func TestCreateGKEAddonMissingClusterRefused(t *testing.T) {
	srv := gkeAddonServer(t, false, false) // cluster 404
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	res := d.createGKEAddon("prod", "csi", gkeAddonAttrs(), gkeAddonImpl(), 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not found") {
		t.Fatalf("create on nonexistent cluster must refuse, got %+v", res)
	}
}

func TestDeleteGKEAddonIdempotentGone(t *testing.T) {
	srv := gkeAddonServer(t, false, false) // cluster gone
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	pid := gkeAddonProviderID("acme-prod", "us-central1", "acme-eks", "gce-pd-csi-driver")
	if res := d.deleteGKEAddon("csi", "prod", pid); res.Status != "succeeded" {
		t.Fatalf("delete of gone cluster must be idempotent success, got %+v", res)
	}
}

func TestDiscoverGKEAddon(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/locations/-/clusters"):
			_, _ = w.Write([]byte(`{"clusters":[{"name":"acme-eks","location":"us-central1","addonsConfig":{` +
				`"gcePersistentDiskCsiDriverConfig":{"enabled":true},` +
				`"httpLoadBalancing":{"disabled":true}}}]}`)) // HLB OFF -> not discovered
		case strings.Contains(r.URL.Path, "/clusters/"):
			_, _ = w.Write([]byte(`{"name":"acme-eks","location":"us-central1","addonsConfig":{` +
				`"gcePersistentDiskCsiDriverConfig":{"enabled":true}}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	found, _, err := d.discoverGKEAddon("us-central1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ResourceType != "capability.cluster.addon" ||
		found[0].ProviderID != "gke-addon:acme-prod:us-central1:acme-eks:gce-pd-csi-driver" {
		t.Fatalf("discover = %+v", found)
	}
}

// D801. An addonsConfig block the driver cannot parse used to be folded into "never
// enabled — idempotent", so delete answered SUCCEEDED about a control whose state nobody
// could read. Refusing to claim a removal that may not have happened is the point.
func TestDeleteGKEAddonRefusesToClaimRemovalOfAnUnreadableAddon(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/clusters/") {
			_, _ = w.Write([]byte(`{"name":"acme-eks","location":"us-central1",` +
				`"resourceLabels":{"groundhold-capability":"csi","groundhold-environment":"prod"},` +
				`"addonsConfig":{"gcePersistentDiskCsiDriverConfig":"yes"}}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	pid := gkeAddonProviderID("acme-prod", "us-central1", "acme-eks", "gce-pd-csi-driver")
	res := d.deleteGKEAddon("csi", "prod", pid)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "not readable") {
		t.Fatalf("an unreadable addon block must not yield a claimed removal, got %+v", res)
	}
}

// D813. Every Google API pages the same way, so the LOOP is shared and the decode stays
// with the caller — the shapes differ per API, and a helper that decoded for them would
// have to know all of them. What was shared was the bug: each sweep read page one.
//
// The assertion is the one the AWS side had to learn: was the second page ASKED for,
// with the token the first handed back?
func TestGCPListAllPagesFollowsTheToken(t *testing.T) {
	asked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("pageToken") == "p2" {
			asked = true
			_, _ = w.Write([]byte(`{"items":{}}`))
			return
		}
		_, _ = w.Write([]byte(`{"items":{},"nextPageToken":"p2"}`))
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	pages := 0
	if err := d.listAllPages("test.list", srv.URL+"/projects/acme-prod/locations/-/clusters", func([]byte) error {
		pages++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !asked {
		t.Fatal("a nextPageToken was handed back and never used")
	}
	if pages != 2 {
		t.Fatalf("collect ran %d time(s) — every page must reach the caller", pages)
	}
}

// A provider that keeps returning the same token must not spin forever, and must not
// hand back the pages read so far as if they were the whole list (D141 gentleness).
func TestGCPListAllPagesRefusesAnEndlessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":{},"nextPageToken":"always"}`))
	}))
	defer srv.Close()
	d := gkeAddonDriver(t, srv)
	err := d.listAllPages("test.list", srv.URL+"/projects/acme-prod/locations/-/clusters", func([]byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("an endless token must stop loudly, got %v", err)
	}
}
