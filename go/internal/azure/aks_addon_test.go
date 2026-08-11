package azure

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

func aksAddonAttrs() map[string]any {
	return map[string]any{
		"addon.name":      "keyvault-secrets-provider",
		"service.managed": true,
		"location.region": "westeurope",
	}
}

func aksAddonImpl() map[string]any {
	return map[string]any{"clusterName": "acme-aks", "resource_group": "rg1"}
}

func TestBuildAKSAddonHonors(t *testing.T) {
	p, err := BuildAKSAddon("prod", "csi", aksAddonAttrs(), aksAddonImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.AddonName != "keyvault-secrets-provider" || p.ProfileKey != "azureKeyvaultSecretsProvider" {
		t.Fatalf("plan addon = %+v", p)
	}
	if p.ClusterName != "acme-aks" || p.ResourceGrp != "rg1" {
		t.Fatalf("plan operands = %+v", p)
	}
}

// The load-bearing honest divergence from eks-addon: addon.version is REFUSED.
func TestBuildAKSAddonRefusesVersion(t *testing.T) {
	a := aksAddonAttrs()
	a["addon.version"] = "v1.5.0"
	_, err := BuildAKSAddon("prod", "csi", a, aksAddonImpl(), 1)
	if err == nil || !strings.Contains(err.Error(), "not independently settable") {
		t.Fatalf("addon.version must be refused honestly, got %v", err)
	}
}

func TestBuildAKSAddonRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"unknown-addon": {"addon.name": "vpc-cni"}, // EKS name, not an AKS profile
		"empty-addon":   {"addon.name": ""},
		"unmanaged":     {"service.managed": false},
		"unknown-attr":  {"addon.tier": "x"},
	}
	for name, extra := range cases {
		a := aksAddonAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildAKSAddon("prod", "csi", a, aksAddonImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// missing clusterName operand must refuse.
	if _, err := BuildAKSAddon("prod", "csi", aksAddonAttrs(), map[string]any{"resource_group": "rg1"}, 1); err == nil {
		t.Error("missing impl.clusterName must refuse")
	}
	// missing resource_group operand must refuse.
	if _, err := BuildAKSAddon("prod", "csi", aksAddonAttrs(), map[string]any{"clusterName": "acme-aks"}, 1); err == nil {
		t.Error("missing impl.resource_group must refuse")
	}
}

func TestBuildAKSAddonConfigPassthrough(t *testing.T) {
	impl := aksAddonImpl()
	impl["addon_config"] = map[string]any{"enableSecretRotation": "true"}
	p, err := BuildAKSAddon("prod", "csi", aksAddonAttrs(), impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Config["enableSecretRotation"] != "true" {
		t.Fatalf("config not carried: %+v", p.Config)
	}
}

func TestClassifyAKSAddonChange(t *testing.T) {
	if cls, _ := classifyAKSAddonChange("addon.name"); cls != "immutable" {
		t.Errorf("addon.name = %q", cls)
	}
	if cls, _ := classifyAKSAddonChange("addon.version"); cls != "unsupported" {
		t.Errorf("addon.version must be unsupported (AKS has no per-addon version), got %q", cls)
	}
	if cls, _ := classifyAKSAddonChange("service.managed"); cls != "unsupported" {
		t.Errorf("service.managed = %q", cls)
	}
}

func TestSplitAKSAddonProviderID(t *testing.T) {
	pid := aksAddonProviderID(testSub, "rg1", "acme-aks", "keyvault-secrets-provider")
	s, r, c, a, err := splitAKSAddonProviderID(pid)
	if err != nil || s != testSub || r != "rg1" || c != "acme-aks" || a != "keyvault-secrets-provider" {
		t.Fatalf("split = %q,%q,%q,%q err=%v", s, r, c, a, err)
	}
	// unknown addon component refuses.
	if _, _, _, _, err := splitAKSAddonProviderID("aks-addon:" + testSub + ":rg1:acme-aks:not-an-addon"); err == nil {
		t.Error("unknown addon component must refuse")
	}
	// wrong prefix refuses.
	if _, _, _, _, err := splitAKSAddonProviderID("gke-addon:x:y:z:w"); err == nil {
		t.Error("wrong prefix must refuse")
	}
}

// aksAddonServer is a STATEFUL fake: PUT records the azureKeyvaultSecretsProvider
// enable/disable, the cluster GET reflects it, provisioningState reports Succeeded.
// lastPut captures the most recent PUT body for config assertions.
func aksAddonServer(t *testing.T, initialEnabled, clusterFound bool, lastPut *[]byte) *httptest.Server {
	t.Helper()
	enabled := initialEnabled
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clusterDoc := func() string {
			en := "false"
			if enabled {
				en = "true"
			}
			return `{"name":"acme-aks","location":"westeurope","properties":{` +
				`"provisioningState":"Succeeded","addonProfiles":{` +
				`"azureKeyvaultSecretsProvider":{"enabled":` + en + `}}}}`
		}
		switch {
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/managedClusters/"):
			body, _ := io.ReadAll(r.Body)
			if lastPut != nil {
				*lastPut = body
			}
			var doc map[string]any
			_ = json.Unmarshal(body, &doc)
			switch aksAddonReadState(doc, "azureKeyvaultSecretsProvider") {
			case aksAddonOn:
				enabled = true
			case aksAddonOff:
				enabled = false
			}
			_, _ = w.Write([]byte(clusterDoc()))
		case r.Method == "GET" && strings.HasSuffix(strings.Split(r.URL.Path, "?")[0], "/managedClusters"):
			// subscription-level list (discover)
			_, _ = w.Write([]byte(`{"value":[{"id":"/subscriptions/` + testSub +
				`/resourceGroups/rg1/providers/Microsoft.ContainerService/managedClusters/acme-aks",` +
				`"name":"acme-aks","location":"westeurope","properties":{"provisioningState":"Succeeded",` +
				`"addonProfiles":{"azureKeyvaultSecretsProvider":{"enabled":` + boolStr(enabled) + `}}}}]}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/managedClusters/"):
			if !clusterFound {
				w.WriteHeader(404)
				return
			}
			_, _ = w.Write([]byte(clusterDoc()))
		default:
			w.WriteHeader(404)
		}
	}))
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func aksAddonDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	d.AKSLROTimeout = 2 * time.Second // keep AKS long-poll timeout paths fast (D264 class)
	return d
}

func TestCreateObserveDeleteAKSAddon(t *testing.T) {
	srv := aksAddonServer(t, false, true, nil)
	defer srv.Close()
	d := aksAddonDriver(t, srv)

	res := d.createAKSAddon("prod", "csi", aksAddonAttrs(), aksAddonImpl(), 1)
	wantPID := "aks-addon:" + testSub + ":rg1:acme-aks:keyvault-secrets-provider"
	if res.Status != "succeeded" || res.ProviderID != wantPID {
		t.Fatalf("create: %+v", res)
	}

	obs, diags, err := d.observeAKSAddon("csi", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["addon.name"] != "keyvault-secrets-provider" || got["service.managed"] != true || got["location.region"] != "westeurope" {
		t.Fatalf("observe: %+v", got)
	}
	// addon.version must NEVER be fabricated — only a diagnostic explains it.
	if _, has := got["addon.version"]; has {
		t.Fatalf("addon.version must not be observed, got %v", got["addon.version"])
	}
	if len(diags) == 0 || !strings.Contains(strings.Join(diags, " "), "cluster version") {
		t.Fatalf("expected a managed-by-cluster diag for addon.version, got %v", diags)
	}

	if del := d.deleteAKSAddon("csi", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
	// After disable the addon is not on the cluster, and D802 changed how that is SAID:
	// "nothing to observe" left the last reading taken while it was ON standing as the
	// freshest word, so posture kept calling it managed. The marker is the statement.
	obs, diags, _ = d.observeAKSAddon("csi", res.ProviderID)
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

func TestCreateAKSAddonConfigInPut(t *testing.T) {
	var put []byte
	srv := aksAddonServer(t, false, true, &put)
	defer srv.Close()
	d := aksAddonDriver(t, srv)
	impl := aksAddonImpl()
	impl["addon_config"] = map[string]any{"enableSecretRotation": "true"}
	if res := d.createAKSAddon("prod", "csi", aksAddonAttrs(), impl, 1); res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	if !strings.Contains(string(put), "enableSecretRotation") {
		t.Fatalf("PUT body missing addon config: %s", put)
	}
}

func TestCreateAKSAddonIdempotentWhenEnabled(t *testing.T) {
	srv := aksAddonServer(t, true, true, nil) // already enabled
	defer srv.Close()
	d := aksAddonDriver(t, srv)
	res := d.createAKSAddon("prod", "csi", aksAddonAttrs(), aksAddonImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("idempotent create: %+v", res)
	}
}

func TestCreateAKSAddonMissingClusterRefused(t *testing.T) {
	srv := aksAddonServer(t, false, false, nil) // cluster 404
	defer srv.Close()
	d := aksAddonDriver(t, srv)
	res := d.createAKSAddon("prod", "csi", aksAddonAttrs(), aksAddonImpl(), 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not found") {
		t.Fatalf("create on nonexistent cluster must refuse, got %+v", res)
	}
}

func TestDeleteAKSAddonIdempotentGone(t *testing.T) {
	srv := aksAddonServer(t, false, false, nil) // cluster gone
	defer srv.Close()
	d := aksAddonDriver(t, srv)
	pid := aksAddonProviderID(testSub, "rg1", "acme-aks", "keyvault-secrets-provider")
	if res := d.deleteAKSAddon("csi", "prod", pid); res.Status != "succeeded" {
		t.Fatalf("delete of gone cluster must be idempotent success, got %+v", res)
	}
}

func TestDiscoverAKSAddon(t *testing.T) {
	srv := aksAddonServer(t, true, true, nil)
	defer srv.Close()
	d := aksAddonDriver(t, srv)
	found, _, err := d.discoverAKSAddon("westeurope")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ResourceType != "capability.cluster.addon" ||
		found[0].ProviderID != "aks-addon:"+testSub+":rg1:acme-aks:keyvault-secrets-provider" {
		t.Fatalf("discover = %+v", found)
	}
}

func TestUpdateAKSAddonRefusesHonestly(t *testing.T) {
	d := NewDriver(testSub)
	pid := aksAddonProviderID(testSub, "rg1", "acme-aks", "keyvault-secrets-provider")
	res := d.updateAKSAddon("csi", "prod", pid, nil, nil, []string{"addon.version"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "no in-place AKS addon mapping") {
		t.Fatalf("update must refuse honestly, got %+v", res)
	}
}

// D801, the twin of the GKE case. ARM serializes false explicitly, so the proto3 trap
// does not apply here — but the unreadable-becomes-absent half did, and a delete
// answered SUCCEEDED about a control whose state nobody could read.
func TestAKSAddonUnreadableProfileIsNotAbsent(t *testing.T) {
	on := map[string]any{"properties": map[string]any{"addonProfiles": map[string]any{
		"azureKeyvaultSecretsProvider": map[string]any{"enabled": true}}}}
	if got := aksAddonReadState(on, "azureKeyvaultSecretsProvider"); got != aksAddonOn {
		t.Errorf("enabled profile read as %v", got)
	}
	off := map[string]any{"properties": map[string]any{"addonProfiles": map[string]any{
		"azureKeyvaultSecretsProvider": map[string]any{"enabled": false}}}}
	if got := aksAddonReadState(off, "azureKeyvaultSecretsProvider"); got != aksAddonOff {
		t.Errorf("disabled profile read as %v", got)
	}
	bad := map[string]any{"properties": map[string]any{"addonProfiles": map[string]any{
		"azureKeyvaultSecretsProvider": "yes"}}}
	if got := aksAddonReadState(bad, "azureKeyvaultSecretsProvider"); got != aksAddonUnreadable {
		t.Errorf("an unparseable profile read as %v", got)
	}
	badFlag := map[string]any{"properties": map[string]any{"addonProfiles": map[string]any{
		"azureKeyvaultSecretsProvider": map[string]any{"enabled": "yes"}}}}
	if got := aksAddonReadState(badFlag, "azureKeyvaultSecretsProvider"); got != aksAddonUnreadable {
		t.Errorf("a non-bool enabled flag read as %v", got)
	}
	if got := aksAddonReadState(map[string]any{}, "azureKeyvaultSecretsProvider"); got != aksAddonAbsent {
		t.Errorf("a missing profile read as %v", got)
	}
}

// D815. The Azure twin of the shared paging loop, and one guard the Google side does not
// need: an ARM nextLink is a COMPLETE URL chosen by the response, so following it blindly
// sends an Azure bearer token wherever a response says to.
func TestARMPagingFollowsNextLinkOnTheSameHost(t *testing.T) {
	asked := false
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			asked = true
			_, _ = w.Write([]byte(`{"value":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"value":[],"nextLink":"` + base + `/x?page=2"}`))
	}))
	defer srv.Close()
	base = srv.URL
	d := vnetTestDriver(t, srv)
	pages := 0
	if err := d.listAllARMPages("test.list", srv.URL+"/x", func([]byte) error {
		pages++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !asked || pages != 2 {
		t.Fatalf("nextLink not followed: asked=%v pages=%d", asked, pages)
	}
}

func TestARMPagingRefusesANextLinkToAnotherHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[],"nextLink":"https://attacker.example/steal?t=1"}`))
	}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	err := d.listAllARMPages("test.list", srv.URL+"/x", func([]byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "refusing to send an Azure token") {
		t.Fatalf("a nextLink to another host must be refused, got %v", err)
	}
}
