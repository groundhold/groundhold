package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func laAttrs() map[string]any {
	return map[string]any{
		"location.region": "eastus",
		"retention.days":  "90d",
		"service.managed": true,
	}
}

func laImpl() map[string]any {
	return map[string]any{"resource_group": "rg1"}
}

func TestBuildLogAnalyticsHonors(t *testing.T) {
	p, err := BuildLogAnalytics("prod", "app-logs", laAttrs(), laImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Region != "eastus" || p.RetentionDays != 90 || p.Sku != "PerGB2018" {
		t.Fatalf("plan = %+v", p)
	}
	props := p.createBody(map[string]any{})["properties"].(map[string]any)
	if props["retentionInDays"] != 90 {
		t.Fatalf("props = %+v", props)
	}
	if props["sku"].(map[string]any)["name"] != "PerGB2018" {
		t.Fatalf("sku = %+v", props["sku"])
	}
}

// retention.days is OPTIONAL — a workspace has a bounded service default, so an absent
// retention is honored (retentionInDays simply not set) rather than refused.
func TestBuildLogAnalyticsRetentionOptional(t *testing.T) {
	a := map[string]any{"location.region": "eastus", "service.managed": true}
	p, err := BuildLogAnalytics("prod", "app-logs", a, laImpl(), 1)
	if err != nil {
		t.Fatalf("absent retention must be honored: %v", err)
	}
	if p.RetentionDays != 0 {
		t.Fatalf("expected unset retention, got %d", p.RetentionDays)
	}
	if _, set := p.createBody(map[string]any{})["properties"].(map[string]any)["retentionInDays"]; set {
		t.Fatal("retentionInDays must be absent when unset")
	}
}

func TestBuildLogAnalyticsSkuOperand(t *testing.T) {
	a := laAttrs()
	i := map[string]any{"resource_group": "rg1", "sku": "CapacityReservation"}
	p, err := BuildLogAnalytics("prod", "app-logs", a, i, 1)
	if err != nil || p.Sku != "CapacityReservation" {
		t.Fatalf("sku operand not honored: %+v err=%v", p, err)
	}
}

func TestBuildLogAnalyticsRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"location.region": "eastus", "service.managed": true}
	}
	cases := map[string]map[string]any{
		"retention-below-min": {"retention.days": "7d"},
		"retention-above-max": {"retention.days": "800d"},
		"retention-not-days":  {"retention.days": "36h"}, // 1.5 days -> fractional
		"retention-not-dur":   {"retention.days": 90},    // bare number, not a duration
		"cmk-refused":         {"encryption.customerManagedKeys": true},
		"unmanaged":           {"service.managed": false},
		"unknown-attr":        {"log.format": "json"},
	}
	for name, extra := range cases {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildLogAnalytics("prod", "app-logs", a, laImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// missing region must refuse
	if _, err := BuildLogAnalytics("prod", "app-logs",
		map[string]any{"retention.days": "90d", "service.managed": true}, laImpl(), 1); err == nil {
		t.Error("missing location.region must refuse")
	}
	// CMK=false is honored (default provider key)
	a := base()
	a["encryption.customerManagedKeys"] = false
	if _, err := BuildLogAnalytics("prod", "app-logs", a, laImpl(), 1); err != nil {
		t.Errorf("CMK=false must be honored: %v", err)
	}
}

// The retention range boundaries are inclusive.
func TestBuildLogAnalyticsRetentionBounds(t *testing.T) {
	for _, d := range []string{"30d", "730d"} {
		a := laAttrs()
		a["retention.days"] = d
		if _, err := BuildLogAnalytics("prod", "app-logs", a, laImpl(), 1); err != nil {
			t.Errorf("%s must be accepted: %v", d, err)
		}
	}
}

func laServer(t *testing.T, tagCap string, retention int) *httptest.Server {
	t.Helper()
	retStr := ""
	if retention > 0 {
		retStr = `"retentionInDays":` + itoaLA(retention) + `,`
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT", "PATCH":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded",` + retStr +
					`"sku":{"name":"PerGB2018"}}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func itoaLA(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func laDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

// TestObserveLogAnalyticsCMKConfirmedAgainstCluster pins D985: a workspace linked to a
// dedicated cluster reports customerManagedKeys=true ONLY when that cluster actually
// carries a key vault key. A linked cluster is a prerequisite for BYOK, not proof of it
// (a commitment-tier cluster can run on Microsoft's platform key), so the linkage alone
// must not certify a control that does not exist.
func TestObserveLogAnalyticsCMKConfirmedAgainstCluster(t *testing.T) {
	clusterID := "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.OperationalInsights/clusters/pv-cl"
	newSrv := func(keyName string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/clusters/"):
				kv := ""
				if keyName != "" {
					kv = `"keyVaultProperties":{"keyName":"` + keyName + `","keyVaultUri":""}`
				}
				_, _ = w.Write([]byte(`{"properties":{` + kv + `}}`))
			case r.Method == "GET": // the workspace
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"app-logs","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","features":{"clusterResourceId":"` + clusterID + `"}}}`))
			default:
				w.WriteHeader(404)
			}
		}))
	}
	pid := laProviderID(testSub, "rg1", azResourceName("pv-la", "prod", "app-logs", 1))

	// (a) the linked cluster carries a key → CMK is confirmed true.
	srv := newSrv("mykey")
	d := laDriver(t, srv)
	obs, _, err := d.observeLogAnalytics("app-logs", pid)
	srv.Close()
	if err != nil {
		t.Fatal(err)
	}
	cmk := false
	for _, o := range obs {
		if o.Path == "encryption.customerManagedKeys" && o.Value == true {
			cmk = true
		}
	}
	if !cmk {
		t.Fatalf("a cluster carrying a key vault key must report CMK=true, got %+v", obs)
	}

	// (b) the linked cluster carries NO key → CMK must NOT be emitted (false BYOK), and a
	// diagnostic must explain why.
	srv2 := newSrv("")
	d2 := laDriver(t, srv2)
	obs2, diags2, err := d2.observeLogAnalytics("app-logs", pid)
	srv2.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs2 {
		if o.Path == "encryption.customerManagedKeys" {
			t.Fatalf("a linked cluster with no key must NOT report CMK — false BYOK; got %+v", o)
		}
	}
	joined := strings.Join(diags2, " | ")
	if !strings.Contains(joined, "platform-managed") {
		t.Fatalf("expected a not-observed diagnostic for the keyless cluster, got %q", joined)
	}
}

func TestCreateObserveDeleteLogAnalytics(t *testing.T) {
	srv := laServer(t, "app-logs", 90)
	defer srv.Close()
	d := laDriver(t, srv)
	res := d.createLogAnalytics("prod", "app-logs", laAttrs(), laImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "laworkspace:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeLogAnalytics("app-logs", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eastus" || got["retention.days"] != "90d" || got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteLogAnalytics("app-logs", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestUpdateLogAnalyticsRetention(t *testing.T) {
	srv := laServer(t, "app-logs", 90)
	defer srv.Close()
	d := laDriver(t, srv)
	pid := laProviderID(testSub, "rg1", azResourceName("pv-la", "prod", "app-logs", 1))
	a := laAttrs()
	a["retention.days"] = "365d"
	res := d.updateLogAnalytics("app-logs", "prod", pid, a, laImpl(), []string{"retention.days"})
	if res.Status != "succeeded" {
		t.Fatalf("update retention: %+v", res)
	}
	// an unsupported path is refused rather than silently ignored.
	res = d.updateLogAnalytics("app-logs", "prod", pid, a, laImpl(), []string{"location.region"})
	if res.Status != "failed" {
		t.Fatalf("region update must refuse in place, got %+v", res)
	}
}

func TestUpdateLogAnalyticsForeignRefused(t *testing.T) {
	srv := laServer(t, "someone-else", 90)
	defer srv.Close()
	d := laDriver(t, srv)
	pid := laProviderID(testSub, "rg1", azResourceName("pv-la", "prod", "app-logs", 1))
	res := d.updateLogAnalytics("app-logs", "prod", pid, laAttrs(), laImpl(), []string{"retention.days"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign workspace must refuse update, got %+v", res)
	}
}

func TestDeleteLogAnalyticsForeignRefused(t *testing.T) {
	srv := laServer(t, "someone-else", 90)
	defer srv.Close()
	d := laDriver(t, srv)
	pid := laProviderID(testSub, "rg1", azResourceName("pv-la", "prod", "app-logs", 1))
	res := d.deleteLogAnalytics("app-logs", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign workspace must refuse delete, got %+v", res)
	}
}

func TestClassifyLogAnalyticsChange(t *testing.T) {
	if cls, _ := classifyLogAnalyticsChange("retention.days"); cls != "mutable" {
		t.Errorf("retention.days should be mutable, got %q", cls)
	}
	if cls, _ := classifyLogAnalyticsChange("location.region"); cls != "immutable" {
		t.Errorf("location.region should be immutable, got %q", cls)
	}
	if cls, _ := classifyLogAnalyticsChange("encryption.customerManagedKeys"); cls != "unsupported" {
		t.Errorf("CMK should be unsupported, got %q", cls)
	}
}

func TestObserveLogAnalyticsProviderIDValidation(t *testing.T) {
	d := NewDriver(testSub)
	if _, _, err := d.observeLogAnalytics("app-logs", "bogus:pid"); err == nil {
		t.Error("malformed providerId must error")
	}
}
