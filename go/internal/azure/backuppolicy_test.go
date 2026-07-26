package azure

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func backupPolicyAttrs() map[string]any {
	return map[string]any{
		"location.region":    "westeurope",
		"schedule.frequency": "24h",
		"retention.duration": "720h", // 30 days
		"copy.crossRegion":   false,
		"service.managed":    true,
	}
}

func backupPolicyImpl() map[string]any {
	return map[string]any{
		"backupVaultName": "bv-prod",
		"resource_group":  "rg1",
		"datasourceType":  "Microsoft.Compute/disks",
	}
}

func TestBuildBackupPolicyHonors(t *testing.T) {
	p, err := BuildBackupPolicy("prod", "dr-plan", backupPolicyAttrs(), backupPolicyImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.FreqStr != "24h" || p.Interval != "P1D" {
		t.Fatalf("cadence not mapped: %+v", p)
	}
	if p.RetentionDays != 30 || p.RetentionISO != "P30D" {
		t.Fatalf("retention not mapped: %+v", p)
	}
	if p.VaultName != "bv-prod" || p.ResourceGroup != "rg1" || p.DatasourceType != "Microsoft.Compute/disks" {
		t.Fatalf("operands not carried: %+v", p)
	}
	if p.DataStoreType != "VaultStore" || p.BackupType != "Incremental" {
		t.Fatalf("defaults wrong: %+v", p)
	}
	if !backupPolicyOurs(p.Name, "prod", "dr-plan") {
		t.Fatalf("name %q must carry ownership marker", p.Name)
	}
	// body shape: a schedule rule + a retention rule.
	body := p.createBody("2026-07-19T00:00:00Z")
	props := body["properties"].(map[string]any)
	if props["objectType"] != "BackupPolicy" {
		t.Fatalf("objectType = %v", props["objectType"])
	}
	rules := props["policyRules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("want 2 policy rules, got %d", len(rules))
	}
	br := rules[0].(map[string]any)
	ivals := br["trigger"].(map[string]any)["schedule"].(map[string]any)["repeatingTimeIntervals"].([]any)
	if ivals[0] != "R/2026-07-19T00:00:00Z/P1D" {
		t.Fatalf("recurrence = %v", ivals[0])
	}
	rr := rules[1].(map[string]any)
	if rr["lifecycles"].([]any)[0].(map[string]any)["deleteAfter"].(map[string]any)["duration"] != "P30D" {
		t.Fatalf("deleteAfter = %+v", rr)
	}
}

func TestBuildBackupPolicyHourlyOverride(t *testing.T) {
	a := backupPolicyAttrs()
	a["schedule.frequency"] = "6h"
	p, err := BuildBackupPolicy("prod", "dr-plan", a, backupPolicyImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Interval != "PT6H" {
		t.Fatalf("6h must map to PT6H, got %q", p.Interval)
	}
}

func TestBuildBackupPolicyRefusals(t *testing.T) {
	cases := map[string]struct {
		attrs map[string]any
		impl  map[string]any
	}{
		"cross-region-true":     {mergeBP(backupPolicyAttrs(), map[string]any{"copy.crossRegion": true}), backupPolicyImpl()},
		"dest-region-present":   {mergeBP(backupPolicyAttrs(), map[string]any{"copy.destinationRegion": "northeurope"}), backupPolicyImpl()},
		"unmanaged":             {mergeBP(backupPolicyAttrs(), map[string]any{"service.managed": false}), backupPolicyImpl()},
		"unknown-attr":          {mergeBP(backupPolicyAttrs(), map[string]any{"retention.locked": true}), backupPolicyImpl()},
		"bad-cadence":           {mergeBP(backupPolicyAttrs(), map[string]any{"schedule.frequency": "48h"}), backupPolicyImpl()},
		"sub-hour-cadence":      {mergeBP(backupPolicyAttrs(), map[string]any{"schedule.frequency": "30m"}), backupPolicyImpl()},
		"retention-not-days":    {mergeBP(backupPolicyAttrs(), map[string]any{"retention.duration": "36h"}), backupPolicyImpl()},
		"no-vault":              {backupPolicyAttrs(), map[string]any{"resource_group": "rg1", "datasourceType": "Microsoft.Compute/disks"}},
		"no-rg":                 {backupPolicyAttrs(), map[string]any{"backupVaultName": "bv-prod", "datasourceType": "Microsoft.Compute/disks"}},
		"no-datasource":         {backupPolicyAttrs(), map[string]any{"backupVaultName": "bv-prod", "resource_group": "rg1"}},
		"bad-datasource":        {backupPolicyAttrs(), map[string]any{"backupVaultName": "bv-prod", "resource_group": "rg1", "datasourceType": "disks"}},
		"bad-datastore":         {backupPolicyAttrs(), mergeBP(backupPolicyImpl(), map[string]any{"dataStoreType": "Nonsense"})},
		"bad-schedule-override": {backupPolicyAttrs(), mergeBP(backupPolicyImpl(), map[string]any{"scheduleInterval": "every-day"})},
	}
	for name, c := range cases {
		if _, err := BuildBackupPolicy("prod", "dr-plan", c.attrs, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// each required attribute, dropped, refuses.
	for _, drop := range []string{"location.region", "schedule.frequency", "retention.duration"} {
		a := backupPolicyAttrs()
		delete(a, drop)
		if _, err := BuildBackupPolicy("prod", "dr-plan", a, backupPolicyImpl(), 1); err == nil {
			t.Errorf("missing %s must refuse", drop)
		}
	}
}

func TestBackupPolicyClassifyChange(t *testing.T) {
	for _, p := range []string{"schedule.frequency", "retention.duration"} {
		if kind, _ := classifyBackupPolicyChange(p); kind != "mutable" {
			t.Errorf("%s should be mutable, got %q", p, kind)
		}
	}
	if kind, _ := classifyBackupPolicyChange("location.region"); kind != "immutable" {
		t.Errorf("location.region should be immutable, got %q", kind)
	}
	for _, p := range []string{"copy.crossRegion", "copy.destinationRegion", "service.managed"} {
		if kind, _ := classifyBackupPolicyChange(p); kind != "unsupported" {
			t.Errorf("%s should be unsupported, got %q", p, kind)
		}
	}
}

func TestBackupPolicyNameGenerations(t *testing.T) {
	g1 := BackupPolicyName("prod", "dr-plan", 1)
	g2 := BackupPolicyName("prod", "dr-plan", 2)
	if g1 == g2 {
		t.Fatal("generation must discriminate the name")
	}
	if !backupPolicyOurs(g1, "prod", "dr-plan") || !backupPolicyOurs(g2, "prod", "dr-plan") {
		t.Fatal("both generations must carry the ownership marker")
	}
	if backupPolicyOurs(g1, "prod", "other-cap") {
		t.Fatal("a different capability must not match ownership")
	}
}

func TestBackupPolicyProviderIDRoundTrip(t *testing.T) {
	pid := backupPolicyProviderID(testSub, "rg1", "bv-prod", "pv-dr")
	sub, rg, vault, policy, err := splitBackupPolicyProviderID(pid)
	if err != nil || sub != testSub || rg != "rg1" || vault != "bv-prod" || policy != "pv-dr" {
		t.Fatalf("round trip: %v %q %q %q %q", err, sub, rg, vault, policy)
	}
	for _, bad := range []string{"x:y:z", "backuppolicy:bad:rg:v:p", "notpolicy:" + testSub + ":rg:v:p"} {
		if _, _, _, _, err := splitBackupPolicyProviderID(bad); err == nil {
			t.Errorf("bad providerId %q must refuse", bad)
		}
	}
}

func backupPolicyDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = func() time.Time { return time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC) }
	return d
}

// backupPolicyServer serves the vault (location) and one policy back on GET.
func backupPolicyServer(t *testing.T, policy, region string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		isPolicy := strings.Contains(path, "/backupPolicies")
		switch {
		case r.Method == "GET" && !isPolicy: // the vault
			_, _ = w.Write([]byte(`{"location":"` + region + `"}`))
		case r.Method == "GET" && isPolicy: // the policy
			doc := map[string]any{
				"name": policy,
				"properties": map[string]any{
					"datasourceTypes": []string{"Microsoft.Compute/disks"},
					"policyRules": []any{
						map[string]any{
							"name": "BackupSchedule", "objectType": "AzureBackupRule",
							"trigger": map[string]any{"schedule": map[string]any{
								"repeatingTimeIntervals": []string{"R/2026-07-19T00:00:00Z/P1D"}}},
						},
						map[string]any{
							"name": "Default", "objectType": "AzureRetentionRule",
							"lifecycles": []any{map[string]any{
								"deleteAfter": map[string]any{"duration": "P30D"}}},
						},
					},
				},
			}
			b, _ := json.Marshal(doc)
			_, _ = w.Write(b)
		case r.Method == "PUT" && isPolicy:
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"name":"` + policy + `"}`))
		case r.Method == "DELETE" && isPolicy:
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestCreateObserveUpdateDeleteBackupPolicy(t *testing.T) {
	name := BackupPolicyName("prod", "dr-plan", 1)
	srv := backupPolicyServer(t, name, "westeurope")
	defer srv.Close()
	d := backupPolicyDriver(t, srv)

	res := d.createBackupPolicy("prod", "dr-plan", backupPolicyAttrs(), backupPolicyImpl(), 1)
	wantPID := backupPolicyProviderID(testSub, "rg1", "bv-prod", name)
	if res.Status != "succeeded" || res.ProviderID != wantPID {
		t.Fatalf("create: %+v", res)
	}

	obs, _, err := d.observeBackupPolicy("dr-plan", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "westeurope" || got["service.managed"] != true || got["copy.crossRegion"] != false {
		t.Fatalf("observe base = %+v", got)
	}
	if got["schedule.frequency"] != "24h" || got["retention.duration"] != "720h" {
		t.Fatalf("observe cadence/retention = %+v", got)
	}

	upd := d.updateBackupPolicy("dr-plan", "prod", res.ProviderID, backupPolicyAttrs(), backupPolicyImpl(), []string{"schedule.frequency"})
	if upd.Status != "succeeded" {
		t.Fatalf("update: %+v", upd)
	}

	del := d.deleteBackupPolicy("dr-plan", "prod", res.ProviderID)
	if del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestCreateBackupPolicyRegionMismatchRefused(t *testing.T) {
	name := BackupPolicyName("prod", "dr-plan", 1)
	srv := backupPolicyServer(t, name, "northeurope") // vault is elsewhere
	defer srv.Close()
	d := backupPolicyDriver(t, srv)
	res := d.createBackupPolicy("prod", "dr-plan", backupPolicyAttrs(), backupPolicyImpl(), 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "does not match the backup vault") {
		t.Fatalf("region mismatch must refuse, got %+v", res)
	}
}

func TestUpdateDeleteBackupPolicyForeignRefused(t *testing.T) {
	srv := backupPolicyServer(t, "someone-elses-policy", "westeurope")
	defer srv.Close()
	d := backupPolicyDriver(t, srv)
	pid := backupPolicyProviderID(testSub, "rg1", "bv-prod", "someone-elses-policy")
	if res := d.deleteBackupPolicy("dr-plan", "prod", pid); res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign delete must refuse, got %+v", res)
	}
	if res := d.updateBackupPolicy("dr-plan", "prod", pid, backupPolicyAttrs(), backupPolicyImpl(), []string{"schedule.frequency"}); res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign update must refuse, got %+v", res)
	}
}

func TestDiscoverBackupPolicy(t *testing.T) {
	name := BackupPolicyName("prod", "dr-plan", 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/backupVaults"):
			doc := map[string]any{"value": []any{map[string]any{
				"id":       "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.DataProtection/backupVaults/bv-prod",
				"name":     "bv-prod",
				"location": "westeurope",
			}}}
			b, _ := json.Marshal(doc)
			_, _ = w.Write(b)
		case strings.HasSuffix(path, "/backupPolicies"):
			doc := map[string]any{"value": []any{map[string]any{"name": name}}}
			b, _ := json.Marshal(doc)
			_, _ = w.Write(b)
		case strings.Contains(path, "/backupPolicies/"):
			doc := map[string]any{"name": name, "properties": map[string]any{"policyRules": []any{
				map[string]any{"name": "BackupSchedule", "objectType": "AzureBackupRule",
					"trigger": map[string]any{"schedule": map[string]any{"repeatingTimeIntervals": []string{"R/2026-07-19T00:00:00Z/P1D"}}}},
				map[string]any{"name": "Default", "objectType": "AzureRetentionRule",
					"lifecycles": []any{map[string]any{"deleteAfter": map[string]any{"duration": "P30D"}}}},
			}}}
			b, _ := json.Marshal(doc)
			_, _ = w.Write(b)
		case strings.Contains(path, "/backupVaults/"): // single vault (location read in observe)
			_, _ = w.Write([]byte(`{"location":"westeurope"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := backupPolicyDriver(t, srv)
	found, _, err := d.discoverBackupPolicy("westeurope")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ResourceType != "capability.backup.plan" {
		t.Fatalf("discover = %+v", found)
	}
	if found[0].ProviderID != backupPolicyProviderID(testSub, "rg1", "bv-prod", name) {
		t.Fatalf("discover providerId = %q", found[0].ProviderID)
	}
}

func mergeBP(base, over map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}
