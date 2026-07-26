package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func gbpAttrs() map[string]any {
	return map[string]any{
		"location.region":    "europe-west1",
		"schedule.frequency": "24h",  // DAILY -> RPO 24h
		"retention.duration": "720h", // 30 days
		"copy.crossRegion":   false,
		"service.managed":    true,
	}
}

func gbpImpl() map[string]any {
	return map[string]any{
		"backupVault":  "projects/acme-prod/locations/europe-west1/backupVaults/pv-vault",
		"resourceType": "compute.googleapis.com/Instance",
	}
}

func TestBuildBackupPlanGCPHonors(t *testing.T) {
	p, err := BuildBackupPlanGCP("acme-prod", "prod", "nightly", gbpAttrs(), gbpImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !gcpName.MatchString(p.PlanID) {
		t.Fatalf("plan id invalid: %q", p.PlanID)
	}
	if p.Recurrence != "DAILY" || p.RetentionDays != 30 {
		t.Fatalf("plan = %+v", p)
	}
	if p.Labels["groundhold-capability"] != "nightly" || p.Labels["groundhold-environment"] != "prod" {
		t.Fatalf("labels = %+v", p.Labels)
	}
	body := p.createBody()
	rules := body["backupRules"].([]any)
	rule := rules[0].(map[string]any)
	if rule["backupRetentionDays"] != 30 {
		t.Fatalf("retention body = %+v", rule)
	}
	sched := rule["standardSchedule"].(map[string]any)
	if sched["recurrenceType"] != "DAILY" {
		t.Fatalf("schedule body = %+v", sched)
	}
}

func TestBuildBackupPlanGCPHourly(t *testing.T) {
	a := gbpAttrs()
	a["schedule.frequency"] = "6h" // HOURLY, hourlyFrequency=6
	p, err := BuildBackupPlanGCP("acme-prod", "prod", "nightly", a, gbpImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Recurrence != "HOURLY" || p.HourlyFreq != 6 {
		t.Fatalf("plan = %+v", p)
	}
	sched := p.standardSchedule()
	if sched["hourlyFrequency"] != 6 {
		t.Fatalf("hourly sched = %+v", sched)
	}
}

func TestBuildBackupPlanGCPRefusals(t *testing.T) {
	base := gbpAttrs()
	cases := map[string]struct {
		attrs map[string]any
		impl  map[string]any
	}{
		// honest gap: backupdr has no cross-region copy
		"cross-region-refused":     {attrs: mergeAttrs(base, map[string]any{"copy.crossRegion": true})},
		"dest-region-refused":      {attrs: mergeAttrs(base, map[string]any{"copy.destinationRegion": "us-east1"})},
		"no-freq":                  {attrs: dropAttr(base, "schedule.frequency")},
		"no-retention":             {attrs: dropAttr(base, "retention.duration")},
		"no-location":              {attrs: dropAttr(base, "location.region")},
		"unmanaged":                {attrs: mergeAttrs(base, map[string]any{"service.managed": false})},
		"unknown-attr":             {attrs: mergeAttrs(base, map[string]any{"encryption.customerManagedKeys": true})},
		"bad-cadence-every-2-days": {attrs: mergeAttrs(base, map[string]any{"schedule.frequency": "48h"})},
		"sub-hour":                 {attrs: mergeAttrs(base, map[string]any{"schedule.frequency": "30m"})},
		"no-vault":                 {impl: map[string]any{"resourceType": "compute.googleapis.com/Instance"}},
		"no-resourcetype":          {impl: map[string]any{"backupVault": "projects/p/locations/l/backupVaults/v"}},
	}
	for name, c := range cases {
		a := c.attrs
		if a == nil {
			a = base
		}
		im := c.impl
		if im == nil {
			im = gbpImpl()
		}
		if _, err := BuildBackupPlanGCP("acme-prod", "prod", "nightly", a, im, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

func mergeAttrs(base, over map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

func dropAttr(base map[string]any, key string) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		if k != key {
			out[k] = v
		}
	}
	return out
}

// gbpServer is a happy backupdr backup-plan LRO double. Create/Patch/Delete return an
// op; the op polls done; GET reflects labels + a DAILY rule with 30-day retention.
func gbpServer(t *testing.T, capLabel string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "POST" && strings.Contains(r.URL.Path, "/backupPlans"):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op-create"}`))
			case r.Method == "PATCH":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op-patch"}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op-delete"}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
					`"backupRules":[{"backupRetentionDays":30,"standardSchedule":{"recurrenceType":"DAILY"}}]}`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func gbpDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.BackupDRBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestBackupPlanGCPCreateObserveUpdateDelete(t *testing.T) {
	srv := gbpServer(t, "nightly")
	defer srv.Close()
	d := gbpDriver(t, srv)

	res := d.createBackupPlanGCP("nightly", "prod", gbpAttrs(), gbpImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "gbkplan:acme-prod:europe-west1:") {
		t.Fatalf("create: %+v", res)
	}

	obs, _, err := d.observeBackupPlanGCP("nightly", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "europe-west1" || got["service.managed"] != true ||
		got["copy.crossRegion"] != false || got["schedule.frequency"] != "24h" ||
		got["retention.duration"] != "720h" {
		t.Fatalf("observe: %+v", got)
	}

	up := d.updateBackupPlanGCP("nightly", "prod", res.ProviderID, gbpAttrs(), gbpImpl(), []string{"retention.duration"})
	if up.Status != "succeeded" || up.ProviderID != res.ProviderID {
		t.Fatalf("update: %+v", up)
	}

	del := d.deleteBackupPlanGCP("nightly", "prod", res.ProviderID)
	if del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestBackupPlanGCPForeignRefused(t *testing.T) {
	srv := gbpServer(t, "someone-else")
	defer srv.Close()
	d := gbpDriver(t, srv)
	pid := gbpProviderID("acme-prod", "europe-west1", resourceName("acme-prod", "prod", "nightly", 1, 62))
	if del := d.deleteBackupPlanGCP("nightly", "prod", pid); del.Status != "failed" || !strings.Contains(del.Reason, "not ours") {
		t.Fatalf("foreign plan must refuse delete, got %+v", del)
	}
	if up := d.updateBackupPlanGCP("nightly", "prod", pid, gbpAttrs(), gbpImpl(), []string{"retention.duration"}); up.Status != "failed" || !strings.Contains(up.Reason, "not ours") {
		t.Fatalf("foreign plan must refuse update, got %+v", up)
	}
}

func TestBackupPlanGCPDiscover(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/backupPlans"):
			_, _ = w.Write([]byte(`{"backupPlans":[{"name":"projects/acme-prod/locations/europe-west1/backupPlans/pv-nightly-abcd1234"}]}`))
		case strings.Contains(r.URL.Path, "/backupPlans/"):
			_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"nightly","groundhold-environment":"prod"},` +
				`"backupRules":[{"backupRetentionDays":30,"standardSchedule":{"recurrenceType":"DAILY"}}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := gbpDriver(t, srv)
	found, _, err := d.discoverBackupPlansGCP("europe-west1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ResourceType != "capability.backup.plan" {
		t.Fatalf("discover: %+v", found)
	}
}

func TestClassifyBackupPlanGCPChange(t *testing.T) {
	cases := []struct {
		path    string
		desired any
		want    string
	}{
		{"schedule.frequency", nil, "mutable"},
		{"retention.duration", nil, "mutable"},
		{"copy.crossRegion", true, "unsupported"},
		{"copy.destinationRegion", "us-east1", "unsupported"},
		{"location.region", nil, "immutable"},
		{"service.managed", nil, "unsupported"},
	}
	for _, c := range cases {
		got, _ := classifyBackupPlanGCPChange(c.path, c.desired)
		if got != c.want {
			t.Errorf("classify %s: got %q want %q", c.path, got, c.want)
		}
	}
}
