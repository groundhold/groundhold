package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func schedAttrs() map[string]any {
	return map[string]any{
		"location.region":  "europe-west1",
		"schedule.enabled": true,
		"service.managed":  true,
	}
}

func schedImpl() map[string]any {
	return map[string]any{
		"schedule":     "0 2 * * *",
		"pubsub_topic": "projects/acme-prod/topics/nightly",
	}
}

func TestBuildCloudSchedulerHonors(t *testing.T) {
	p, err := BuildCloudSchedulerJob("acme-prod", "prod", "nightly", schedAttrs(), schedImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !schedJobIDOK.MatchString(p.JobID) || !strings.HasPrefix(p.JobID, "pv-nightly-prod-") {
		t.Fatalf("job id = %q", p.JobID)
	}
	if !strings.Contains(p.Description, "capability=nightly") {
		t.Fatalf("ownership marker missing: %q", p.Description)
	}
	body := p.createBody("acme-prod")
	if _, has := body["pubsubTarget"]; !has {
		t.Fatalf("pubsub target missing: %+v", body)
	}
}

func TestBuildCloudSchedulerRefusals(t *testing.T) {
	type c struct{ attrs, impl map[string]any }
	cases := map[string]c{
		"no-schedule":  {schedAttrs(), map[string]any{"pubsub_topic": "t"}},
		"no-target":    {schedAttrs(), map[string]any{"schedule": "0 2 * * *"}},
		"both-targets": {schedAttrs(), map[string]any{"schedule": "x", "pubsub_topic": "t", "http_uri": "https://x"}},
		"unmanaged":    {map[string]any{"location.region": "europe-west1", "service.managed": false}, schedImpl()},
		"unknown-attr": {map[string]any{"location.region": "europe-west1", "trigger.jitter": "5s"}, schedImpl()},
		"no-location":  {map[string]any{"service.managed": true}, schedImpl()},
	}
	for name, tc := range cases {
		if _, err := BuildCloudSchedulerJob("acme-prod", "prod", "nightly", tc.attrs, tc.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

// schedServer is a happy Cloud Scheduler double. GET reflects the marker + state.
func schedServer(t *testing.T, capLabel, state string) *httptest.Server {
	t.Helper()
	marker := vpcOwnerMarker(capLabel, "prod")
	doc := `{"name":"projects/acme-prod/locations/europe-west1/jobs/pv-nightly-prod-x",` +
		`"description":"` + marker + `","state":"` + state + `","schedule":"0 2 * * *"}`
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":pause"):
				_, _ = w.Write([]byte(`{"name":"x","state":"PAUSED"}`))
			case r.Method == "POST" && strings.Contains(r.URL.Path, "/jobs"):
				_, _ = w.Write([]byte(doc))
			case r.Method == "GET":
				_, _ = w.Write([]byte(doc))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func schedDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.SchedulerBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteCloudScheduler(t *testing.T) {
	srv := schedServer(t, "nightly", "ENABLED")
	defer srv.Close()
	d := schedDriver(t, srv)
	res := d.Create("cloudscheduler", "nightly", "prod", schedAttrs(), schedImpl(), "k", 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "gsched:acme-prod:europe-west1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeCloudScheduler("nightly", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["schedule.enabled"] != true || got["location.region"] != "europe-west1" || got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.Delete("cloudscheduler", "nightly", "prod", res.ProviderID, "k"); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestCreatePausedCloudScheduler(t *testing.T) {
	srv := schedServer(t, "nightly", "PAUSED")
	defer srv.Close()
	d := schedDriver(t, srv)
	a := schedAttrs()
	a["schedule.enabled"] = false
	res := d.Create("cloudscheduler", "nightly", "prod", a, schedImpl(), "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("create paused: %+v", res)
	}
	obs, _, _ := d.observeCloudScheduler("nightly", res.ProviderID)
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["schedule.enabled"] != false {
		t.Fatalf("paused job must observe schedule.enabled=false: %+v", got)
	}
}

func TestDeleteCloudSchedulerForeignRefused(t *testing.T) {
	srv := schedServer(t, "someone-else", "ENABLED")
	defer srv.Close()
	d := schedDriver(t, srv)
	pid := schedProviderID("acme-prod", "europe-west1", SchedulerJobID("prod", "nightly", 1))
	res := d.Delete("cloudscheduler", "nightly", "prod", pid, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign job must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessCloudScheduler(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := schedProviderID("acme-prod", "europe-west1", SchedulerJobID("prod", "nightly", 1))
	p := &certifynet.Probe{
		// AssertTransient left false — D237 TODO: this driver's create/delete ladder
		// still maps 429/503/403 to terminal failed (and drops the providerId); it must
		// route through provider.MutationResult before the transient invariant can lock.
		Name:            "gcp/cloudscheduler",
		AssertTransient: true,       // D237 sweep
		Classify:        secretRole, // sync REST: GET read, POST/DELETE opaque (id deterministic)
		OwnerTagValue:   "nightly",
		DeterministicID: true, // the job id is a chosen slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return schedServer(t, "nightly", "ENABLED") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("cloudscheduler", "nightly", "prod", schedAttrs(), schedImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return schedServer(t, "nightly", "ENABLED") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("cloudscheduler", "nightly", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}
