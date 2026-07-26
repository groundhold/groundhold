package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func cajAttrs() map[string]any {
	return map[string]any{
		"location.region": "eastus",
		"image":           "myregistry.azurecr.io/worker:1.2",
		"trigger.type":    "manual",
		"timeout":         "600s",
		"service.managed": true,
	}
}

func cajImpl() map[string]any {
	return map[string]any{
		"resource_group": "rg1",
		"environment_id": "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.App/managedEnvironments/env1",
	}
}

func TestBuildContainerAppsJobHonors(t *testing.T) {
	p, err := BuildContainerAppsJob("prod", "worker", cajAttrs(), cajImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.TriggerType != "Manual" || p.Image != "myregistry.azurecr.io/worker:1.2" || p.TimeoutSec != 600 || p.EnvironmentID == "" {
		t.Fatalf("plan = %+v", p)
	}
	props := p.createBody(map[string]any{})["properties"].(map[string]any)
	if props["environmentId"] == "" || props["configuration"].(map[string]any)["triggerType"] != "Manual" {
		t.Fatalf("body = %+v", props)
	}
}

func TestBuildContainerAppsJobScheduleNeedsCron(t *testing.T) {
	a := cajAttrs()
	a["trigger.type"] = "schedule"
	if _, err := BuildContainerAppsJob("prod", "worker", a, cajImpl(), 1); err == nil {
		t.Fatal("schedule without cron must refuse")
	}
	impl := cajImpl()
	impl["cron_expression"] = "0 */6 * * *"
	p, err := BuildContainerAppsJob("prod", "worker", a, impl, 1)
	if err != nil || p.TriggerType != "Schedule" || p.CronExpression == "" {
		t.Fatalf("schedule plan = %+v err=%v", p, err)
	}
}

func TestBuildContainerAppsJobRefusals(t *testing.T) {
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"bad-trigger":  {map[string]any{"trigger.type": "whenever"}, cajImpl()},
		"empty-image":  {map[string]any{"image": ""}, cajImpl()},
		"unmanaged":    {map[string]any{"service.managed": false}, cajImpl()},
		"unknown-attr": {map[string]any{"job.tier": "x"}, cajImpl()},
		"no-env":       {map[string]any{}, map[string]any{"resource_group": "rg1"}}, // managed env required
	}
	for name, c := range cases {
		a := cajAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildContainerAppsJob("prod", "worker", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := cajAttrs()
	delete(a, "location.region")
	if _, err := BuildContainerAppsJob("prod", "worker", a, cajImpl(), 1); err == nil {
		t.Error("missing location.region must refuse")
	}
}

func cajServer(t *testing.T, capLabel, trigger, image string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","configuration":{"triggerType":"` + trigger + `"},` +
					`"template":{"containers":[{"image":"` + image + `"}]}}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func cajDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteContainerAppsJob(t *testing.T) {
	srv := cajServer(t, "worker", "Manual", "myregistry.azurecr.io/worker:1.2")
	defer srv.Close()
	d := cajDriver(t, srv)
	res := d.createContainerAppsJob("prod", "worker", cajAttrs(), cajImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "acjob:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeContainerAppsJob("worker", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eastus" || got["trigger.type"] != "manual" ||
		got["image"] != "myregistry.azurecr.io/worker:1.2" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteContainerAppsJob("worker", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteContainerAppsJobForeignRefused(t *testing.T) {
	srv := cajServer(t, "someone-else", "Manual", "img")
	defer srv.Close()
	d := cajDriver(t, srv)
	pid := containerAppsJobProviderID(testSub, "rg1", azResourceName("pv-job", "prod", "worker", 1))
	res := d.deleteContainerAppsJob("worker", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign job must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessContainerAppsJob(t *testing.T) {
	pid := containerAppsJobProviderID(testSub, "rg1", azResourceName("pv-job", "prod", "worker", 1))
	p := &certifynet.Probe{
		// AssertTransient left false — D237 TODO: this driver's create/delete ladder
		// still maps 429/503/403 to terminal failed (and drops the providerId); it must
		// route through provider.MutationResult before the transient invariant can lock.
		Name:            "azure/containerappsjob",
		Classify:        armRole,
		OwnerTagValue:   "worker",
		AssertTransient: true, // D237
		DeterministicID: true,
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.BaseURL = happyURL
			d.HTTP = &http.Client{Transport: rt}
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return cajServer(t, "worker", "Manual", "img") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("containerappsjob", "worker", "prod", cajAttrs(), cajImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return cajServer(t, "worker", "Manual", "img") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("containerappsjob", "worker", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.container.job on Azure Container Apps Jobs.
func TestMetamorphicContainerAppsJobRoundTrip(t *testing.T) {
	cases := []struct {
		name        string
		trigger     string
		cron        string
		wantTrigger string
	}{
		{"manual", "manual", "", "manual"},
		{"schedule", "schedule", "0 */6 * * *", "schedule"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var trigger, image string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch r.Method {
					case "PUT":
						body, _ := io.ReadAll(r.Body)
						var doc struct {
							Properties struct {
								Configuration struct {
									TriggerType string `json:"triggerType"`
								} `json:"configuration"`
								Template struct {
									Containers []struct {
										Image string `json:"image"`
									} `json:"containers"`
								} `json:"template"`
							} `json:"properties"`
						}
						_ = json.Unmarshal(body, &doc)
						trigger = doc.Properties.Configuration.TriggerType
						if len(doc.Properties.Template.Containers) > 0 {
							image = doc.Properties.Template.Containers[0].Image
						}
						w.WriteHeader(200)
						_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
					case "GET":
						_, _ = w.Write([]byte(`{"location":"eastus","tags":{"groundhold-capability":"worker","groundhold-environment":"prod"},` +
							`"properties":{"provisioningState":"Succeeded","configuration":{"triggerType":"` + trigger + `"},` +
							`"template":{"containers":[{"image":"` + image + `"}]}}}`))
					default:
						w.WriteHeader(200)
					}
				}))
			defer srv.Close()
			d := cajDriver(t, srv)
			a := cajAttrs()
			a["trigger.type"] = c.trigger
			impl := cajImpl()
			if c.cron != "" {
				impl["cron_expression"] = c.cron
			}
			res := d.createContainerAppsJob("prod", "worker", a, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeContainerAppsJob("worker", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["trigger.type"] != c.wantTrigger {
				t.Errorf("trigger round-trip: want %q got %v", c.wantTrigger, got["trigger.type"])
			}
		})
	}
}
