package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func crjAttrs() map[string]any {
	return map[string]any{
		"location.region": "europe-west1",
		"image":           "gcr.io/proj/worker:1.2",
		"trigger.type":    "manual",
		"timeout":         "600s",
		"service.managed": true,
	}
}

func TestBuildCloudRunJobHonors(t *testing.T) {
	p, err := BuildCloudRunJob("acme-prod", "prod", "worker", crjAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Region != "europe-west1" || p.Image != "gcr.io/proj/worker:1.2" || p.TimeoutSec != 600 {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("worker", "prod")
	tt := body["template"].(map[string]any)["template"].(map[string]any)
	if tt["timeout"] != "600s" || tt["containers"].([]any)[0].(map[string]any)["image"] != "gcr.io/proj/worker:1.2" {
		t.Fatalf("body = %+v", tt)
	}
}

func TestBuildCloudRunJobRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"schedule-refused": {"trigger.type": "schedule"}, // needs Cloud Scheduler
		"bad-trigger":      {"trigger.type": "whenever"},
		"empty-image":      {"image": ""},
		"unmanaged":        {"service.managed": false},
		"unknown-attr":     {"job.tier": "x"},
	}
	for name, extra := range cases {
		a := crjAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildCloudRunJob("acme-prod", "prod", "worker", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := crjAttrs()
	delete(a, "location.region")
	if _, err := BuildCloudRunJob("acme-prod", "prod", "worker", a, nil, 1); err == nil {
		t.Error("missing location.region must refuse")
	}
}

func crjServer(t *testing.T, capLabel, image, timeout string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "jobId="):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op1"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/opdel"}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/jobs/x",` +
					`"labels":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
					`"template":{"template":{"containers":[{"image":"` + image + `"}],"timeout":"` + timeout + `"}}}`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func crjDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.RunBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteCloudRunJob(t *testing.T) {
	srv := crjServer(t, "worker", "gcr.io/proj/worker:1.2", "600s")
	defer srv.Close()
	d := crjDriver(t, srv)
	res := d.createCloudRunJob("prod", "worker", crjAttrs(), nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "gjob:acme-prod:europe-west1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeCloudRunJob("worker", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "europe-west1" || got["image"] != "gcr.io/proj/worker:1.2" ||
		got["trigger.type"] != "manual" || got["timeout"] != "600s" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteCloudRunJob("worker", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteCloudRunJobForeignRefused(t *testing.T) {
	srv := crjServer(t, "someone-else", "img", "600s")
	defer srv.Close()
	d := crjDriver(t, srv)
	pid := cloudRunJobProviderID("acme-prod", "europe-west1", resourceName("acme-prod", "prod", "worker", 1, 63))
	res := d.deleteCloudRunJob("worker", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign job must refuse delete, got %+v", res)
	}
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.container.job on GCP Cloud Run Jobs. A STATEFUL fake records the image
// and timeout the create writes and reflects them on the job read.
func TestMetamorphicCloudRunJobRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		image   string
		timeout string
	}{
		{"a", "gcr.io/proj/a:1", "300s"},
		{"b", "gcr.io/proj/b:2", "900s"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var image, timeout string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "jobId="):
						body, _ := io.ReadAll(r.Body)
						var doc struct {
							Template struct {
								Template struct {
									Containers []struct {
										Image string `json:"image"`
									} `json:"containers"`
									Timeout string `json:"timeout"`
								} `json:"template"`
							} `json:"template"`
						}
						_ = json.Unmarshal(body, &doc)
						if len(doc.Template.Template.Containers) > 0 {
							image = doc.Template.Template.Containers[0].Image
						}
						timeout = doc.Template.Template.Timeout
						_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op1"}`))
					case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
						_, _ = w.Write([]byte(`{"done":true}`))
					case r.Method == "GET":
						_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"worker","groundhold-environment":"prod"},` +
							`"template":{"template":{"containers":[{"image":"` + image + `"}],"timeout":"` + timeout + `"}}}`))
					default:
						w.WriteHeader(404)
					}
				}))
			defer srv.Close()
			d := crjDriver(t, srv)
			a := crjAttrs()
			a["image"] = c.image
			a["timeout"] = c.timeout
			res := d.createCloudRunJob("prod", "worker", a, nil, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeCloudRunJob("worker", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["image"] != c.image {
				t.Errorf("image round-trip: want %q got %v", c.image, got["image"])
			}
			if got["timeout"] != c.timeout {
				t.Errorf("timeout round-trip: want %q got %v", c.timeout, got["timeout"])
			}
		})
	}
}
