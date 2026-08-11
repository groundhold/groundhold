package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/provider"
)

// azAsyncStuckDriver returns a driver whose ARM fake owns the resource (GET reports it
// present with matching tags) and ACCEPTS every DELETE with a 202 — but the resource
// never leaves (GET never 404s). A delete that routes through deleteAndConfirm (D971)
// must poll to the timeout and report unknown; a delete that concludes succeeded on the
// bare 202 (the D984 defect) would return succeeded instead.
func azAsyncStuckDriver(t *testing.T, capLabel, env string) (*Driver, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A companion resource (e.g. the VMSS autoscale setting, deleted FIRST) must be
		// absent so the delete proceeds to the MAIN resource — otherwise a companion that
		// also 202s would make the function return "still deleting" from the companion and
		// never exercise the resource under test.
		if strings.Contains(strings.ToLower(r.URL.Path), "autoscalesettings") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case "GET": // owned + present, forever — never 404
			_, _ = w.Write([]byte(`{"location":"eastus","sku":{"name":"Standard","tier":"Standard","capacity":1},` +
				`"tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"` + env + `"},` +
				`"properties":{"provisioningState":"Succeeded"}}`))
		case "PUT":
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
		case "DELETE": // 202 Accepted — an async delete that never completes in this fixture
			w.WriteHeader(202)
		default:
			w.WriteHeader(404)
		}
	}))
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 5 * time.Millisecond
	return d, srv.Close
}

// TestAzureAsyncDeletesPollToAbsence pins D984: every Azure delete that ARM answers with
// a 202 Accepted must poll the resource to a confirmed 404 before concluding succeeded —
// never tombstone a billable/data-bearing resource still being torn down. Each of these
// deletes was routed through the D971 deleteAndConfirm helper; this drives a 202 through
// each and asserts the honest unknown (with the poll-timeout reason, so a pre-delete
// failure cannot pass this by accident).
func TestAzureAsyncDeletesPollToAbsence(t *testing.T) {
	cases := []struct {
		name, cap, env string
		del            func(d *Driver) provider.CreateResult
	}{
		{"cosmos", "sessions", "prod", func(d *Driver) provider.CreateResult {
			return d.deleteCosmos("sessions", "prod", cosmosProviderID(testSub, "rg1", cosmosAccountName("prod", "sessions", 1)))
		}},
		{"acr", "images", "prod", func(d *Driver) provider.CreateResult {
			return d.deleteACR("images", "prod", "acr:"+testSub+":rg1:"+acrName("prod", "images", 1))
		}},
		{"redis", "sessions", "prod", func(d *Driver) provider.CreateResult {
			return d.deleteRedisAzure("sessions", "prod", redisAzureProviderID(testSub, "rg1", azResourceName("pv-cache", "prod", "sessions", 1)))
		}},
		{"apim", "front", "prod", func(d *Driver) provider.CreateResult {
			return d.deleteAPIM("front", "prod", apimProviderID(testSub, "rg1", apimServiceName("prod", "front", 1)))
		}},
		{"vm", "web", "production", func(d *Driver) provider.CreateResult {
			return d.deleteAzureVM("web", "production", azureVMProviderID(testSub, "rg", "pv-vm-abc123456789"))
		}},
		{"vmss", "web-fleet", "production", func(d *Driver) provider.CreateResult {
			return d.deleteAzureVMSS("web-fleet", "production", azureVMSSProviderID(testSub, "rg", "pv-vmss-x"))
		}},
		{"disk", "orders-data", "production", func(d *Driver) provider.CreateResult {
			return d.deleteAzureDisk("orders-data", "production", azureDiskProviderID(testSub, "rg", "pv-disk-x"))
		}},
		{"cdn", "edge", "prod", func(d *Driver) provider.CreateResult {
			return d.deleteAzureCDN("edge", "prod", azureCDNProviderID(testSub, "rg1", azCDNProfileName("prod", "edge", 1), azResourceName("pv-ep", "prod", "edge", 1)))
		}},
		{"eventhubs", "events", "prod", func(d *Driver) provider.CreateResult {
			return d.deleteEventHubs("events", "prod", eventHubsProviderID(testSub, "rg1", eventHubsNamespaceName("prod", "events", 1), azResourceName("pv-hub", "prod", "events", 1)))
		}},
		{"azkafka", "bus", "prod", func(d *Driver) provider.CreateResult {
			return d.deleteAzKafka("bus", "prod", azKafkaProviderID(testSub, "rg1", azKafkaNamespaceName("prod", "bus", 1)))
		}},
		{"azureopenai", "inference", "prod", func(d *Driver) provider.CreateResult {
			return d.deleteAzureOpenAI("inference", "prod", aoiProviderID(testSub, "rg1", aoiAccountName("prod", "inference", 1)))
		}},
		{"aisearch", "catalog", "prod", func(d *Driver) provider.CreateResult {
			return d.deleteAISearch("catalog", "prod", aiSearchProviderID(testSub, "rg1", aiSearchName("prod", "catalog", 1)))
		}},
		{"containerappsjob", "worker", "prod", func(d *Driver) provider.CreateResult {
			return d.deleteContainerAppsJob("worker", "prod", containerAppsJobProviderID(testSub, "rg1", azResourceName("pv-job", "prod", "worker", 1)))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, done := azAsyncStuckDriver(t, c.cap, c.env)
			defer done()
			res := c.del(d)
			if res.Status != "unknown" || !strings.Contains(res.Reason, "still deleting") {
				t.Fatalf("%s: an accepted-but-still-deleting resource must poll to unknown, got %+v", c.name, res)
			}
		})
	}
}
