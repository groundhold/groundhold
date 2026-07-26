package gcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func runAttrs() map[string]any {
	return map[string]any{
		"location.region":        "europe-central2",
		"availability.class":     "regional",
		"network.publicExposure": true,
		"replicas.minimum":       float64(1),
		"autoscaling.enabled":    true,
		"image.signedProvenance": true,
		"tls.enforced":           true,
		"service.managed":        true,
	}
}

func TestBuildCloudRunCreateGolden(t *testing.T) {
	impl := map[string]any{
		"image": "europe-docker.pkg.dev/acme/app/be:sha256-abc",
		"port":  float64(8080),
	}
	req, err := BuildCloudRunCreateRequest("acme-prod", "prod", "app-be",
		runAttrs(), impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" {
		t.Fatalf("method=%s", req.Method)
	}
	wantName := ServiceName("acme-prod", "prod", "app-be", 1)
	if !strings.Contains(req.URL, "/locations/europe-central2/services?serviceId="+wantName) {
		t.Fatalf("url=%s (want region + serviceId=%s)", req.URL, wantName)
	}
	got, _ := json.Marshal(req.Body)
	want := `{"binaryAuthorization":{"useDefault":true},` +
		`"ingress":"INGRESS_TRAFFIC_ALL",` +
		`"labels":{"groundhold-capability":"app-be","groundhold-environment":"prod"},` +
		`"template":{"containers":[{"image":"europe-docker.pkg.dev/acme/app/be:sha256-abc",` +
		`"ports":[{"containerPort":8080}]}],"scaling":{"minInstanceCount":1}}}`
	if string(got) != want {
		t.Fatalf("body golden mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestCloudRunPrivateIngress(t *testing.T) {
	a := runAttrs()
	a["network.publicExposure"] = false
	req, err := BuildCloudRunCreateRequest("p", "prod", "be", a,
		map[string]any{"image": "img"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if req.Body["ingress"] != "INGRESS_TRAFFIC_INTERNAL_ONLY" {
		t.Fatalf("ingress=%v", req.Body["ingress"])
	}
}

func TestCloudRunRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(a map[string]any, impl map[string]any)
	}{
		{"no image", func(a, impl map[string]any) { delete(impl, "image") }},
		{"no region", func(a, impl map[string]any) { delete(a, "location.region") }},
		{"zonal", func(a, impl map[string]any) { a["availability.class"] = "zonal" }},
		{"no autoscale", func(a, impl map[string]any) { a["autoscaling.enabled"] = false }},
		{"plaintext", func(a, impl map[string]any) { a["tls.enforced"] = false }},
		{"unmanaged", func(a, impl map[string]any) { a["service.managed"] = false }},
		{"unknown attr", func(a, impl map[string]any) { a["storage.encryption"] = true }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := runAttrs()
			impl := map[string]any{"image": "img"}
			c.mutate(a, impl)
			if _, err := BuildCloudRunCreateRequest("p", "prod", "be", a, impl, 1); err == nil {
				t.Fatalf("expected refusal for %q, got none", c.name)
			}
		})
	}
}

// The shared name helper must not have changed Cloud SQL's names.
func TestInstanceNameUnchangedByRefactor(t *testing.T) {
	// stable snapshot: a known input keeps its historical name shape
	n := InstanceName("acme-prod", "prod", "orders-db", 1)
	if !strings.HasPrefix(n, "orders-db-prod-") || len(n) > 98 {
		t.Fatalf("instance name shape changed: %q", n)
	}
}
