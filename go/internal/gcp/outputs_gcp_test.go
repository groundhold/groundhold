package gcp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// D284: GCP typed create outputs — pid-derived, plus one network read for
// vpc subnetworks.

func TestGCPDeriveOutputsFromPid(t *testing.T) {
	d := NewDriver("proj-x")
	cases := []struct {
		service, pid string
		want         map[string]any
	}{
		{"gcs", "gcs:proj-x:my-bucket", map[string]any{"bucketName": "my-bucket"}},
		{"pubsub-topic", "pubsub:proj-x:alerts", map[string]any{
			"topicName": "alerts", "topicId": "projects/proj-x/topics/alerts"}},
		{"serviceaccount", "gsa:proj-x:app-runner", map[string]any{
			"accountId": "app-runner",
			"email":     "app-runner@proj-x.iam.gserviceaccount.com",
			"member":    "serviceAccount:app-runner@proj-x.iam.gserviceaccount.com"}},
		{"cloudkms", "gkms:proj-x:europe-west1:ring1:key1", map[string]any{
			"keyName": "projects/proj-x/locations/europe-west1/keyRings/ring1/cryptoKeys/key1"}},
		{"gke", "gke:proj-x:europe-west1:demo", map[string]any{
			"clusterName": "demo", "location": "europe-west1"}},
		{"certmanager", "gcert:proj-x:global:cert1", map[string]any{
			"certificateName": "projects/proj-x/locations/global/certificates/cert1"}},
		{"artifactregistry", "gar:proj-x:europe-west1:app-repo", map[string]any{
			"repositoryUri": "europe-west1-docker.pkg.dev/proj-x/app-repo"}},
		{"backupvault", "gbkv:proj-x:europe-west1:app-vault", map[string]any{
			"vaultName":   "app-vault",
			"backupVault": "projects/proj-x/locations/europe-west1/backupVaults/app-vault"}},
	}
	for _, c := range cases {
		got, err := d.deriveOutputs(c.service, c.pid)
		if err != nil {
			t.Fatalf("%s: %v", c.service, err)
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Fatalf("%s: output %s = %v, want %v", c.service, k, got[k], v)
			}
		}
		specs := d.OutputsFor(c.service)
		if len(specs) != len(got) {
			t.Fatalf("%s: OutputsFor declares %d, derivation yields %d",
				c.service, len(specs), len(got))
		}
		for _, s := range specs {
			if _, ok := got[s.Name]; !ok {
				t.Fatalf("%s: declared output %s not derived", c.service, s.Name)
			}
		}
	}
}

func TestGCPVpcOutputsReadSubnetworks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/global/networks/net-1") {
			fmt.Fprint(w, `{"description":"x","autoCreateSubnetworks":false,
				"subnetworks":["https://www.googleapis.com/compute/v1/projects/proj-x/regions/europe-west1/subnetworks/net-1-sub"]}`)
			return
		}
		http.Error(w, "unexpected", 400)
	}))
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("proj-x")
	d.ComputeBaseURL = srv.URL

	outs, err := d.deriveOutputs("vpc", "vpc:proj-x:europe-west1:net-1")
	if err != nil {
		t.Fatal(err)
	}
	if outs["network"] != "net-1" || outs["region"] != "europe-west1" {
		t.Fatalf("outs = %v", outs)
	}
	if outs["networkSelfLink"] != "https://www.googleapis.com/compute/v1/projects/proj-x/global/networks/net-1" {
		t.Fatalf("networkSelfLink = %v", outs["networkSelfLink"])
	}
	subs, _ := outs["subnetworks"].([]any)
	if len(subs) != 1 || !strings.HasSuffix(subs[0].(string), "/subnetworks/net-1-sub") {
		t.Fatalf("subnetworks = %v", outs["subnetworks"])
	}
}

// TestCloudSQLConnectionOutput: connectionName is pid-derived (no read);
// privateIpAddress + port come from one instances.get — the ipAddresses[] entry
// whose type is PRIVATE, and the port from databaseVersion. A public-only
// instance (no PRIVATE address) publishes connectionName alone, never a fabricated
// endpoint. Mirrors AWS's TestAuroraEndpointOutput.
func TestCloudSQLConnectionOutput(t *testing.T) {
	instJSON := `{"databaseVersion":"POSTGRES_16","ipAddresses":[` +
		`{"type":"PRIMARY","ipAddress":"34.1.2.3"},` +
		`{"type":"PRIVATE","ipAddress":"10.1.2.3"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/instances/orders-db") {
			fmt.Fprint(w, instJSON)
			return
		}
		http.Error(w, "unexpected", 400)
	}))
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.BaseURL = srv.URL

	outs, err := d.deriveOutputs("cloudsql", "acme-prod:europe-west1:orders-db")
	if err != nil {
		t.Fatal(err)
	}
	if outs["connectionName"] != "acme-prod:europe-west1:orders-db" {
		t.Fatalf("connectionName = %v", outs["connectionName"])
	}
	if outs["privateIpAddress"] != "10.1.2.3" {
		t.Fatalf("privateIpAddress = %v", outs["privateIpAddress"])
	}
	if outs["port"] != "5432" {
		t.Fatalf("port = %v", outs["port"])
	}
	// completeness: a private instance derives every declared output.
	for _, s := range d.OutputsFor("cloudsql") {
		if _, ok := outs[s.Name]; !ok {
			t.Fatalf("declared cloudsql output %s not derived", s.Name)
		}
	}

	// a public-only instance: connectionName only, no fabricated private endpoint.
	pubSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"databaseVersion":"POSTGRES_16","ipAddresses":[{"type":"PRIMARY","ipAddress":"34.1.2.3"}]}`)
	}))
	defer pubSrv.Close()
	d.BaseURL = pubSrv.URL
	outs, err = d.deriveOutputs("cloudsql", "acme-prod:europe-west1:orders-db")
	if err != nil {
		t.Fatal(err)
	}
	if outs["connectionName"] != "acme-prod:europe-west1:orders-db" {
		t.Fatalf("public connectionName = %v", outs["connectionName"])
	}
	if _, has := outs["privateIpAddress"]; has {
		t.Fatalf("a public-only instance must not publish privateIpAddress, got %v", outs["privateIpAddress"])
	}
}

func TestGCPAttachOutputsUnderivableDemotesToUnknown(t *testing.T) {
	d := NewDriver("proj-x")
	cr := provider.CreateResult{ProviderID: "gkms:bad", Status: "succeeded"}
	d.attachOutputs("cloudkms", &cr)
	if cr.Status != "unknown" {
		t.Fatalf("underivable outputs must demote to unknown, got %+v", cr)
	}
	cr = provider.CreateResult{ProviderID: "anything", Status: "succeeded"}
	d.attachOutputs("cloudrunjobs", &cr) // a service with no declared outputs
	if cr.Status != "succeeded" || cr.Outputs != nil {
		t.Fatalf("a non-declaring service must pass through untouched, got %+v", cr)
	}
}
