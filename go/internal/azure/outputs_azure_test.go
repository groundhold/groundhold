package azure

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// D284: Azure typed create outputs — pid-derived ARM ids/URIs, plus one read
// for managedidentity's server-assigned principalId/clientId.

const azSub = "00000000-0000-0000-0000-000000000001"

func TestAzureDeriveOutputsFromPid(t *testing.T) {
	d := NewDriver(azSub)
	cases := []struct {
		service, pid string
		want         map[string]any
	}{
		{"vnet", "vnet:" + azSub + ":rg1:net-1", map[string]any{
			"resourceGroup": "rg1", "vnetName": "net-1",
			"vnetId": "/subscriptions/" + azSub + "/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/net-1"}},
		{"blob", "blob:" + azSub + ":rg1:acmestore:media", map[string]any{
			"storageAccount": "acmestore", "containerName": "media",
			"blobEndpoint": "https://acmestore.blob.core.windows.net"}},
		{"servicebustopic", "sbt:" + azSub + ":rg1:ns1:alerts", map[string]any{
			"namespace": "ns1", "topicName": "alerts",
			"topicId": "/subscriptions/" + azSub + "/resourceGroups/rg1/providers/Microsoft.ServiceBus/namespaces/ns1/topics/alerts"}},
		{"keyvaultkey", "akvkey:" + azSub + ":rg1:westeurope:vault1:key1", map[string]any{
			"vaultUri": "https://vault1.vault.azure.net",
			"keyUri":   "https://vault1.vault.azure.net/keys/key1"}},
		{"aks", "aks:" + azSub + ":rg1:demo", map[string]any{
			"clusterName": "demo", "resourceGroup": "rg1",
			"aksId": "/subscriptions/" + azSub + "/resourceGroups/rg1/providers/Microsoft.ContainerService/managedClusters/demo"}},
		// mixed-case registry name proves the login server is lowercased (as ACR returns it)
		{"acr", "acr:" + azSub + ":rg1:AcmeReg01", map[string]any{
			"repositoryUri": "acmereg01.azurecr.io"}},
		{"backupvault", "backupvault:" + azSub + ":rg1:app-vault", map[string]any{
			"resourceGroup": "rg1", "vaultName": "app-vault",
			"vaultId": "/subscriptions/" + azSub + "/resourceGroups/rg1/providers/Microsoft.DataProtection/backupVaults/app-vault"}},
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

func TestAzureManagedIdentityOutputsReadGUIDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/userAssignedIdentities/id-1") {
			fmt.Fprint(w, `{"location":"westeurope","properties":{"clientId":"cccccccc-0000-0000-0000-000000000001","principalId":"pppppppp-0000-0000-0000-000000000002"}}`)
			return
		}
		http.Error(w, "unexpected", 400)
	}))
	defer srv.Close()
	d := uamiDriver(t, srv)

	outs, err := d.deriveOutputs("managedidentity", "uami:"+azSub+":rg1:id-1")
	if err != nil {
		t.Fatal(err)
	}
	if outs["principalId"] != "pppppppp-0000-0000-0000-000000000002" ||
		outs["clientId"] != "cccccccc-0000-0000-0000-000000000001" ||
		outs["identityName"] != "id-1" {
		t.Fatalf("outs = %v", outs)
	}

	// a servicebus QUEUE pid must not masquerade as a topic
	if _, err := d.deriveOutputs("servicebustopic", "sbq:"+azSub+":rg1:ns1:jobs"); err == nil {
		t.Fatal("a queue pid must refuse the topic derivation")
	}
}

// TestContainerAppsOutputsFQDN: the D330 output derivation reads the
// server-assigned ingress fqdn via one containerApps.get — the GCP cloudrun uri
// twin. An app WITH ingress publishes fqdn; an ingress-DISABLED app omits it (no
// demotion); a read FAILURE is an error (reconcile), never a fabricated absence.
func TestContainerAppsOutputsFQDN(t *testing.T) {
	const pid = "aca:" + azSub + ":rg1:pv-app-web"
	t.Run("app with ingress publishes fqdn", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && strings.Contains(r.URL.Path, "/containerApps/pv-app-web") {
				fmt.Fprint(w, `{"location":"westeurope","properties":{"configuration":{"ingress":{"external":true,"fqdn":"pv-app-web.happyhill-1a2b3c4d.westeurope.azurecontainerapps.io"}}}}`)
				return
			}
			http.Error(w, "unexpected", 400)
		}))
		defer srv.Close()
		d := uamiDriver(t, srv)
		outs, err := d.ReadOutputs("containerapps", pid)
		if err != nil {
			t.Fatalf("ReadOutputs: %v", err)
		}
		if outs["fqdn"] != "pv-app-web.happyhill-1a2b3c4d.westeurope.azurecontainerapps.io" {
			t.Fatalf("fqdn = %v, want the azurecontainerapps.io host", outs["fqdn"])
		}
		// completeness: an ingress app derives every declared output.
		for _, s := range d.OutputsFor("containerapps") {
			if _, ok := outs[s.Name]; !ok {
				t.Fatalf("declared containerapps output %s not derived", s.Name)
			}
		}
	})
	t.Run("internal app still publishes its fqdn (probe gates on publicExposure)", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `{"properties":{"configuration":{"ingress":{"external":false,"fqdn":"pv-app-web.internal.happyhill-1a2b3c4d.westeurope.azurecontainerapps.io"}}}}`)
		}))
		defer srv.Close()
		d := uamiDriver(t, srv)
		outs, err := d.ReadOutputs("containerapps", pid)
		if err != nil {
			t.Fatal(err)
		}
		if outs["fqdn"] != "pv-app-web.internal.happyhill-1a2b3c4d.westeurope.azurecontainerapps.io" {
			t.Fatalf("internal fqdn = %v", outs["fqdn"])
		}
	})
	t.Run("ingress-disabled app omits fqdn, no demotion", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `{"properties":{"configuration":{}}}`)
		}))
		defer srv.Close()
		d := uamiDriver(t, srv)
		outs, err := d.deriveOutputs("containerapps", pid)
		if err != nil {
			t.Fatalf("an ingress-disabled app must not error: %v", err)
		}
		if _, has := outs["fqdn"]; has {
			t.Fatalf("an ingress-disabled app must not publish fqdn, got %v", outs["fqdn"])
		}
		// attachOutputs must NOT demote a succeeded create with no fqdn.
		cr := provider.CreateResult{ProviderID: pid, Status: "succeeded"}
		d.attachOutputs("containerapps", &cr)
		if cr.Status != "succeeded" {
			t.Fatalf("ingress-disabled app must stay succeeded, got %+v", cr)
		}
	})
	t.Run("read failure is an error (reconcile), demotes create", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(500)
		}))
		defer srv.Close()
		d := uamiDriver(t, srv)
		if _, err := d.deriveOutputs("containerapps", pid); err == nil {
			t.Fatal("a non-200 read must be an error, not a fabricated absence")
		}
		cr := provider.CreateResult{ProviderID: pid, Status: "succeeded"}
		d.attachOutputs("containerapps", &cr)
		if cr.Status != "unknown" {
			t.Fatalf("an underivable fqdn must demote to unknown, got %+v", cr)
		}
	})
}

func TestAzureAttachOutputsUnderivableDemotesToUnknown(t *testing.T) {
	d := NewDriver(azSub)
	cr := provider.CreateResult{ProviderID: "vnet:bad", Status: "succeeded"}
	d.attachOutputs("vnet", &cr)
	if cr.Status != "unknown" {
		t.Fatalf("underivable outputs must demote to unknown, got %+v", cr)
	}
	cr = provider.CreateResult{ProviderID: "azsql:x", Status: "succeeded"}
	d.attachOutputs("azuresql", &cr)
	if cr.Status != "succeeded" || cr.Outputs != nil {
		t.Fatalf("a non-declaring service must pass through untouched, got %+v", cr)
	}
}
