package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// obsMap flattens a Discovered's observations into path->value for assertions.
func gapObsMap(d provider.Discovered) map[string]any {
	m := map[string]any{}
	for _, o := range d.Observations {
		m[o.Path] = o.Value
	}
	return m
}

// --- acr: capability.registry.image via observeACR ---

func TestDiscoverACRGolden(t *testing.T) {
	var sawList, sawBearer, sawAPIVersion bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/providers/Microsoft.ContainerRegistry/registries") && !strings.Contains(p, "/resourceGroups/"):
			sawList = true
			sawBearer = r.Header.Get("Authorization") == "Bearer test-token"
			sawAPIVersion = r.URL.Query().Get("api-version") == acrAPIVersion
			_, _ = w.Write([]byte(`{"value":[
				{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.ContainerRegistry/registries/hereacr01","name":"hereacr01","location":"West Europe"},
				{"id":"/subscriptions/` + testSub + `/resourceGroups/rg2/providers/Microsoft.ContainerRegistry/registries/faracr01","name":"faracr01","location":"eastus"}
			]}`))
		case strings.HasSuffix(p, "/registries/hereacr01"):
			_, _ = w.Write([]byte(`{"location":"westeurope","properties":{"publicNetworkAccess":"Disabled","encryption":{"status":"enabled"}}}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":[]}`))
		}
	}))
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	found, diags, err := d.discoverACR("westeurope")
	if err != nil {
		t.Fatal(err)
	}
	if !sawList || !sawBearer || !sawAPIVersion {
		t.Fatalf("acr list not seen bearer-authenticated with api-version: list=%v bearer=%v apiver=%v", sawList, sawBearer, sawAPIVersion)
	}
	if len(found) != 1 { // faracr01 is out-of-region
		t.Fatalf("acr discovery = %+v (diags %v)", found, diags)
	}
	if found[0].ProviderID != "acr:"+testSub+":rg1:hereacr01" || found[0].ResourceType != "capability.registry.image" {
		t.Fatalf("acr providerId/type = %q/%q", found[0].ProviderID, found[0].ResourceType)
	}
	o := gapObsMap(found[0])
	if o["location.region"] != "westeurope" || o["network.publicExposure"] != false || o["encryption.customerManagedKeys"] != true {
		t.Fatalf("acr reverse-map = %+v", o)
	}
}

// --- aisearch: capability.search.index via observeAISearch ---

func TestDiscoverAISearchGolden(t *testing.T) {
	var sawList, sawBearer, sawAPIVersion bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/providers/Microsoft.Search/searchServices") && !strings.Contains(p, "/resourceGroups/"):
			sawList = true
			sawBearer = r.Header.Get("Authorization") == "Bearer test-token"
			sawAPIVersion = r.URL.Query().Get("api-version") == searchAPIVersion
			_, _ = w.Write([]byte(`{"value":[
				{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.Search/searchServices/heresearch","name":"heresearch","location":"West Europe"},
				{"id":"/subscriptions/` + testSub + `/resourceGroups/rg2/providers/Microsoft.Search/searchServices/farsearch","name":"farsearch","location":"eastus"}
			]}`))
		case strings.HasSuffix(p, "/searchServices/heresearch"):
			_, _ = w.Write([]byte(`{"location":"westeurope","sku":{"name":"standard"},"properties":{"publicNetworkAccess":"disabled","replicaCount":3,"encryptionWithCmk":{"enforcement":"Enabled"}}}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":[]}`))
		}
	}))
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	found, diags, err := d.discoverAISearch("westeurope")
	if err != nil {
		t.Fatal(err)
	}
	if !sawList || !sawBearer || !sawAPIVersion {
		t.Fatalf("aisearch list not seen bearer-authenticated with api-version: list=%v bearer=%v apiver=%v", sawList, sawBearer, sawAPIVersion)
	}
	if len(found) != 1 {
		t.Fatalf("aisearch discovery = %+v (diags %v)", found, diags)
	}
	if found[0].ProviderID != "aisearch:"+testSub+":rg1:heresearch" || found[0].ResourceType != "capability.search.index" {
		t.Fatalf("aisearch providerId/type = %q/%q", found[0].ProviderID, found[0].ResourceType)
	}
	o := gapObsMap(found[0])
	if o["location.region"] != "westeurope" || o["network.publicExposure"] != false ||
		o["availability.class"] != "regional" || o["encryption.customerManagedKeys"] != true {
		t.Fatalf("aisearch reverse-map = %+v", o)
	}
}

// --- apim: capability.apigateway.http via observeAPIM ---

func TestDiscoverAPIMGolden(t *testing.T) {
	var sawList, sawBearer, sawAPIVersion bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/providers/Microsoft.ApiManagement/service") && !strings.Contains(p, "/resourceGroups/"):
			sawList = true
			sawBearer = r.Header.Get("Authorization") == "Bearer test-token"
			sawAPIVersion = r.URL.Query().Get("api-version") == apimAPIVersion
			_, _ = w.Write([]byte(`{"value":[
				{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.ApiManagement/service/hereapim","name":"hereapim","location":"West Europe"},
				{"id":"/subscriptions/` + testSub + `/resourceGroups/rg2/providers/Microsoft.ApiManagement/service/farapim","name":"farapim","location":"eastus"}
			]}`))
		case strings.HasSuffix(p, "/service/hereapim"):
			_, _ = w.Write([]byte(`{"location":"westeurope","properties":{"provisioningState":"Succeeded"}}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":[]}`))
		}
	}))
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	found, diags, err := d.discoverAPIM("westeurope")
	if err != nil {
		t.Fatal(err)
	}
	if !sawList || !sawBearer || !sawAPIVersion {
		t.Fatalf("apim list not seen bearer-authenticated with api-version: list=%v bearer=%v apiver=%v", sawList, sawBearer, sawAPIVersion)
	}
	if len(found) != 1 {
		t.Fatalf("apim discovery = %+v (diags %v)", found, diags)
	}
	if found[0].ProviderID != "apim:"+testSub+":rg1:hereapim" || found[0].ResourceType != "capability.apigateway.http" {
		t.Fatalf("apim providerId/type = %q/%q", found[0].ProviderID, found[0].ResourceType)
	}
	o := gapObsMap(found[0])
	if o["location.region"] != "westeurope" || o["protocol"] != "http" || o["service.managed"] != true {
		t.Fatalf("apim reverse-map = %+v", o)
	}
}

// --- azkafka: capability.messaging.kafka via observeAzKafka ---

func TestDiscoverAzKafkaGolden(t *testing.T) {
	var sawList, sawBearer, sawAPIVersion bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/providers/Microsoft.EventHub/namespaces") && !strings.Contains(p, "/resourceGroups/"):
			sawList = true
			sawBearer = r.Header.Get("Authorization") == "Bearer test-token"
			sawAPIVersion = r.URL.Query().Get("api-version") == azKafkaAPIVersion
			_, _ = w.Write([]byte(`{"value":[
				{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.EventHub/namespaces/herekafka","name":"herekafka","location":"West Europe"},
				{"id":"/subscriptions/` + testSub + `/resourceGroups/rg2/providers/Microsoft.EventHub/namespaces/farkafka","name":"farkafka","location":"eastus"}
			]}`))
		case strings.HasSuffix(p, "/namespaces/herekafka"):
			_, _ = w.Write([]byte(`{"location":"westeurope","properties":{"kafkaEnabled":true,"zoneRedundant":true,"encryption":{"keySource":"Microsoft.KeyVault"}}}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":[]}`))
		}
	}))
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	found, diags, err := d.discoverAzKafka("westeurope")
	if err != nil {
		t.Fatal(err)
	}
	if !sawList || !sawBearer || !sawAPIVersion {
		t.Fatalf("azkafka list not seen bearer-authenticated with api-version: list=%v bearer=%v apiver=%v", sawList, sawBearer, sawAPIVersion)
	}
	if len(found) != 1 {
		t.Fatalf("azkafka discovery = %+v (diags %v)", found, diags)
	}
	if found[0].ProviderID != "azkafka:"+testSub+":rg1:herekafka" || found[0].ResourceType != "capability.messaging.kafka" {
		t.Fatalf("azkafka providerId/type = %q/%q", found[0].ProviderID, found[0].ResourceType)
	}
	o := gapObsMap(found[0])
	if o["location.region"] != "westeurope" || o["engine.protocol"] != "kafka/3" ||
		o["availability.class"] != "regional" || o["encryption.customerManagedKeys"] != true {
		t.Fatalf("azkafka reverse-map = %+v", o)
	}
}

// --- azurefiles: capability.storage.filesystem via observeAzFiles (account->share) ---

func TestDiscoverAzureFilesGolden(t *testing.T) {
	var sawList, sawBearer, sawAPIVersion bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/providers/Microsoft.Storage/storageAccounts") && !strings.Contains(p, "/resourceGroups/"):
			sawList = true
			sawBearer = r.Header.Get("Authorization") == "Bearer test-token"
			sawAPIVersion = r.URL.Query().Get("api-version") == storageAPIVersion
			_, _ = w.Write([]byte(`{"value":[
				{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/herefiles","name":"herefiles","location":"West Europe"},
				{"id":"/subscriptions/` + testSub + `/resourceGroups/rg2/providers/Microsoft.Storage/storageAccounts/farfiles","name":"farfiles","location":"eastus"}
			]}`))
		case strings.HasSuffix(p, "/storageAccounts/herefiles/fileServices/default/shares"):
			_, _ = w.Write([]byte(`{"value":[{"name":"shareone"}]}`))
		case strings.HasSuffix(p, "/storageAccounts/herefiles"):
			_, _ = w.Write([]byte(`{"location":"westeurope","kind":"StorageV2","sku":{"name":"Standard_ZRS"},"properties":{"encryption":{"keySource":"Microsoft.Keyvault"}}}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":[]}`))
		}
	}))
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	found, diags, err := d.discoverAzureFiles("westeurope")
	if err != nil {
		t.Fatal(err)
	}
	if !sawList || !sawBearer || !sawAPIVersion {
		t.Fatalf("azurefiles list not seen bearer-authenticated with api-version: list=%v bearer=%v apiver=%v", sawList, sawBearer, sawAPIVersion)
	}
	if len(found) != 1 {
		t.Fatalf("azurefiles discovery = %+v (diags %v)", found, diags)
	}
	if found[0].ProviderID != "azfiles:"+testSub+":rg1:herefiles:shareone" || found[0].ResourceType != "capability.storage.filesystem" {
		t.Fatalf("azurefiles providerId/type = %q/%q", found[0].ProviderID, found[0].ResourceType)
	}
	o := gapObsMap(found[0])
	if o["location.region"] != "westeurope" || o["protocol"] != "smb/3" ||
		o["availability.class"] != "regional" || o["encryption.customerManagedKeys"] != true {
		t.Fatalf("azurefiles reverse-map = %+v", o)
	}
}

// --- azurecdn: capability.cdn.distribution via observeAzureCDN (profile->endpoint, GLOBAL) ---

func TestDiscoverAzureCDNGolden(t *testing.T) {
	var sawList, sawBearer, sawAPIVersion bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/providers/Microsoft.Cdn/profiles") && !strings.Contains(p, "/resourceGroups/"):
			sawList = true
			sawBearer = r.Header.Get("Authorization") == "Bearer test-token"
			sawAPIVersion = r.URL.Query().Get("api-version") == azureCDNAPIVersion
			_, _ = w.Write([]byte(`{"value":[
				{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.Cdn/profiles/hereprofile","name":"hereprofile","location":"Global"}
			]}`))
		case strings.HasSuffix(p, "/profiles/hereprofile/endpoints/hereendpoint"):
			_, _ = w.Write([]byte(`{"properties":{"isHttpAllowed":false,"isHttpsAllowed":true,"origins":[{"properties":{"hostName":"origin.example.com"}}]}}`))
		case strings.HasSuffix(p, "/profiles/hereprofile/endpoints"):
			_, _ = w.Write([]byte(`{"value":[{"name":"hereendpoint"}]}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":[]}`))
		}
	}))
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	// region argument is ignored (CDN is global); pass a region no resource lives in.
	found, diags, err := d.discoverAzureCDN("eastus")
	if err != nil {
		t.Fatal(err)
	}
	if !sawList || !sawBearer || !sawAPIVersion {
		t.Fatalf("azurecdn list not seen bearer-authenticated with api-version: list=%v bearer=%v apiver=%v", sawList, sawBearer, sawAPIVersion)
	}
	if len(found) != 1 {
		t.Fatalf("azurecdn discovery = %+v (diags %v)", found, diags)
	}
	if found[0].ProviderID != "azcdn:"+testSub+":rg1:hereprofile:hereendpoint" || found[0].ResourceType != "capability.cdn.distribution" {
		t.Fatalf("azurecdn providerId/type = %q/%q", found[0].ProviderID, found[0].ResourceType)
	}
	o := gapObsMap(found[0])
	if o["viewer.protocol"] != "https-only" || o["origin.domain"] != "origin.example.com" || o["service.managed"] != true {
		t.Fatalf("azurecdn reverse-map = %+v", o)
	}
}

// --- dnszone: capability.dns.zone via observeAzureDNS (public + private types, GLOBAL) ---

func TestDiscoverDNSZoneGolden(t *testing.T) {
	var sawPubList, sawBearer, sawAPIVersion bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/providers/Microsoft.Network/dnsZones") && !strings.Contains(p, "/resourceGroups/"):
			sawPubList = true
			sawBearer = r.Header.Get("Authorization") == "Bearer test-token"
			sawAPIVersion = r.URL.Query().Get("api-version") == publicDNSAPIVersion
			_, _ = w.Write([]byte(`{"value":[
				{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.Network/dnsZones/example.com","name":"example.com","location":"global"}
			]}`))
		case strings.HasSuffix(p, "/providers/Microsoft.Network/privateDnsZones") && !strings.Contains(p, "/resourceGroups/"):
			_, _ = w.Write([]byte(`{"value":[
				{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.Network/privateDnsZones/internal.example","name":"internal.example","location":"global"}
			]}`))
		case strings.Contains(p, "/privateDnsZones/internal.example"):
			_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
		case strings.Contains(p, "/dnsZones/example.com"):
			_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":[]}`))
		}
	}))
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	// region argument is ignored (DNS zones are global); pass a region no resource lives in.
	found, diags, err := d.discoverDNSZone("eastus")
	if err != nil {
		t.Fatal(err)
	}
	if !sawPubList || !sawBearer || !sawAPIVersion {
		t.Fatalf("dnszone public list not seen bearer-authenticated with api-version: list=%v bearer=%v apiver=%v", sawPubList, sawBearer, sawAPIVersion)
	}
	if len(found) != 2 {
		t.Fatalf("dnszone discovery (want public + private) = %+v (diags %v)", found, diags)
	}
	byID := map[string]provider.Discovered{}
	for _, f := range found {
		byID[f.ProviderID] = f
	}
	pub, okPub := byID["adns:"+testSub+":rg1:pub:example.com"]
	priv, okPriv := byID["adns:"+testSub+":rg1:priv:internal.example"]
	if !okPub || !okPriv {
		t.Fatalf("dnszone providerIds = %+v", byID)
	}
	if pub.ResourceType != "capability.dns.zone" || priv.ResourceType != "capability.dns.zone" {
		t.Fatalf("dnszone ResourceType pub=%q priv=%q", pub.ResourceType, priv.ResourceType)
	}
	po := gapObsMap(pub)
	if po["zone.domain"] != "example.com" || po["network.publicExposure"] != true {
		t.Fatalf("dnszone public reverse-map = %+v", po)
	}
	pro := gapObsMap(priv)
	if pro["zone.domain"] != "internal.example" || pro["network.publicExposure"] != false {
		t.Fatalf("dnszone private reverse-map = %+v", pro)
	}
}
