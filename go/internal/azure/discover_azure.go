package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"groundhold/internal/provider"
)

// List enumerates existing azure resources in the region as vocabulary
// capabilities — the azure half of the D52 brownfield path (discover ->
// adopt). Strictly read-only. Each service is swept independently: a
// service that errors becomes a diagnostic, never a hard failure that
// hides another's resources.
func (d *Driver) List(region string) ([]provider.Discovered, []string, error) {
	if !subOK.MatchString(d.Subscription) {
		return nil, nil, fmt.Errorf("azure discovery requires a subscription GUID")
	}
	if region == "" {
		return nil, nil, fmt.Errorf("azure discovery requires a region")
	}
	var out []provider.Discovered
	var diags []string
	for _, e := range d.serviceDiscoverers() {
		found, ds, err := e.fn(region)
		if err != nil {
			diags = append(diags, err.Error())
			continue
		}
		out = append(out, found...)
		diags = append(diags, ds...)
	}
	return out, diags, nil
}

// azSweep pairs a read-only discovery sweep with the SERVICE token(s) it covers.
// Pairing (not a token->fn map) is deliberate: discoverServiceBus alone covers
// TWO tokens (servicebusqueue + servicebustopic) in one namespaces sweep, so the
// tokens must travel WITH the function that lists them — the token declaration
// cannot drift from what List actually runs.
type azSweep struct {
	tokens []string
	fn     func(string) ([]provider.Discovered, []string, error)
}

// serviceDiscoverers is the azure discovery registry. List iterates it (each fn
// once); TestCertifyAzureDriver asserts via provider.CertifyDiscoverability that
// every certified service is either a token here or a declared non-listable
// exemption — so no Observe ships undiscoverable (spec/drivers.md §2).
func (d *Driver) serviceDiscoverers() []azSweep {
	return []azSweep{
		// original production-stack coverage
		{[]string{"blob"}, d.discoverBlob},
		{[]string{"flexpostgres"}, d.discoverPostgres},
		{[]string{"cosmos"}, d.discoverCosmos},
		{[]string{"rediscache"}, d.discoverRedis},
		{[]string{"servicebusqueue", "servicebustopic"}, d.discoverServiceBus},
		{[]string{"containerapps"}, d.discoverContainerApps},
		{[]string{"containerappsjob"}, d.discoverContainerAppsJobs},
		{[]string{"vnet"}, d.discoverVNet},
		{[]string{"loadbalancer"}, d.discoverLoadBalancers},
		{[]string{"keyvault"}, d.discoverKeyVault},
		{[]string{"managedidentity"}, d.discoverManagedIdentity},
		{[]string{"customroledef"}, d.discoverCustomRoles},
		{[]string{"roleassignment"}, d.discoverRoleAssignments},
		// discoverability backfill
		{[]string{"acr"}, d.discoverACR},
		{[]string{"azvm"}, d.discoverAzureVMs},
		{[]string{"azdisk"}, d.discoverAzureDisks},
		{[]string{"azimage"}, d.discoverAzureImages},
		{[]string{"azvmss"}, d.discoverAzureVMSS},
		{[]string{"aisearch"}, d.discoverAISearch},
		{[]string{"apim"}, d.discoverAPIM},
		{[]string{"azkafka"}, d.discoverAzKafka},
		{[]string{"azurefiles"}, d.discoverAzureFiles},
		{[]string{"azurecdn"}, d.discoverAzureCDN},
		{[]string{"dnszone"}, d.discoverDNSZone},
		{[]string{"eventhubs"}, d.discoverEventHubs},
		{[]string{"frontdoorwaf"}, d.discoverFrontDoorWAF},
		{[]string{"metricalert"}, d.discoverMetricAlert},
		{[]string{"portaldash"}, d.discoverPortalDash},
		{[]string{"scheduledquery"}, d.discoverScheduledQuery},
		{[]string{"webtest"}, d.discoverWebTest},
		// posture parity (D76)
		{[]string{"consumptionbudget"}, d.discoverConsumptionBudget},
		{[]string{"loganalytics"}, d.discoverLogAnalytics},
		{[]string{"activitylog"}, d.discoverActivityLog},
		{[]string{"defender"}, d.discoverDefender},
		{[]string{"azureopenai"}, d.discoverAzureOpenAI},
		// cluster family (D76 parity)
		{[]string{"aks"}, d.discoverAKS},
		{[]string{"aks-addon"}, d.discoverAKSAddon},
		{[]string{"aks-workloadidentity"}, d.discoverAKSWorkloadIdentity},
		// backup + email (D76 parity, fala 4)
		{[]string{"backuppolicy"}, d.discoverBackupPolicy},
		{[]string{"backupvault"}, d.discoverBackupVault},
		{[]string{"acsemail"}, d.discoverACSEmail},
	}
}

// DiscoverableServices flattens the registry's covered tokens (sorted), so the
// discoverability gate proves coverage rather than trusting it.
func (d *Driver) DiscoverableServices() []string {
	var out []string
	for _, e := range d.serviceDiscoverers() {
		out = append(out, e.tokens...)
	}
	sort.Strings(out)
	return out
}

// NonListableServices names the certified services that are NOT standalone
// listable resources, with a categorical reason — the only sanctioned exemption
// from the discoverability gate.
func (d *Driver) NonListableServices() map[string]string {
	return map[string]string{
		"changefeed":  "provisioned-feed", // the Event Grid feed groundhold PROVISIONS, not a resource it lists
		"keyvaultkey": "sub-resource",     // a key inside a vault, enumerated under it
		"dnsrecord":   "sub-resource",     // a record set inside a DNS zone, enumerated under it
	}
}

// discoverBlob enumerates Blob containers in the region as
// capability.storage.object: storageAccounts.list -> containers per
// in-region account -> the same reverse map observe uses.
func (d *Driver) discoverBlob(region string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=%s",
		d.BaseURL, d.Subscription, storageAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("storageAccounts.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("storageAccounts.list: HTTP %d", st)
	}
	var accts struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &accts) != nil {
		return nil, nil, &armReadError{Op: "storageAccounts.list", Cause: "body", Status: st}
	}

	want := azRegion(region)
	var out []provider.Discovered
	var diags []string
	for _, a := range accts.Value {
		if azRegion(a.Location) != want {
			continue // lives in another region — not this sweep
		}
		rg := resourceGroupOf(a.ID)
		if rg == "" {
			diags = append(diags, a.Name+": resource group unparseable from id")
			continue
		}
		cURL, err := d.armURL(rg, d.acctPath(a.Name)+"/blobServices/default/containers", storageAPIVersion)
		if err != nil {
			diags = append(diags, a.Name+": "+err.Error())
			continue
		}
		cst, cresp, cerr := d.doARM("GET", cURL, nil)
		if cerr != nil {
			diags = append(diags, a.Name+": "+armTransport("containers.list", cerr).Error())
			continue
		}
		if cst != http.StatusOK {
			diags = append(diags, a.Name+": "+armHTTP("containers.list", cst, cresp).Error())
			continue
		}
		var conts struct {
			Value []struct {
				Name string `json:"name"`
			} `json:"value"`
		}
		_ = json.Unmarshal(cresp, &conts)
		for _, c := range conts.Value {
			pid := blobProviderID(d.Subscription, rg, a.Name, c.Name)
			obs, odiags, oerr := d.observeBlob("", pid)
			if oerr != nil {
				diags = append(diags, a.Name+"/"+c.Name+": "+oerr.Error())
				continue
			}
			for _, dg := range odiags {
				diags = append(diags, a.Name+"/"+c.Name+": "+dg)
			}
			out = append(out, provider.Discovered{
				ProviderID:   pid,
				ResourceType: "capability.storage.object",
				Observations: obs,
			})
		}
	}
	return out, diags, nil
}

// discoverPostgres enumerates PostgreSQL flexible servers in the region as
// capability.database.relational, reusing the same reverse map observe uses.
func (d *Driver) discoverPostgres(region string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.DBforPostgreSQL/flexibleServers?api-version=%s",
		d.BaseURL, d.Subscription, pgAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("flexibleServers.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("flexibleServers.list: HTTP %d", st)
	}
	var servers struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &servers) != nil {
		return nil, nil, &armReadError{Op: "flexibleServers.list", Cause: "body", Status: st}
	}
	want := azRegion(region)
	var out []provider.Discovered
	var diags []string
	for _, s := range servers.Value {
		if azRegion(s.Location) != want {
			continue
		}
		rg := resourceGroupOf(s.ID)
		if rg == "" {
			diags = append(diags, s.Name+": resource group unparseable from id")
			continue
		}
		pid := flexProviderID(d.Subscription, rg, s.Name)
		obs, odiags, oerr := d.observeFlexServer("", pid)
		if oerr != nil {
			diags = append(diags, s.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, s.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.database.relational",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// resourceGroupOf pulls the resource group out of an ARM resource id
// (.../resourceGroups/<rg>/providers/...); "" when absent.
func resourceGroupOf(armID string) string {
	parts := strings.Split(armID, "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			return parts[i+1]
		}
	}
	return ""
}

// azRegion normalizes an Azure location for comparison
// ("West Europe" and "westeurope" both become "westeurope").
func azRegion(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, " ", ""))
}

// discoverRedis enumerates Azure Cache for Redis instances in the region as
// capability.cache.keyvalue.
func (d *Driver) discoverRedis(region string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Cache/redis?api-version=%s",
		d.BaseURL, d.Subscription, redisAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("redis.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("redis.list: HTTP %d", st)
	}
	var caches struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &caches) != nil {
		return nil, nil, &armReadError{Op: "redis.list", Cause: "body", Status: st}
	}
	want := azRegion(region)
	var out []provider.Discovered
	var diags []string
	for _, c := range caches.Value {
		if azRegion(c.Location) != want {
			continue
		}
		rg := resourceGroupOf(c.ID)
		if rg == "" {
			diags = append(diags, c.Name+": resource group unparseable from id")
			continue
		}
		pid := redisAzureProviderID(d.Subscription, rg, c.Name)
		obs, odiags, oerr := d.observeRedisAzure("", pid)
		if oerr != nil {
			diags = append(diags, c.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, c.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.cache.keyvalue",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverServiceBus enumerates Service Bus queues and topics in the region
// as capability.messaging.queue and capability.messaging.topic: list
// namespaces, then the entities under each in-region namespace, then the
// same reverse map observe uses.
func (d *Driver) discoverServiceBus(region string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.ServiceBus/namespaces?api-version=%s",
		d.BaseURL, d.Subscription, serviceBusAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("servicebus namespaces.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("servicebus namespaces.list: HTTP %d", st)
	}
	var namespaces struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &namespaces) != nil {
		return nil, nil, &armReadError{Op: "servicebus namespaces.list", Cause: "body", Status: st}
	}
	want := azRegion(region)
	var out []provider.Discovered
	var diags []string
	for _, ns := range namespaces.Value {
		if azRegion(ns.Location) != want {
			continue
		}
		rg := resourceGroupOf(ns.ID)
		if rg == "" {
			diags = append(diags, ns.Name+": resource group unparseable from id")
			continue
		}
		out = append(out, d.sbEntities("sbq", "queues", "capability.messaging.queue", rg, ns.Name, &diags)...)
		out = append(out, d.sbEntities("sbt", "topics", "capability.messaging.topic", rg, ns.Name, &diags)...)
	}
	return out, diags, nil
}

// sbEntities lists one entity kind (queues or topics) under a namespace and
// projects each through sbObserve. Errors append to diags and yield nothing.
func (d *Driver) sbEntities(kind, path, resourceType, rg, ns string, diags *[]string) []provider.Discovered {
	eURL, err := d.armURL(rg, d.sbNamespacePath(ns)+"/"+path, serviceBusAPIVersion)
	if err != nil {
		*diags = append(*diags, ns+": "+err.Error())
		return nil
	}
	st, resp, err := d.doARM("GET", eURL, nil)
	if err != nil || st != http.StatusOK {
		*diags = append(*diags, ns+"/"+path+": "+azReadWhy(st, resp, err))
		return nil
	}
	var ents struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	_ = json.Unmarshal(resp, &ents)
	var out []provider.Discovered
	for _, e := range ents.Value {
		pid := sbProviderID(kind, d.Subscription, rg, ns, e.Name)
		obs, odiags, oerr := d.sbObserve("", pid)
		if oerr != nil {
			*diags = append(*diags, ns+"/"+e.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			*diags = append(*diags, ns+"/"+e.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: resourceType,
			Observations: obs,
		})
	}
	return out
}

// discoverCosmos enumerates Cosmos DB accounts in the region as
// capability.database.nosql, reusing the same reverse map observe uses.
func (d *Driver) discoverCosmos(region string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.DocumentDB/databaseAccounts?api-version=%s",
		d.BaseURL, d.Subscription, cosmosAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("databaseAccounts.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("databaseAccounts.list: HTTP %d", st)
	}
	var accts struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &accts) != nil {
		return nil, nil, &armReadError{Op: "databaseAccounts.list", Cause: "body", Status: st}
	}
	want := azRegion(region)
	var out []provider.Discovered
	var diags []string
	for _, a := range accts.Value {
		if azRegion(a.Location) != want {
			continue
		}
		rg := resourceGroupOf(a.ID)
		if rg == "" {
			diags = append(diags, a.Name+": resource group unparseable from id")
			continue
		}
		pid := cosmosProviderID(d.Subscription, rg, a.Name)
		obs, odiags, oerr := d.observeCosmos("", pid)
		if oerr != nil {
			diags = append(diags, a.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, a.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.database.nosql",
			Observations: obs,
		})
	}
	return out, diags, nil
}
