package azure

import (
	"testing"

	"groundhold/internal/provider"
)

// azureCertifyServices is the authoritative set of SERVICE tokens the Azure
// driver observes/provisions — both certification gates run over the same set.
var azureCertifyServices = []string{"loadbalancer", "changefeed", "vnet", "blob", "containerapps",
	"flexpostgres", "servicebusqueue", "servicebustopic", "keyvault", "rediscache", "dnszone", "dnsrecord", "roleassignment", "customroledef", "metricalert", "portaldash", "webtest", "scheduledquery", "acr", "azurefiles", "cosmos", "aisearch", "eventhubs", "azkafka", "frontdoorwaf", "azurecdn", "apim", "containerappsjob", "managedidentity", "keyvaultkey", "consumptionbudget", "loganalytics", "activitylog", "defender", "azureopenai", "aks", "aks-addon", "aks-workloadidentity", "backuppolicy", "acsemail", "backupvault", "azvm", "azdisk", "azimage", "azvmss"}

// TestCertifyAzureDriver runs the network-free certification battery (dispatch
// fails closed, providerId charset, permission tables non-empty + quiet-reads).
func TestCertifyAzureDriver(t *testing.T) {
	provider.CertifyDriver(t, NewDriver(testSub), azureCertifyServices)
}

// TestAzureDiscoverabilityComplete enforces spec/drivers.md §2: every observable
// Azure service is either covered by a List sweep or a declared non-listable
// feed/sub-resource.
func TestAzureDiscoverabilityComplete(t *testing.T) {
	provider.CertifyDiscoverability(t, NewDriver(testSub), azureCertifyServices)
}

// TestAzureParityComplete enforces spec/drivers.md §8: every certified Azure service
// declares the capability TYPE it fulfils, so the parity matrix is proven.
func TestAzureParityComplete(t *testing.T) {
	provider.CertifyParity(t, NewDriver(testSub), azureCertifyServices)
}
