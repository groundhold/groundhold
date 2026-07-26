// Azure Cosmos DB network shell (D112): the ARM half of the capability.database.nosql
// driver. A single databaseAccounts PUT polled to provisioningState=Succeeded; the
// account name is deterministic, so the providerId is knowable before the response
// (D29). Ownership is tags. observe reverse-maps region / continuous-backup (PITR)
// / CMK. deletion.protection is refused at build (Cosmos has no flag). D29/D87.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func cosmosProviderID(sub, rg, account string) string {
	return "cosmos:" + sub + ":" + rg + ":" + account
}

func splitCosmosProviderID(providerID string) (sub, rg, account string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "cosmos" {
		return "", "", "", fmt.Errorf("providerId %q is not cosmos:sub:rg:account", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || !cosmosNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) cosmosPath(account string) string {
	return "Microsoft.DocumentDB/databaseAccounts/" + account
}

func (d *Driver) createCosmos(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildCosmos(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure cosmos requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := cosmosProviderID(d.Subscription, rg, plan.Account)
	acctURL, _ := d.armURL(rg, d.cosmosPath(plan.Account), cosmosAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	if r := d.putAndPoll(acctURL, body, pid, "cosmos account"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type cosmosDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
		KeyVaultKeyUri    string `json:"keyVaultKeyUri"`
		BackupPolicy      struct {
			Type string `json:"type"`
		} `json:"backupPolicy"`
		Locations []struct {
			LocationName string `json:"locationName"`
		} `json:"locations"`
	} `json:"properties"`
}

func (d *Driver) observeCosmos(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, account, err := splitCosmosProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	acctURL, _ := d.armURL(rg, d.cosmosPath(account), cosmosAPIVersion)
	st, resp, e := d.doARM("GET", acctURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("databaseAccounts.get: %v", e)
	}
	if st == http.StatusNotFound {
		return nil, []string{"cosmos account not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("databaseAccounts.get: HTTP %d", st)
	}
	var doc cosmosDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "databaseAccounts.get", Cause: "body", Status: st}
	}
	region := doc.Location
	if region == "" && len(doc.Properties.Locations) > 0 {
		region = doc.Properties.Locations[0].LocationName
	}
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "availability.class", Value: "regional", Derivation: "config-intent"},
		{Path: "backup.pointInTimeRecovery", Value: doc.Properties.BackupPolicy.Type == "Continuous", Derivation: "measured"},
	}
	if region != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: strings.ToLower(region), Derivation: "measured"})
	}
	if doc.Properties.KeyVaultKeyUri != "" {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: true, Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteCosmos(capability, environment, providerID string) provider.CreateResult {
	_, rg, account, err := splitCosmosProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	acctURL, _ := d.armURL(rg, d.cosmosPath(account), cosmosAPIVersion)
	st, resp, e := d.doARM("GET", acctURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc cosmosDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "cosmos account tags do not match — refusing to delete a resource that is not ours"}
	}
	dst, dresp, de := d.doARM("DELETE", acctURL, nil)
	if de != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", de)}
	}
	if dst == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if dst >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", dst)}
	}
	if dst < 200 || dst >= 300 {
		if r := provider.MutationResult(dst, azErrCode(dresp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", dst, mutDetailAz(dresp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
