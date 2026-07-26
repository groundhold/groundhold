// Azure Files network shell (D111): the ARM half of the capability.storage.filesystem
// driver. The constitutive composite is created in sequence under ONE binding:
// storage account (async, poll provisioningState) -> fileServices/default ->
// fileShares/{share}. The providerId is the share, carried from the account PUT
// (the first durable resource) so a partial is unknown/failed WITH the pid.
// Ownership is account tags; delete removes the account (which removes the share).
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func azFilesProviderID(sub, rg, account, share string) string {
	return "azfiles:" + sub + ":" + rg + ":" + account + ":" + share
}

func splitAzFilesProviderID(providerID string) (sub, rg, account, share string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 5 || parts[0] != "azfiles" {
		return "", "", "", "", fmt.Errorf("providerId %q is not azfiles:sub:rg:account:share", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) ||
		!storageNameOK.MatchString(parts[3]) || !azNameOK.MatchString(parts[4]) {
		return "", "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], parts[4], nil
}

func (d *Driver) createAzFiles(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAzFiles(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure files requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := azFilesProviderID(d.Subscription, rg, plan.Account, plan.Share)

	// ---- 1. storage account (the constitutive substrate; async) ----
	acctURL, _ := d.armURL(rg, "Microsoft.Storage/storageAccounts/"+plan.Account, storageAPIVersion)
	acctBody, _ := json.Marshal(plan.accountBody(d.tags(capability, environment)))
	if r := d.putAndPoll(acctURL, acctBody, pid, "storage account"); r != nil {
		return *r
	}

	// ---- 2. fileServices/default (leave defaults; ensures the service exists) ----
	fsURL, _ := d.armURL(rg, "Microsoft.Storage/storageAccounts/"+plan.Account+"/fileServices/default", storageAPIVersion)
	fsBody, _ := json.Marshal(map[string]any{"properties": map[string]any{}})
	if r := d.putSetting(fsURL, fsBody, pid, "file-services"); r != nil {
		return *r
	}

	// ---- 3. the file share (the leaf) ----
	shURL, _ := d.armURL(rg, "Microsoft.Storage/storageAccounts/"+plan.Account+"/fileServices/default/shares/"+plan.Share, storageAPIVersion)
	shBody, _ := json.Marshal(plan.shareBody())
	if r := d.putSetting(shURL, shBody, pid, "file-share"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type azFilesAccountDoc struct {
	Location   string                `json:"location"`
	Kind       string                `json:"kind"`
	Tags       map[string]string     `json:"tags"`
	Sku        struct{ Name string } `json:"sku"`
	Properties struct {
		Encryption struct {
			KeySource string `json:"keySource"`
		} `json:"encryption"`
	} `json:"properties"`
}

// azFilesProtocolForKind derives the wire protocol from the account kind:
// FileStorage (Premium) is provisioned for NFS; StorageV2 speaks SMB.
func azFilesProtocolForKind(kind string) string {
	if kind == "FileStorage" {
		return "nfs/4.1"
	}
	return "smb/3"
}

func (d *Driver) observeAzFiles(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, account, _, err := splitAzFilesProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	acctURL, _ := d.armURL(rg, "Microsoft.Storage/storageAccounts/"+account, storageAPIVersion)
	st, resp, e := d.doARM("GET", acctURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("storageAccounts.get: %v", e)
	}
	if st == http.StatusNotFound {
		return nil, []string{"storage account not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("storageAccounts.get: HTTP %d", st)
	}
	var doc azFilesAccountDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "storageAccounts.get", Cause: "body", Status: st}
	}
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "encryption.atRest", Value: true, Derivation: "config-intent"},
		{Path: "protocol", Value: azFilesProtocolForKind(doc.Kind), Derivation: "config-intent"},
	}
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: strings.ToLower(doc.Location), Derivation: "measured"})
	}
	switch doc.Sku.Name {
	case "Standard_LRS", "Premium_LRS":
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "zonal", Derivation: "measured"})
	case "Standard_ZRS", "Premium_ZRS":
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "regional", Derivation: "measured"})
	}
	if doc.Properties.Encryption.KeySource == "Microsoft.Keyvault" {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: true, Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteAzFiles(capability, environment, providerID string) provider.CreateResult {
	_, rg, account, _, err := splitAzFilesProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	acctURL, _ := d.armURL(rg, "Microsoft.Storage/storageAccounts/"+account, storageAPIVersion)
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
	var doc azFilesAccountDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "storage account tags do not match — refusing to delete a resource that is not ours"}
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
