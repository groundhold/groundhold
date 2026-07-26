// Azure virtual machine network shell (D360): ARM calls, LRO polling and the
// reverse mapping. No semantics here — those are in azurevm.go.
//
// Two things are worth knowing before reading further.
//
// The create reuses `putAndPoll`, which already refuses to PUT over a resource
// that is not ours (D254). On ARM a PUT is an UPSERT, so without that check a
// name collision would silently overwrite a stranger's machine rather than
// refusing — the Azure equivalent of the tag check EC2 does and the label check
// GCE does, and it is already implemented once, correctly.
//
// Public exposure needs a SECOND read. An Azure VM references a network
// interface, and the interface carries the public address; the machine document
// says nothing about it. So observe reads the NIC, and when that read fails the
// attribute is reported UNREAD rather than defaulted — a silent `false` would
// pass an "is it private?" constraint on a machine that is on the internet.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// azureVMAPIVersion pins the Compute API this driver targets.
const azureVMAPIVersion = "2024-07-01"

// azureNICAPIVersion pins the Network API used for the exposure read. It reuses
// the version already registered for Microsoft.Network rather than introducing a
// second one: every distinct pin is drift surface the canary has to watch.
const azureNICAPIVersion = "2023-11-01"

func azureVMProviderID(sub, rg, name string) string {
	return "azvm:" + sub + ":" + rg + ":" + name
}

func splitAzureVMProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "azvm" {
		return "", "", "", fmt.Errorf("providerId %q is not azvm:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || parts[3] == "" {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) azureVMPath(name string) string {
	return "Microsoft.Compute/virtualMachines/" + name
}

// azureVMDoc is the slice of virtualMachines.get this driver reads.
type azureVMDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
		StorageProfile    struct {
			OSDisk struct {
				ManagedDisk struct {
					DiskEncryptionSet *struct {
						ID string `json:"id"`
					} `json:"diskEncryptionSet"`
				} `json:"managedDisk"`
			} `json:"osDisk"`
		} `json:"storageProfile"`
		NetworkProfile struct {
			NetworkInterfaces []struct {
				ID string `json:"id"`
			} `json:"networkInterfaces"`
		} `json:"networkProfile"`
	} `json:"properties"`
}

func (d *Driver) getAzureVM(rg, name string) (azureVMDoc, bool, error) {
	url, _ := d.armURL(rg, d.azureVMPath(name), azureVMAPIVersion)
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil {
		return azureVMDoc{}, false, &armReadError{Op: "virtualMachines.get", Cause: "transport", Detail: e.Error()}
	}
	if st == http.StatusNotFound {
		return azureVMDoc{}, false, nil
	}
	if st != http.StatusOK {
		return azureVMDoc{}, false, &armReadError{Op: "virtualMachines.get", Cause: "http", Status: st}
	}
	var doc azureVMDoc
	if json.Unmarshal(resp, &doc) != nil {
		return azureVMDoc{}, false, &armReadError{Op: "virtualMachines.get", Cause: "body", Status: st}
	}
	return doc, true, nil
}

// nicHasPublicIP reads the interface the machine references. Returns
// (public, known): `known=false` means the read did not answer, and the caller
// must report the attribute unread rather than choose a value for it.
func (d *Driver) nicHasPublicIP(nicID string) (public bool, known bool) {
	if nicID == "" {
		return false, false
	}
	url := d.BaseURL + nicID + "?api-version=" + azureNICAPIVersion
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil || st != http.StatusOK {
		return false, false
	}
	var doc struct {
		Properties struct {
			IPConfigurations []struct {
				Properties struct {
					PublicIPAddress *struct {
						ID string `json:"id"`
					} `json:"publicIPAddress"`
				} `json:"properties"`
			} `json:"ipConfigurations"`
		} `json:"properties"`
	}
	if json.Unmarshal(resp, &doc) != nil {
		return false, false
	}
	for _, cfg := range doc.Properties.IPConfigurations {
		if cfg.Properties.PublicIPAddress != nil && cfg.Properties.PublicIPAddress.ID != "" {
			return true, true
		}
	}
	return false, true
}

func (d *Driver) createAzureVM(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {

	plan, err := BuildAzureVM(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure vm requires implementation.resource_group (groundhold does not create resource groups)"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := azureVMProviderID(d.Subscription, rg, plan.Name)
	url, _ := d.armURL(rg, d.azureVMPath(plan.Name), azureVMAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	// putAndPoll refuses a foreign upsert (D254) before it writes anything.
	if r := d.putAndPoll(url, body, pid, "virtual machine"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

func (d *Driver) observeAzureVM(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitAzureVMProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	doc, found, rerr := d.getAzureVM(rg, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"virtual machine not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: doc.Location, Derivation: "measured"},
		{Path: "availability.class", Value: "zonal", Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// Managed disks are always encrypted at rest — a fact about the platform,
		// not a reading of this resource, so it is config-intent rather than measured.
		{Path: "encryption.atRest", Value: true, Derivation: "config-intent"},
		{Path: "encryption.customerManagedKeys",
			Value:      doc.Properties.StorageProfile.OSDisk.ManagedDisk.DiskEncryptionSet != nil,
			Derivation: "measured"},
	}
	var unread []string
	nicID := ""
	if n := doc.Properties.NetworkProfile.NetworkInterfaces; len(n) > 0 {
		nicID = n[0].ID
	}
	public, known := d.nicHasPublicIP(nicID)
	if known {
		obs = append(obs, provider.Observation{
			Path: "network.publicExposure", Value: public, Derivation: "measured"})
	} else {
		// Defaulting here would be the dangerous choice: a silent false passes an
		// "is it private?" constraint on a machine that may be on the internet.
		unread = append(unread, "network interface unread — public exposure not determined")
	}
	return obs, unread, nil
}

func (d *Driver) deleteAzureVM(capability, environment, providerID string) provider.CreateResult {
	sub, rg, name, err := splitAzureVMProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	doc, found, rerr := d.getAzureVM(rg, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "virtual machine tags do not match — refusing to delete a machine that is not ours"}
	}
	url, _ := d.armURL(rg, d.azureVMPath(name), azureVMAPIVersion)
	dst, dresp, de := d.doARM("DELETE", url, nil)
	switch {
	case de != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", de)}
	case dst == http.StatusNotFound:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	case dst >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete HTTP %d (server error — may have landed) — reconcile", dst)}
	case dst < 200 || dst >= 300:
		if r := provider.MutationResult(dst, azErrCode(dresp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed",
			Reason: fmt.Sprintf("delete HTTP %d: %s", dst, mutDetailAz(dresp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// discoverAzureVMs enumerates machines in the subscription as
// capability.compute.instance. Every observable service must be discoverable
// (spec/drivers.md §2) — a machine the proactive posture cannot see is a machine
// nobody is watching.
func (d *Driver) discoverAzureVMs(region string) ([]provider.Discovered, []string, error) {
	url := d.BaseURL + "/subscriptions/" + d.Subscription +
		"/providers/Microsoft.Compute/virtualMachines?api-version=" + azureVMAPIVersion
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil {
		return nil, nil, &armReadError{Op: "virtualMachines.listAll", Cause: "transport", Detail: e.Error()}
	}
	if st != http.StatusOK {
		return nil, nil, &armReadError{Op: "virtualMachines.listAll", Cause: "http", Status: st}
	}
	var page struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &page) != nil {
		return nil, nil, &armReadError{Op: "virtualMachines.listAll", Cause: "body", Status: st}
	}
	var out []provider.Discovered
	var diags []string
	for _, vm := range page.Value {
		if vm.Name == "" || (region != "" && vm.Location != region) {
			continue
		}
		rg := resourceGroupOfID(vm.ID)
		if rg == "" {
			diags = append(diags, vm.Name+": resource id carried no resource group")
			continue
		}
		pid := azureVMProviderID(d.Subscription, rg, vm.Name)
		obs, odiags, oerr := d.observeAzureVM("", pid)
		if oerr != nil {
			diags = append(diags, vm.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, vm.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.compute.instance",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// resourceGroupOfID lifts the resource group out of an ARM resource id.
func resourceGroupOfID(id string) string {
	const marker = "/resourceGroups/"
	i := strings.Index(id, marker)
	if i < 0 {
		return ""
	}
	rest := id[i+len(marker):]
	if j := strings.Index(rest, "/"); j >= 0 {
		return rest[:j]
	}
	return rest
}
