// Azure managed disk network shell (D369): auth, HTTP, polling and the reverse
// mapping. No semantics here — those are in azuredisk.go.
//
// The ARM plumbing is NOT reimplemented: `putAndPoll` already carries the D29
// discipline for this API family AND the foreign-upsert refusal (D254) — a PUT at
// a named path would otherwise happily overwrite a resource somebody else owns,
// which on a STATEFUL capability means overwriting their data. Writing a second
// one would have been the easy mistake: a copy diverges, and the copy is always
// the one missing the fix.
//
// availability.class is read back from the SKU, which is where Azure keeps it.
// The suffix is the whole of the durability guarantee: _ZRS spans zones, _LRS
// does not.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// azureDiskAPIVersion pins the Compute disks API this driver targets.
const azureDiskAPIVersion = "2024-03-02"

func azureDiskProviderID(sub, rg, name string) string {
	return "azdisk:" + sub + ":" + rg + ":" + name
}

func splitAzureDiskProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "azdisk" {
		return "", "", "", fmt.Errorf("providerId %q is not azdisk:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || parts[3] == "" {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) azureDiskPath(name string) string {
	return "Microsoft.Compute/disks/" + name
}

// azureDiskDoc is the slice of disks.get this driver reads.
type azureDiskDoc struct {
	Location string            `json:"location"`
	Tags     map[string]string `json:"tags"`
	Zones    []string          `json:"zones"`
	SKU      struct {
		Name string `json:"name"`
	} `json:"sku"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
		Encryption        struct {
			Type                string `json:"type"`
			DiskEncryptionSetID string `json:"diskEncryptionSetId"`
		} `json:"encryption"`
	} `json:"properties"`
}

// getAzureDisk reads one disk. `found=false` with no error means the API answered
// and the disk is not there — different from "the read failed", and the
// difference is what keeps a delete idempotent instead of guessing.
func (d *Driver) getAzureDisk(rg, name string) (azureDiskDoc, bool, error) {
	url, _ := d.armURL(rg, d.azureDiskPath(name), azureDiskAPIVersion)
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil {
		return azureDiskDoc{}, false, &armReadError{Op: "disks.get", Cause: "transport", Detail: e.Error()}
	}
	if st == http.StatusNotFound {
		return azureDiskDoc{}, false, nil
	}
	if st < 200 || st >= 300 {
		return azureDiskDoc{}, false, &armReadError{Op: "disks.get", Cause: "http", Status: st, Code: azErrCode(resp)}
	}
	var doc azureDiskDoc
	if json.Unmarshal(resp, &doc) != nil {
		return azureDiskDoc{}, false, &armReadError{Op: "disks.get", Cause: "body", Status: st}
	}
	return doc, true, nil
}

func (d *Driver) createAzureDisk(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {

	plan, err := BuildAzureDisk(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure disk requires implementation.resource_group (groundhold does not create resource groups)"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := azureDiskProviderID(d.Subscription, rg, plan.Name)
	url, _ := d.armURL(rg, d.azureDiskPath(plan.Name), azureDiskAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	// putAndPoll refuses a foreign upsert (D254) before it writes anything — on a
	// stateful capability that refusal is what stands between a name collision and
	// overwriting somebody else's data.
	if r := d.putAndPoll(url, body, pid, "managed disk"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// observeAzureDisk is the reverse mapping. encryption.atRest is reported as a
// CONSTANT true because a managed disk is always encrypted with at least a
// platform key — a fact about the platform, not a reading of this resource, so it
// is tagged config-intent rather than measured.
func (d *Driver) observeAzureDisk(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitAzureDiskProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	doc, found, rerr := d.getAzureDisk(rg, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"managed disk not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: doc.Location, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "encryption.atRest", Value: true, Derivation: "config-intent"},
		// A platform key is NOT customer-managed: reporting true on its strength
		// would certify a BYOK control the customer cannot revoke.
		{Path: "encryption.customerManagedKeys",
			Value:      doc.Properties.Encryption.DiskEncryptionSetID != "",
			Derivation: "measured"},
	}
	var unread []string
	// The SKU is where the durability guarantee lives. A disk whose SKU came back
	// empty is one whose class we do not know — and defaulting to `zonal` would
	// pass a "must survive a zone failure" constraint the disk may violate, while
	// defaulting to `regional` would fail one it may satisfy. Neither is a reading.
	if doc.SKU.Name == "" {
		unread = append(unread, "disk sku unread — zone redundancy (availability.class) not determined")
	} else {
		class := "zonal"
		if azDiskSKUIsZoneRedundant(doc.SKU.Name) {
			class = "regional"
		}
		obs = append(obs, provider.Observation{
			Path: "availability.class", Value: class, Derivation: "measured"})
	}
	return obs, unread, nil
}

// deleteAzureDisk destroys the disk AND the data on it, and refuses to touch one
// whose ownership tags are not ours.
//
// The stateful gates (D47) sit above this in the executor: reaching here at all
// means the plan pinned this disk as a retirement target and the operator
// consented to the data loss. What this function owes them is that it deletes
// exactly what was pinned and nothing else.
func (d *Driver) deleteAzureDisk(capability, environment, providerID string) provider.CreateResult {
	sub, rg, name, err := splitAzureDiskProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	doc, found, rerr := d.getAzureDisk(rg, name)
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
			Reason: "managed disk tags do not match — refusing to destroy data that is not ours"}
	}
	url, _ := d.armURL(rg, d.azureDiskPath(name), azureDiskAPIVersion)
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

// discoverAzureDisks enumerates managed disks in the subscription as
// capability.storage.block. Every observable service must be discoverable
// (spec/drivers.md §2) — and an unmanaged disk nobody is watching is one of the
// more expensive blind spots a proactive posture can have, because the data on it
// is already there.
func (d *Driver) discoverAzureDisks(region string) ([]provider.Discovered, []string, error) {
	url := d.BaseURL + "/subscriptions/" + d.Subscription +
		"/providers/Microsoft.Compute/disks?api-version=" + azureDiskAPIVersion
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("disks.list: %s", azReadWhy(0, nil, e))
	}
	if st < 200 || st >= 300 {
		return nil, nil, fmt.Errorf("disks.list: %s", azReadWhy(st, resp, nil))
	}
	var page struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &page) != nil {
		return nil, nil, &armReadError{Op: "disks.list", Cause: "body", Status: st}
	}
	var out []provider.Discovered
	var diags []string
	for _, item := range page.Value {
		if item.Name == "" || (region != "" && item.Location != region) {
			continue
		}
		rg := resourceGroupOfID(item.ID)
		if rg == "" {
			diags = append(diags, item.Name+": resource group not readable from the resource id")
			continue
		}
		pid := azureDiskProviderID(d.Subscription, rg, item.Name)
		obs, odiags, oerr := d.observeAzureDisk("", pid)
		if oerr != nil {
			diags = append(diags, item.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, item.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.storage.block",
			Observations: obs,
		})
	}
	return out, diags, nil
}
