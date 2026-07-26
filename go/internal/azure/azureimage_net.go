// Azure managed image network shell (D370): auth, HTTP and the reverse mapping.
// No semantics here — those are in azureimage.go.
//
// There is no mutation shell, because there is nothing to mutate: this is a
// witness driver (D177). What replaces the D29 create/delete discipline is the
// read discipline, which is the only discipline a witness has: every fact is
// either MEASURED from the API, stated as a CONFIG-INTENT property of the
// platform, or reported UNREAD. Nothing in between, and nothing defaulted.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// azureImageAPIVersion pins the Compute images API this driver targets.
const azureImageAPIVersion = "2024-07-01"

func azureImageProviderID(sub, rg, name string) string {
	return "azimage:" + sub + ":" + rg + ":" + name
}

func splitAzureImageProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "azimage" {
		return "", "", "", fmt.Errorf("providerId %q is not azimage:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || parts[3] == "" {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) azureImagePath(name string) string {
	return "Microsoft.Compute/images/" + name
}

// azureImageDoc is the slice of images.get this driver reads.
type azureImageDoc struct {
	Location   string `json:"location"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
		StorageProfile    struct {
			OSDisk struct {
				DiskEncryptionSet *struct {
					ID string `json:"id"`
				} `json:"diskEncryptionSet"`
			} `json:"osDisk"`
		} `json:"storageProfile"`
	} `json:"properties"`
}

func (d *Driver) getAzureImage(rg, name string) (azureImageDoc, bool, error) {
	url, _ := d.armURL(rg, d.azureImagePath(name), azureImageAPIVersion)
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil {
		return azureImageDoc{}, false, &armReadError{Op: "images.get", Cause: "transport", Detail: e.Error()}
	}
	if st == http.StatusNotFound {
		return azureImageDoc{}, false, nil
	}
	if st < 200 || st >= 300 {
		return azureImageDoc{}, false, &armReadError{Op: "images.get", Cause: "http", Status: st, Code: azErrCode(resp)}
	}
	var doc azureImageDoc
	if json.Unmarshal(resp, &doc) != nil {
		return azureImageDoc{}, false, &armReadError{Op: "images.get", Cause: "body", Status: st}
	}
	return doc, true, nil
}

// observeAzureImage is the whole driver.
func (d *Driver) observeAzureImage(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitAzureImageProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	doc, found, rerr := d.getAzureImage(rg, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"managed image not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: doc.Location, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// The image's disks are managed disks, always encrypted at rest — a fact
		// about the platform, not a reading of this resource.
		{Path: "encryption.atRest", Value: true, Derivation: "config-intent"},
		{Path: "encryption.customerManagedKeys",
			Value:      doc.Properties.StorageProfile.OSDisk.DiskEncryptionSet != nil,
			Derivation: "measured"},
		// CONFIG-INTENT, deliberately: a Microsoft.Compute/images resource cannot be
		// shared outside its subscription at all (cross-tenant sharing lives in a
		// Compute Gallery, a different type). Marking this `measured` would claim the
		// driver read a sharing setting and found it off, when the truth is that
		// there is no such setting to read.
		{Path: "network.publicExposure", Value: false, Derivation: "config-intent"},
	}
	// sourceProvenance has no readable field on a managed image (a gallery image
	// VERSION can be signed; this is not one). Left unobserved so a hard constraint
	// on it stays `unknown` and blocks, rather than being answered with an invented
	// `false`.
	unread := []string{
		"sourceProvenance unread — a managed image carries no readable build " +
			"attestation; a constraint on it cannot be proven from here",
	}
	return obs, unread, nil
}

// discoverAzureImages enumerates the managed images in the subscription.
func (d *Driver) discoverAzureImages(region string) ([]provider.Discovered, []string, error) {
	url := d.BaseURL + "/subscriptions/" + d.Subscription +
		"/providers/Microsoft.Compute/images?api-version=" + azureImageAPIVersion
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("images.list: %s", azReadWhy(0, nil, e))
	}
	if st < 200 || st >= 300 {
		return nil, nil, fmt.Errorf("images.list: %s", azReadWhy(st, resp, nil))
	}
	var page struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &page) != nil {
		return nil, nil, &armReadError{Op: "images.list", Cause: "body", Status: st}
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
		pid := azureImageProviderID(d.Subscription, rg, item.Name)
		obs, odiags, oerr := d.observeAzureImage("", pid)
		if oerr != nil {
			diags = append(diags, item.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, item.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.compute.image",
			Observations: obs,
		})
	}
	return out, diags, nil
}
