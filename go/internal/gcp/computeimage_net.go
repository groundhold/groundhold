// Compute Engine image network shell (D370): auth, HTTP and the reverse mapping.
// No semantics here — those are in computeimage.go.
//
// There is no mutation shell, because there is nothing to mutate: this is a
// witness driver (D177). The D29 create/delete honesty rules have nothing to
// apply to, and the adversarial mutation harness has no operations to
// fault-inject. What replaces them is the read discipline, which is the only
// discipline a witness has: every fact is either MEASURED from the API or
// reported UNREAD, and nothing in between.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// gcpImageProviderID carries no region: a Compute Engine image is a GLOBAL
// resource, and inventing a region for it would make two names for one image.
func gcpImageProviderID(project, name string) string {
	return "gcpimage:" + project + ":" + name
}

func splitGCPImageProviderID(providerID string) (project, name string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "gcpimage" {
		return "", "", fmt.Errorf("providerId %q is not gcpimage:project:name", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !gcpName.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId image name %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

// gcpImageDoc is the slice of images.get this driver reads.
type gcpImageDoc struct {
	Name               string   `json:"name"`
	Status             string   `json:"status"`
	StorageLocations   []string `json:"storageLocations"`
	ImageEncryptionKey *struct {
		KmsKeyName string `json:"kmsKeyName"`
	} `json:"imageEncryptionKey"`
}

func (d *Driver) gcpImageURL(project, name string) string {
	return fmt.Sprintf("%s/projects/%s/global/images/%s", d.computeBase(), project, name)
}

// getGCPImage reads one image. `found=false` with no error means the API answered
// and the image is not there — different from "the read failed".
func (d *Driver) getGCPImage(project, name string) (gcpImageDoc, bool, error) {
	st, body, err := d.call("GET", d.gcpImageURL(project, name), nil)
	if err != nil {
		return gcpImageDoc{}, false, readTransport("images.get", err)
	}
	if st == http.StatusNotFound {
		return gcpImageDoc{}, false, nil
	}
	if st != http.StatusOK {
		return gcpImageDoc{}, false, readHTTP("images.get", st, gcpErrCode(body))
	}
	var doc gcpImageDoc
	if json.Unmarshal(body, &doc) != nil {
		return gcpImageDoc{}, false, readBody("images.get", st)
	}
	return doc, true, nil
}

// readImagePolicy reads whether the image is shared beyond this project. A
// binding naming allUsers or allAuthenticatedUsers is the whole of it: either one
// means a stranger can boot from the image, and anything baked into it is
// readable with it.
func (d *Driver) readImagePolicy(project, name string) (public bool, err error) {
	const op = "images.getIamPolicy"
	st, body, cerr := d.call("GET", fmt.Sprintf("%s/getIamPolicy?optionsRequestedPolicyVersion=%d",
		d.gcpImageURL(project, name), iamPolicyVersion), nil)
	if cerr != nil {
		return false, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return false, readHTTP(op, st, gcpErrCode(body))
	}
	var policy struct {
		Bindings []map[string]any `json:"bindings"`
	}
	if json.Unmarshal(body, &policy) != nil {
		return false, readBody(op, st)
	}
	for _, b := range policy.Bindings {
		if hasMember(b, "allUsers") || hasMember(b, "allAuthenticatedUsers") {
			return true, nil
		}
	}
	return false, nil
}

// observeGCPImage is the whole driver. Every fact is measured or unread.
func (d *Driver) observeGCPImage(capability, providerID string) ([]provider.Observation, []string, error) {
	project, name, err := splitGCPImageProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	// D466 — the project boundary. 39 of 44 GCP deletes already guard it; these
	// families did not, and the label check is not a substitute: our capability +
	// environment labels are IDENTICAL in every project we manage, so a providerId
	// naming another project passes it. sameProject is a no-op when nothing is
	// pinned (observe/discover), a refusal when apply/converge pinned one.
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getGCPImage(project, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"image not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// Compute Engine encrypts every image; a fact about the platform rather than
		// a reading of this resource, so config-intent rather than measured.
		{Path: "encryption.atRest", Value: true, Derivation: "platform-invariant"},
		{Path: "encryption.customerManagedKeys",
			Value:      doc.ImageEncryptionKey != nil && doc.ImageEncryptionKey.KmsKeyName != "",
			Derivation: "measured"},
	}
	// sourceProvenance has no readable field on a Compute image (see the package
	// comment). Left unobserved so a hard constraint on it stays `unknown` and
	// blocks, rather than being answered with an invented `false`.
	unread := []string{
		"sourceProvenance unread — a Compute Engine image carries no readable build " +
			"attestation; a constraint on it cannot be proven from here",
	}
	// An image is global, but the BYTES sit somewhere, and that somewhere is the
	// residency question the attribute asks. An image with no reported storage
	// location has no answer — not a guessed one.
	if len(doc.StorageLocations) > 0 {
		obs = append(obs, provider.Observation{
			Path: "location.region", Value: doc.StorageLocations[0], Derivation: "measured"})
	} else {
		unread = append(unread, "image reported no storageLocations — location.region unread")
	}
	public, perr := d.readImagePolicy(project, name)
	if perr != nil {
		// A silent false here passes an "is our base image private?" constraint on an
		// image the whole internet can launch.
		unread = append(unread, "image sharing unread: "+perr.Error())
	} else {
		obs = append(obs, provider.Observation{
			Path: "network.publicExposure", Value: public, Derivation: "measured"})
	}
	return obs, unread, nil
}

// discoverGCPImages enumerates the images this PROJECT owns. The list endpoint is
// already project-scoped, which is why there is no equivalent of the AWS
// Owner=self filter — but the consequence is the same and worth stating: public
// images from other projects are not ours and are not enumerated.
func (d *Driver) discoverGCPImages(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.call("GET", fmt.Sprintf("%s/projects/%s/global/images",
		d.computeBase(), d.Project), nil)
	if err != nil {
		return nil, nil, readTransport("images.list", err)
	}
	if st != http.StatusOK {
		return nil, nil, readHTTP("images.list", st, gcpErrCode(body))
	}
	var page struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &page) != nil {
		return nil, nil, readBody("images.list", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, item := range page.Items {
		if item.Name == "" {
			continue
		}
		pid := gcpImageProviderID(d.Project, item.Name)
		obs, odiags, oerr := d.observeGCPImage("", pid)
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
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}
