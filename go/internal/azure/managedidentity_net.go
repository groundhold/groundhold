// Azure managed identity network shell (D121): the bearer-signed, ARM-JSON half of
// the capability.identity.serviceaccount driver. A user-assigned managed identity
// PUT is SYNCHRONOUS (200/201 with the identity's clientId/principalId) — no async
// provisioningState poll. The resource name is deterministic, so the providerId is
// knowable before the response (D29). Ownership is ARM tags. The raw display name
// rides in a dedicated tag (ARM UAMI has no display field) so it round-trips
// unmangled. D29/D87 honesty.
package azure

import (
	"encoding/json"
	"fmt"
	"strings"

	"groundhold/internal/provider"
)

func uamiProviderID(sub, rg, name string) string {
	return "uami:" + sub + ":" + rg + ":" + name
}

func splitUAMIProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "uami" {
		return "", "", "", fmt.Errorf("providerId %q is not uami:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId subscription %q is invalid", parts[1])
	}
	if !rgOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId resource group %q is invalid", parts[2])
	}
	if !azNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId name %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) uamiURL(rg, name string) (string, error) {
	return d.armURL(rg, "Microsoft.ManagedIdentity/userAssignedIdentities/"+name, managedIdentityAPIVersion)
}

type uamiDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ClientID    string `json:"clientId"`
		PrincipalID string `json:"principalId"`
	} `json:"properties"`
}

// getUAMI reads the resource. D295: a read that yielded nothing returns an
// error NAMING the cause (status + the provider's own code); a 404 stays an
// authoritative absence (found=false, no error), so the four-valued
// semantics are unchanged — only the diagnosis is new.
func (d *Driver) getUAMI(rg, name string) (doc uamiDoc, found bool, err error) {
	url, uerr := d.uamiURL(rg, name)
	if uerr != nil {
		return uamiDoc{}, false, &armReadError{Op: "userAssignedIdentities.get", Cause: "scope", Detail: uerr.Error()}
	}
	found, err = d.armGetURLInto("userAssignedIdentities.get", url, &doc)
	return doc, found, err
}

func (d *Driver) createManagedIdentity(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildManagedIdentity(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure managed identity requires implementation.resource_group (a valid Azure resource group)"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := uamiProviderID(d.Subscription, rg, plan.Name)
	url, e := d.uamiURL(rg, plan.Name)
	if e != nil {
		return provider.CreateResult{Status: "failed", Reason: e.Error()}
	}
	tags := d.tags(capability, environment)
	if plan.DisplayName != "" {
		tags["groundhold-display"] = plan.DisplayName // raw, unmangled — round-trips
	}
	body, _ := json.Marshal(map[string]any{"location": plan.Location, "tags": tags})

	if r := d.refuseForeignUpsert(url, body); r != nil { // D254
		return *r
	}
	st, resp, err := d.doARM("PUT", url, body)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("PUT outcome unknown (may have landed): %v", err)}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("PUT HTTP %d (server error — may have landed) — reconcile", st)}
	case st >= 200 && st < 300:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // synchronous
	default:
		if r := provider.MutationResult(st, azErrCode(resp), nil, pid, "PUT"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("PUT HTTP %d: %s", st, mutDetailAz(resp))}
	}
}

func (d *Driver) observeManagedIdentity(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitUAMIProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's %q", sub, d.Subscription)
	}
	doc, found, rerr := d.getUAMI(rg, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"managed identity not found — bound resource is gone (will re-create)"}, nil
	}
	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// a managed identity is keyless — Azure holds the credential.
		{Path: "key.exportable", Value: false, Derivation: "platform-invariant"},
	}
	if dn := doc.Tags["groundhold-display"]; dn != "" {
		obs = append(obs, provider.Observation{Path: "display.name", Value: dn, Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteManagedIdentity(capability, environment, providerID string) provider.CreateResult {
	_, rg, name, err := splitUAMIProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getUAMI(rg, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile" + ": " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "managed identity tags do not match — refusing to delete a resource that is not ours"}
	}
	url, _ := d.uamiURL(rg, name)
	if r := d.deleteAndConfirm(url, providerID, "managed-identity"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
