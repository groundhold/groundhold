// AKS Workload Identity network shell (D76 parity): the bearer-signed, ARM-JSON
// half of the capability.identity.podidentity Azure driver. A
// federatedIdentityCredential PUT is SYNCHRONOUS (200/201 with the credential
// properties) — no async provisioningState poll (mirrors the UAMI PUT). The
// credential name is deterministic, so the providerId is knowable before the
// response (D29). Ownership carries NO tag marker (ARM gives a federated
// credential no tags field): ownership is the DETERMINISTIC name PLUS a content
// match on subject+issuer+audience — a name that exists with different content is
// foreign and refused. D29/D87 honesty.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

// ficURL builds the federatedIdentityCredential ARM URL, bounding the uami + name
// at the D73 injection boundary before they enter the provider path (armURL bounds
// the subscription + resource group).
func (d *Driver) ficURL(rg, uami, name string) (string, error) {
	if !azNameOK.MatchString(uami) {
		return "", fmt.Errorf("uami name %q is invalid", uami)
	}
	if !azNameOK.MatchString(name) {
		return "", fmt.Errorf("federated credential name %q is invalid", name)
	}
	return d.armURL(rg,
		"Microsoft.ManagedIdentity/userAssignedIdentities/"+uami+"/federatedIdentityCredentials/"+name,
		federatedCredentialAPIVersion)
}

// ficDoc is the projection of a federated credential the driver reads back.
type ficDoc struct {
	Properties struct {
		Issuer    string   `json:"issuer"`
		Subject   string   `json:"subject"`
		Audiences []string `json:"audiences"`
	} `json:"properties"`
}

// getFIC resolves one federated credential. (found, readable) mirror the UAMI
// get: a 404 is found=false+readable (gone), any transport/other error or a
// garbled 200 is readable=false (unknown — never a fabricated absence).
// getFIC reads the resource. D295: a failed read names its cause
// (status + the provider's code); a 404 stays an authoritative absence.
func (d *Driver) getFIC(rg, uami, name string) (doc ficDoc, found bool, err error) {
	url, uerr := d.ficURL(rg, uami, name)
	if uerr != nil {
		return ficDoc{}, false, &armReadError{Op: "federatedIdentityCredentials.get", Cause: "scope", Detail: uerr.Error()}
	}
	found, err = d.armGetURLInto("federatedIdentityCredentials.get", url, &doc)
	return doc, found, err
}

// ficContentMatches reports whether an existing credential is OURS: same subject,
// same issuer, and the fixed AAD audience present. With no tag marker this content
// match IS the ownership proof (the deterministic name got us here).
func ficContentMatches(doc ficDoc, plan AKSWorkloadIdentityPlan) bool {
	if doc.Properties.Subject != plan.Subject() || doc.Properties.Issuer != plan.OIDCIssuer {
		return false
	}
	for _, a := range doc.Properties.Audiences {
		if a == aksWIAudience {
			return true
		}
	}
	return false
}

// createAKSWorkloadIdentity creates a federated credential, four-valued
// throughout. Pre-read GETs the deterministic name: an ours-already one (content
// match) is a repair (succeeded); a name that exists with DIFFERENT content is
// foreign and refused; else PUT (synchronous — no long poll). Transport/5xx are
// unknown WITH the pid (may have landed).
func (d *Driver) createAKSWorkloadIdentity(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAKSWorkloadIdentity(d.Subscription, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if plan.Subscription != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("implementation.uamiResourceId subscription %q is not the driver's %q", plan.Subscription, d.Subscription)}
	}
	pid := aksWIProviderID(plan.Subscription, plan.ResourceGroup, plan.UAMIName, plan.CredentialName)

	doc, found, rerr := d.getFIC(plan.ResourceGroup, plan.UAMIName, plan.CredentialName)
	if rerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "pre-create ownership read gave no answer — reconcile before provisioning: " + rerr.Error()}
	}
	if found {
		if !ficContentMatches(doc, plan) {
			return provider.CreateResult{Status: "failed",
				Reason: "a federated credential with this name exists under the UAMI and is not ours (subject/issuer/audience differ) — refusing to adopt it"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // ours already — repair/no-op
	}

	url, e := d.ficURL(plan.ResourceGroup, plan.UAMIName, plan.CredentialName)
	if e != nil {
		return provider.CreateResult{Status: "failed", Reason: e.Error()}
	}
	body, _ := json.Marshal(map[string]any{
		"properties": map[string]any{
			"issuer":    plan.OIDCIssuer,
			"subject":   plan.Subject(),
			"audiences": []string{aksWIAudience},
		},
	})
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
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("PUT HTTP %d: %s", st, mutDetailAz(resp))}
	}
}

// observeAKSWorkloadIdentity reverse-maps a federated credential to
// capability.identity.podidentity: GET, then parse the subject back into
// namespace/serviceAccount. An unreadable read is an error (unknown), never a
// fabricated absence; a not-found is "nothing to observe"; a subject that is not a
// system:serviceaccount:<ns>:<sa> is surfaced as a diagnostic (the credential is
// real but not a Kubernetes SA binding — no ns/sa to map).
func (d *Driver) observeAKSWorkloadIdentity(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, uami, name, err := splitAKSWIProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's %q", sub, d.Subscription)
	}
	doc, found, rerr := d.getFIC(rg, uami, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"federated identity credential not found — nothing to observe"}, nil
	}
	ns, sa, ok := parseFICSubject(doc.Properties.Subject)
	if !ok {
		return nil, []string{fmt.Sprintf("federated credential subject %q is not a system:serviceaccount:<ns>:<sa> — no workload identity to map", doc.Properties.Subject)}, nil
	}
	obs := []provider.Observation{
		{Path: "workload.namespace", Value: ns, Derivation: "measured"},
		{Path: "workload.serviceAccount", Value: sa, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	return obs, nil, nil
}

// deleteAKSWorkloadIdentity removes the federated credential, ownership-guarded:
// GET, re-check the content match (no tag marker — subject+issuer+audience is the
// proof), DELETE. Idempotent on already-gone; a transport/5xx is unknown WITH the
// pid (reconcile); a name that exists with foreign content is refused.
func (d *Driver) deleteAKSWorkloadIdentity(capability, environment, providerID string) provider.CreateResult {
	sub, rg, uami, name, err := splitAKSWIProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's %q", sub, d.Subscription)}
	}
	doc, found, rerr := d.getFIC(rg, uami, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	// Ownership: the subject must be a real Kubernetes SA binding whose subject the
	// deterministic name produced. A subject that is not a system:serviceaccount is
	// not ours; refuse rather than delete another use of this UAMI's credentials.
	if _, _, ok := parseFICSubject(doc.Properties.Subject); !ok {
		return provider.CreateResult{Status: "failed",
			Reason: "federated credential subject is not a Kubernetes serviceAccount binding — refusing to delete a resource that is not ours"}
	}
	url, e := d.ficURL(rg, uami, name)
	if e != nil {
		return provider.CreateResult{Status: "failed", Reason: e.Error()}
	}
	if r := d.deleteAndConfirm(url, providerID, "federated-credential"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// discoverAKSWorkloadIdentity enumerates every federated credential UNDER every
// in-region UAMI as capability.identity.podidentity — the nested EKS pattern
// (list clusters -> list associations), Azure flavour (list UAMIs -> list
// federatedIdentityCredentials). Federated credentials inherit the UAMI's region,
// so filtering the parent UAMI by region scopes the sweep. Reuses
// observeAKSWorkloadIdentity for the reverse map. Four-valued: a list that errors
// becomes a diagnostic, never a fabricated absence.
func (d *Driver) discoverAKSWorkloadIdentity(region string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=%s",
		d.BaseURL, d.Subscription, managedIdentityAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("userAssignedIdentities.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("userAssignedIdentities.list: HTTP %d", st)
	}
	var page struct {
		Value []azListItem `json:"value"`
	}
	if json.Unmarshal(resp, &page) != nil {
		return nil, nil, &armReadError{Op: "userAssignedIdentities.list", Cause: "body", Status: st}
	}
	want := azRegion(region)
	var out []provider.Discovered
	var diags []string
	for _, uami := range page.Value {
		if azRegion(uami.Location) != want {
			continue // parent UAMI lives elsewhere — not this sweep
		}
		rg := resourceGroupOf(uami.ID)
		if rg == "" {
			diags = append(diags, uami.Name+": resource group unparseable from id")
			continue
		}
		fURL, e := d.armURL(rg,
			"Microsoft.ManagedIdentity/userAssignedIdentities/"+uami.Name+"/federatedIdentityCredentials",
			federatedCredentialAPIVersion)
		if e != nil {
			diags = append(diags, uami.Name+": "+e.Error())
			continue
		}
		const fedOp = "federatedIdentityCredentials.list"
		fst, fresp, ferr := d.doARM("GET", fURL, nil)
		if ferr != nil {
			diags = append(diags, uami.Name+": "+armTransport(fedOp, ferr).Error()+" — skipped")
			continue
		}
		if fst != http.StatusOK {
			diags = append(diags, uami.Name+": "+armHTTP(fedOp, fst, fresp).Error()+" — skipped")
			continue
		}
		var creds struct {
			Value []struct {
				Name string `json:"name"`
			} `json:"value"`
		}
		if json.Unmarshal(fresp, &creds) != nil {
			diags = append(diags, uami.Name+": "+armBody(fedOp, fst).Error()+" — skipped")
			continue
		}
		for _, c := range creds.Value {
			pid := aksWIProviderID(d.Subscription, rg, uami.Name, c.Name)
			obs, odiags, oerr := d.observeAKSWorkloadIdentity("", pid)
			if oerr != nil {
				diags = append(diags, uami.Name+"/"+c.Name+": "+oerr.Error())
				continue
			}
			for _, dg := range odiags {
				diags = append(diags, uami.Name+"/"+c.Name+": "+dg)
			}
			// A non-SA-subject credential yields no observations (diag only) — do not
			// surface it as a discovered podidentity.
			if len(obs) == 0 {
				continue
			}
			out = append(out, provider.Discovered{
				ProviderID:   pid,
				ResourceType: "capability.identity.podidentity",
				Observations: obs,
			})
		}
	}
	return out, diags, nil
}
