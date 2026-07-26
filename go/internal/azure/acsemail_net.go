// Azure Communication Services Email network shell (D76 fala 4): the ARM half of the
// Azure capability.email.sending composite. A create composes the emailService (the
// sending service, carrying the immutable dataLocation residency) and — iff DKIM is
// asked — an emailServices/{name}/domains/{domain} sub-resource, in dependency order.
// Both PUTs are async (LRO), polled to properties.provisioningState == Succeeded.
// Four-valued throughout (D29/D87): once the emailService lands, ANY later ambiguity
// (the domain, its provisioning) is unknown WITH the providerId — never a silent
// half-provision, never a bare "failed" that hides a standing service. Delete tears
// the composite down in REVERSE order (domains -> emailService), ownership-guarded by
// the emailService's ARM tags. DKIM verification is ASYNC (the operator publishes the
// DNS records) — the create does NOT block on it; observe reports it honestly.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func acsEmailProviderID(sub, rg, name string) string {
	return "acsemail:" + sub + ":" + rg + ":" + name
}

func splitACSEmailProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "acsemail" {
		return "", "", "", fmt.Errorf("providerId %q is not acsemail:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || !acsEmailNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) acsEmailPath(name string) string {
	return "Microsoft.Communication/emailServices/" + name
}

func (d *Driver) acsDomainPath(service, domain string) string {
	return "Microsoft.Communication/emailServices/" + service + "/domains/" + domain
}

// --- projections ---------------------------------------------------------------

type acsEmailDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
		DataLocation      string `json:"dataLocation"`
	} `json:"properties"`
}

type acsDomainDoc struct {
	Name       string `json:"name"`
	Properties struct {
		ProvisioningState  string `json:"provisioningState"`
		DomainManagement   string `json:"domainManagement"`
		VerificationStates struct {
			DKIM struct {
				Status string `json:"status"`
			} `json:"DKIM"`
		} `json:"verificationStates"`
	} `json:"properties"`
}

// getEmailService resolves the emailService. (doc, found, err): a 404 is
// found=false with a nil error (absent, not a failure); a transport error, any
// other non-200, or an unparseable body names why the read gave no answer —
// never a fabricated absence.
func (d *Driver) getEmailService(rg, name string) (acsEmailDoc, bool, error) {
	var doc acsEmailDoc
	found, err := d.armGetInto("emailServices.get", rg, d.acsEmailPath(name),
		acsEmailAPIVersion, &doc)
	if err != nil || !found {
		return acsEmailDoc{}, false, err
	}
	return doc, true, nil
}

func (d *Driver) acsEmailState(rg, name string) (string, bool) {
	doc, found, rerr := d.getEmailService(rg, name)
	if rerr != nil || !found {
		return "", false
	}
	return doc.Properties.ProvisioningState, true
}

// listACSDomains enumerates the domains under an emailService. A non-nil error
// (transport, non-200 — a 404 included, since the parent may be gone — or an
// unparseable body) means the caller must OMIT the derived attribute rather
// than fabricate "no DKIM".
func (d *Driver) listACSDomains(rg, service string) ([]acsDomainDoc, error) {
	const op = "emailServices.domains.list"
	url, err := d.armURL(rg, d.acsEmailPath(service)+"/domains", acsEmailAPIVersion)
	if err != nil {
		return nil, &armReadError{Op: op, Cause: "scope", Detail: err.Error()}
	}
	st, resp, cerr := d.doARM("GET", url, nil)
	if cerr != nil {
		return nil, armTransport(op, cerr)
	}
	if st != http.StatusOK {
		return nil, armHTTP(op, st, resp)
	}
	var out struct {
		Value []acsDomainDoc `json:"value"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return nil, armBody(op, st)
	}
	return out.Value, nil
}

// getACSDomain reads one domain sub-resource. (doc, found, err) like getEmailService.
func (d *Driver) getACSDomain(rg, service, domain string) (acsDomainDoc, bool, error) {
	var doc acsDomainDoc
	found, err := d.armGetInto("emailServices.domains.get", rg,
		d.acsDomainPath(service, domain), acsEmailAPIVersion, &doc)
	if err != nil || !found {
		return acsDomainDoc{}, false, err
	}
	return doc, true, nil
}

// dkimVerified reports whether a domain's DKIM verification state is Verified — the
// precise authentication proof authentication.dkim governs (parity with SES's
// SigningEnabled && Status==SUCCESS).
func dkimVerified(dom acsDomainDoc) bool {
	return dom.Properties.VerificationStates.DKIM.Status == "Verified"
}

// --- create ---------------------------------------------------------------------

// createACSEmail provisions the composite (D26): the emailService and — iff DKIM is
// asked — a domain sub-resource. Four-valued: once the emailService lands, ANY later
// ambiguity is unknown WITH the providerId (a partial composite to reconcile).
func (d *Driver) createACSEmail(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildACSEmail(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := acsEmailProviderID(d.Subscription, plan.ResourceGroup, plan.Name)

	// ownership pre-read: refuse to touch a foreign emailService already at our name.
	doc, found, rerr := d.getEmailService(plan.ResourceGroup, plan.Name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "pre-create ownership read gave no answer — reconcile before provisioning: " + rerr.Error()}
	}
	if found {
		if !d.acsOwned(doc.Tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "an emailService with this name exists and is not ours (tags do not match) — refusing to adopt it"}
		}
		return d.ensureACSComposite(pid, capability, environment, plan) // ours already — repair a partial
	}

	url, _ := d.armURL(plan.ResourceGroup, d.acsEmailPath(plan.Name), acsEmailAPIVersion)
	body, _ := json.Marshal(map[string]any{
		"location":   "global", // the emailService resource is always global; residency is dataLocation
		"tags":       d.tags(capability, environment),
		"properties": map[string]any{"dataLocation": plan.DataLocation},
	})
	st, resp, err := d.doARM("PUT", url, body)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("emailService create outcome unknown (may have landed): %v", err)}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("emailService create HTTP %d (server error — may have landed) — reconcile", st)}
	case st < 200 || st >= 300:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("emailService create HTTP %d: %s", st, mutDetailAz(resp))}
	}
	// poll the emailService to Succeeded before attaching the domain.
	if r := d.pollACSState(pid, "emailService", func() (string, bool) {
		return d.acsEmailState(plan.ResourceGroup, plan.Name)
	}); r != nil {
		return *r
	}
	return d.ensureACSComposite(pid, capability, environment, plan)
}

// ensureACSComposite completes an existing emailService: iff DKIM is asked, ensure the
// domain sub-resource exists (idempotent for the ours-already repair path). The
// emailService ALREADY exists, so EVERY failure here is unknown WITH the pid (a partial
// composite), NEVER a bare "failed" that hides the standing service. DKIM VERIFICATION
// is async (the operator publishes DNS) — this does NOT block on it.
func (d *Driver) ensureACSComposite(pid, capability, environment string, plan ACSEmailPlan) provider.CreateResult {
	if !plan.DKIM {
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	}
	// idempotent: skip the PUT if the domain sub-resource is already present.
	if _, dfound, derr := d.getACSDomain(plan.ResourceGroup, plan.Name, plan.DomainName); derr == nil && dfound {
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	}
	url, _ := d.armURL(plan.ResourceGroup, d.acsDomainPath(plan.Name, plan.DomainName), acsEmailAPIVersion)
	body, _ := json.Marshal(map[string]any{
		"location":   "global",
		"properties": map[string]any{"domainManagement": plan.DomainManagement},
	})
	st, resp, err := d.doARM("PUT", url, body)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("emailService exists but the DKIM domain outcome is unknown — reconcile: %v", err)}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("emailService exists but the DKIM domain PUT HTTP %d (server error — may have landed) — reconcile", st)}
	case st < 200 || st >= 300:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("emailService exists but the DKIM domain could not be created (HTTP %d: %s) — "+
				"the sender claims DKIM with no domain; reconcile the half-provisioned sender", st, mutDetailAz(resp))}
	}
	if r := d.pollACSState(pid, "domain", func() (string, bool) {
		dom, found, rerr := d.getACSDomain(plan.ResourceGroup, plan.Name, plan.DomainName)
		if rerr != nil || !found {
			return "", false
		}
		return dom.Properties.ProvisioningState, true
	}); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// pollACSState polls an LRO provisioningState to a terminal outcome. Returns nil on
// Succeeded, or a non-nil four-valued result (unknown-with-pid on timeout, failed on a
// terminal Failed/Canceled). what names the resource in the diagnostic.
func (d *Driver) pollACSState(pid, what string, state func() (string, bool)) *provider.CreateResult {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		s, readable := state()
		if readable {
			switch s {
			case "Succeeded":
				return nil
			case "Failed", "Canceled":
				return &provider.CreateResult{ProviderID: pid, Status: "failed", Reason: what + " entered state " + s}
			}
		}
		if d.Now().After(deadline) {
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: what + " still provisioning at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

// --- observe --------------------------------------------------------------------

// observeACSEmail reverse-maps a live sending service to capability.email.sending:
// location.region is the measured dataLocation (residency, lowercased for comparison);
// authentication.dkim is TRUE iff a domain sub-resource has DKIM verificationState
// Verified; bounce.tracked is OMITTED with a diagnostic (no per-emailService mapping —
// it is Event Grid on the linked comm-services resource; never fabricated). An
// unreadable emailService is unknown (an error); an unreadable domain list omits DKIM
// with a diagnostic.
func (d *Driver) observeACSEmail(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitACSEmailProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	doc, found, rerr := d.getEmailService(rg, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"emailService not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if doc.Properties.DataLocation != "" {
		obs = append(obs, provider.Observation{Path: "location.region",
			Value: strings.ToLower(doc.Properties.DataLocation), Derivation: "measured"})
	}
	var diags []string
	// authentication.dkim lives on the domain sub-resources. An unreadable domain list
	// is UNKNOWN: omit the attribute with a diagnostic rather than fabricate "no DKIM".
	if domains, derr := d.listACSDomains(rg, name); derr != nil {
		diags = append(diags, "authentication.dkim not derivable ("+derr.Error()+") — omitted rather than fabricated")
	} else {
		dkim := false
		for _, dom := range domains {
			if dkimVerified(dom) {
				dkim = true
				break
			}
		}
		obs = append(obs, provider.Observation{Path: "authentication.dkim", Value: dkim, Derivation: "measured"})
	}
	// bounce.tracked has NO per-emailService mapping — never fabricated. Name what was
	// NOT observed and why (D44), directing the reader to the Event Grid path.
	diags = append(diags,
		"bounce.tracked not observed on ACS Email — delivery/bounce reports are Event Grid events "+
			"(EmailDeliveryReportReceived) on the linked Microsoft.Communication/communicationServices resource, "+
			"not a property of the emailService+domains composite; groundhold does not fabricate it")
	return obs, diags, nil
}

// --- delete ---------------------------------------------------------------------

// deleteACSEmail tears the composite down in REVERSE order, ownership-guarded: pre-read
// the emailService's tags (refuse a foreign service), delete every domain sub-resource,
// then the emailService. Idempotent on already-gone (404); a transport/5xx is unknown
// WITH the pid (reconcile), never a claimed success.
func (d *Driver) deleteACSEmail(capability, environment, providerID string) provider.CreateResult {
	sub, rg, name, err := splitACSEmailProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: "providerId subscription is not the driver's — refusing to delete across subscriptions"}
	}
	doc, found, rerr := d.getEmailService(rg, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	if !d.acsOwned(doc.Tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "emailService tags do not match — refusing to delete a resource that is not ours"}
	}
	// (1) delete every domain sub-resource (an unreadable list is unknown — reconcile).
	domains, derr := d.listACSDomains(rg, name)
	if derr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "domains gave no answer before delete — reconcile rather than delete the service with domains behind it: " + derr.Error()}
	}
	for _, dom := range domains {
		url, _ := d.armURL(rg, d.acsDomainPath(name, dom.Name), acsEmailAPIVersion)
		if r := d.deleteAndConfirm(url, providerID, "email domain"); r != nil && r.Status != "succeeded" {
			return *r
		}
	}
	// (2) delete the emailService.
	url, _ := d.armURL(rg, d.acsEmailPath(name), acsEmailAPIVersion)
	if r := d.deleteAndConfirm(url, providerID, "emailService"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// --- update ---------------------------------------------------------------------

// updateACSEmail patches a bound sender in place (D46): authentication.dkim by adding
// (a domain sub-resource) or removing (every domain) the DKIM sending domain. Ownership
// tags gate the patch; the desired shape is re-derived (refuse-before-mutate) from the
// hash-pinned candidate attrs+impl; four-valued throughout.
func (d *Driver) updateACSEmail(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	sub, rg, name, err := splitACSEmailProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed", Reason: "providerId subscription is not the driver's — refusing"}
	}
	// refuse-before-mutate: re-derive + validate the full desired shape.
	plan, err := BuildACSEmail(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if plan.Name != name {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("candidate emailService name %q does not match the bound service %q — refusing", plan.Name, name)}
	}
	doc, found, rerr := d.getEmailService(rg, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-update ownership read gave no answer — reconcile before patching: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "emailService no longer exists — cannot update"}
	}
	if !d.acsOwned(doc.Tags, capability, environment) {
		return provider.CreateResult{Status: "failed", Reason: "emailService tags do not match — refusing to patch a resource that is not ours"}
	}

	for _, path := range changes {
		switch path {
		case "authentication.dkim":
			if plan.DKIM {
				if r := d.ensureACSComposite(providerID, capability, environment, plan); r.Status != "succeeded" {
					return r
				}
			} else {
				// remove: drop every domain sub-resource (disable DKIM sending).
				domains, derr := d.listACSDomains(rg, name)
				if derr != nil {
					return provider.CreateResult{ProviderID: providerID, Status: "unknown",
						Reason: "domains gave no answer — cannot disable DKIM in place; reconcile: " + derr.Error()}
				}
				for _, dom := range domains {
					url, _ := d.armURL(rg, d.acsDomainPath(name, dom.Name), acsEmailAPIVersion)
					if r := d.deleteAndConfirm(url, providerID, "email domain"); r != nil && r.Status != "succeeded" {
						return *r
					}
				}
			}
		default:
			// ClassifyChange gates this (unsupported/immutable); refuse honestly rather than no-op.
			return provider.CreateResult{Status: "failed", Reason: "no in-place ACS Email mapping for " + path}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// acsOwned reports whether the ARM tags carry groundhold's ownership markers for this
// capability+environment (the same discipline as flexserver's tag guard).
func (d *Driver) acsOwned(tags map[string]string, capability, environment string) bool {
	return tags["groundhold-capability"] == sanitizeAzTag(capability) &&
		tags["groundhold-environment"] == sanitizeAzTag(environment)
}

// --- discover -------------------------------------------------------------------

// discoverACSEmail enumerates the subscription's ACS emailServices as
// capability.email.sending — so `discover --provider azure` surfaces a sending service
// for adoption. The emailService resource is always global (no per-region filter);
// reuses observeACSEmail (list -> reverse map).
func (d *Driver) discoverACSEmail(region string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Communication/emailServices?api-version=%s",
		d.BaseURL, d.Subscription, acsEmailAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("emailServices.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("emailServices.list: HTTP %d", st)
	}
	var out struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return nil, nil, &armReadError{Op: "emailServices.list", Cause: "body", Status: st}
	}
	var found []provider.Discovered
	var diags []string
	for _, s := range out.Value {
		rg := resourceGroupOf(s.ID)
		if rg == "" {
			diags = append(diags, s.Name+": resource group unparseable from id")
			continue
		}
		pid := acsEmailProviderID(d.Subscription, rg, s.Name)
		obs, od, oerr := d.observeACSEmail("", pid)
		if oerr != nil {
			diags = append(diags, s.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range od {
			diags = append(diags, s.Name+": "+dg)
		}
		found = append(found, provider.Discovered{
			ProviderID: pid, ResourceType: "capability.email.sending", Observations: obs})
	}
	return found, diags, nil
}
