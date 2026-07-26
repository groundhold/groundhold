// AWS SES sending network shell (D148): the SigV4-signed, REST-JSON half of the AWS
// capability.email.sending composite. A create composes the sending DOMAIN identity
// (Easy DKIM) and — iff bounces are tracked — a configuration set with a
// BOUNCE+COMPLAINT SNS event destination, in dependency order. Four-valued
// throughout (D29/D87): once the identity lands, ANY later ambiguity (DKIM,
// configuration set, event destination) is unknown WITH the providerId — never a
// silent half-provision that claims bounce tracking with no sink, and never a bare
// "failed" that hides a standing identity. Delete tears the composite down in
// REVERSE order (configuration set -> identity), ownership-guarded by the identity's
// tags. SESv2 speaks REST-JSON at email.<region>.amazonaws.com; SigV4 service "ses".
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

const sesIdentitiesPath = "/v2/email/identities"
const sesConfigSetsPath = "/v2/email/configuration-sets"
const sesAccountPath = "/v2/email/account"

func (d *Driver) sesBase(region string) string {
	if d.SESBaseURL != "" {
		return d.SESBaseURL
	}
	return "https://email." + region + ".amazonaws.com"
}

func (d *Driver) sesDo(method, region, path string, body []byte) (int, []byte, error) {
	return d.doSigned(method, d.sesBase(region)+path, "ses", region,
		map[string]string{"Content-Type": "application/json"}, body)
}

// sesErr pulls a human string out of a SESv2 JSON error body (the message lives in
// "message"). Falls back to the raw body when it cannot be parsed.
func sesErr(body []byte) string {
	var e struct {
		Message string `json:"message"`
		Msg     string `json:"Message"`
	}
	_ = json.Unmarshal(body, &e)
	if e.Message != "" {
		return e.Message
	}
	if e.Msg != "" {
		return e.Msg
	}
	return mutDetail(body)
}

func sesIsNotFound(status int, body []byte) bool {
	return status == http.StatusNotFound || strings.Contains(sesErr(body), "NotFound")
}

func sesIsAlreadyExists(status int, body []byte) bool {
	return status == http.StatusConflict || strings.Contains(sesErr(body), "AlreadyExists")
}

// sesIdentity is the projection of GetEmailIdentity the driver reads. DkimAttributes
// drive authentication.dkim; Tags drive the ownership gate for every mutation.
type sesIdentity struct {
	DkimAttributes struct {
		SigningEnabled bool   `json:"SigningEnabled"`
		Status         string `json:"Status"`
	} `json:"DkimAttributes"`
	Tags []struct {
		Key   string `json:"Key"`
		Value string `json:"Value"`
	} `json:"Tags"`
}

func (id sesIdentity) tagMap() map[string]string {
	m := map[string]string{}
	for _, t := range id.Tags {
		m[t.Key] = t.Value
	}
	return m
}

// getEmailIdentity resolves the identity our domain names. (found, readable): a 404 /
// NotFound is found=false+readable (an absent identity, not an error); a transport
// error or any other non-200 is readable=false (unknown — never a fabricated absence).
func (d *Driver) getEmailIdentity(region, domain string) (sesIdentity, bool, error) {
	const op = "GetEmailIdentity"
	st, resp, err := d.sesDo("GET", region, sesIdentitiesPath+"/"+domain, nil)
	if err != nil {
		return sesIdentity{}, false, readTransport(op, err)
	}
	if sesIsNotFound(st, resp) {
		return sesIdentity{}, false, nil
	}
	if st != http.StatusOK {
		return sesIdentity{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var id sesIdentity
	if json.Unmarshal(resp, &id) != nil {
		return sesIdentity{}, false, readBody(op, st)
	}
	return id, true, nil
}

// sesEventDestination is the projection of one configuration-set event destination.
type sesEventDestination struct {
	MatchingEventTypes []string `json:"MatchingEventTypes"`
	SnsDestination     *struct {
		TopicArn string `json:"TopicArn"`
	} `json:"SnsDestination"`
}

// hasBounceComplaintSNS reports whether any destination captures BOTH BOUNCE and
// COMPLAINT to an SNS topic — the precise shape bounce.tracked governs.
func hasBounceComplaintSNS(dests []sesEventDestination) bool {
	for _, e := range dests {
		if e.SnsDestination == nil || e.SnsDestination.TopicArn == "" {
			continue
		}
		var bounce, complaint bool
		for _, t := range e.MatchingEventTypes {
			switch t {
			case "BOUNCE":
				bounce = true
			case "COMPLAINT":
				complaint = true
			}
		}
		if bounce && complaint {
			return true
		}
	}
	return false
}

// getEventDestinations reads a configuration set's event destinations. (found,
// readable): a 404 / NotFound is found=false+readable (the configuration set does not
// exist — authoritatively "no tracking"); a transport/other error is readable=false
// (unknown — never a fabricated "not tracked").
func (d *Driver) getEventDestinations(region, configSet string) ([]sesEventDestination, bool, error) {
	const op = "GetConfigurationSetEventDestinations"
	st, resp, cerr := d.sesDo("GET", region, sesConfigSetsPath+"/"+configSet+"/event-destinations", nil)
	if cerr != nil {
		return nil, false, readTransport(op, cerr)
	}
	if sesIsNotFound(st, resp) {
		return nil, false, nil
	}
	if st != http.StatusOK {
		return nil, false, readHTTP(op, st, awsErrCodeOf(resp))
	}
	var out struct {
		EventDestinations []sesEventDestination `json:"EventDestinations"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return nil, false, readBody(op, st)
	}
	return out.EventDestinations, true, nil
}

// sesAccount is the projection of SESv2 GetAccount the driver reads for the
// MANUAL-GATE. ProductionAccessEnabled is the authoritative sandbox-exit signal
// (false = sandboxed, may only send to verified addresses); EnforcementStatus is
// carried for diagnostics only.
type sesAccount struct {
	ProductionAccessEnabled bool   `json:"ProductionAccessEnabled"`
	EnforcementStatus       string `json:"EnforcementStatus"`
}

// getAccount reads the account-level SES posture (GetAccount) for the region. It is
// ACCOUNT-level, not per-identity — that is correct: sandbox/production access is a
// property of the account in the region, not of one sending domain. Returns
// (productionAccess, readable): readable=false on transport / non-200 / unparseable
// (unknown — never a fabricated "sandboxed"). groundhold NEVER writes this — there is no
// API to leave the sandbox; the grant is a manual console request.
func (d *Driver) getAccount(region string) (bool, error) {
	const op = "GetAccount"
	st, resp, cerr := d.sesDo("GET", region, sesAccountPath, nil)
	if cerr != nil {
		return false, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return false, readHTTP(op, st, awsErrCodeOf(resp))
	}
	var a sesAccount
	if json.Unmarshal(resp, &a) != nil {
		return false, readBody(op, st)
	}
	return a.ProductionAccessEnabled, nil
}

// createEmailIdentityBody is the CreateEmailIdentity request body: the domain and the
// ownership tags. Easy DKIM is enabled by default for a domain identity.
func (p SESSendingPlan) createEmailIdentityBody(capability, environment string) []byte {
	body := map[string]any{
		"EmailIdentity": p.Domain,
		"Tags": []any{
			map[string]any{"Key": "groundhold-capability", "Value": sanitizeTag(capability)},
			map[string]any{"Key": "groundhold-environment", "Value": sanitizeTag(environment)},
		},
	}
	return []byte(jsonBody(body))
}

// createSESSending provisions the composite (D26): the sending DOMAIN identity and —
// iff bounces are tracked — a configuration set with a BOUNCE+COMPLAINT SNS event
// destination. Four-valued: once the identity lands, ANY later ambiguity is unknown
// WITH the providerId (a partial composite to reconcile), never a silent success and
// never a bare "failed". DKIM verification is ASYNC (the operator publishes the DNS
// records) — the create does NOT block on Status==SUCCESS; observe reports the
// current DKIM status honestly.
func (d *Driver) createSESSending(region, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildSESSending(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := sesSendingProviderID(region, plan.Domain)

	// ownership pre-read: refuse to touch a foreign identity already at our domain.
	// Not-found continues to a fresh create; ours-already repairs a partial.
	id, found, rerr := d.getEmailIdentity(region, plan.Domain)
	if rerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "pre-create ownership read gave no answer — reconcile before provisioning: " + rerr.Error()}
	}
	if found {
		if !groundholdTagsMatch(id.tagMap(), capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "an email identity for this domain exists and is not ours (tags do not match) — refusing to adopt it"}
		}
		// ours already — ensure DKIM + the bounce composite exist (repair a partial).
		return d.ensureSESComposite(region, pid, plan)
	}

	// CreateEmailIdentity. The pid is knowable before the response (deterministic:
	// region+domain), so transport/5xx/AlreadyExists ambiguity carries it.
	st, body, err := d.sesDo("POST", region, sesIdentitiesPath, plan.createEmailIdentityBody(capability, environment))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateEmailIdentity outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK || st == http.StatusCreated:
		// created — fall through to the composite
	case sesIsAlreadyExists(st, body):
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "CreateEmailIdentity says the domain now exists — reconcile ownership"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateEmailIdentity HTTP %d (server error — may have landed): %s", st, sesErr(body))}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateEmailIdentity HTTP %d: %s", st, sesErr(body))}
	}
	return d.ensureSESComposite(region, pid, plan)
}

// ensureSESComposite completes an existing identity: set the DKIM posture, and — iff
// bounces are tracked — ensure the configuration set + its BOUNCE+COMPLAINT event
// destination exist (idempotent for the ours-already repair path). The identity
// ALREADY exists, so EVERY failure here is unknown WITH the pid (a partial composite
// to reconcile), NEVER a bare "failed" that hides the standing identity.
func (d *Driver) ensureSESComposite(region, pid string, plan SESSendingPlan) provider.CreateResult {
	// (1) DKIM signing posture (idempotent; Easy DKIM is default-on for a domain).
	dkimBody := []byte(jsonBody(map[string]any{"SigningEnabled": plan.DKIM}))
	st, body, err := d.sesDo("PUT", region, sesIdentitiesPath+"/"+plan.Domain+"/dkim", dkimBody)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("identity exists but PutEmailIdentityDkimAttributes outcome unknown — reconcile: %v", err)}
	case st == http.StatusOK:
		// ok
	default:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("identity exists but DKIM posture could not be set (HTTP %d: %s) — reconcile", st, sesErr(body))}
	}

	if !plan.BounceTracked {
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	}

	// (2) CreateConfigurationSet (idempotent: AlreadyExists is a prior partial).
	csBody := []byte(jsonBody(map[string]any{"ConfigurationSetName": plan.ConfigurationSetName}))
	st, body, err = d.sesDo("POST", region, sesConfigSetsPath, csBody)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("identity exists but CreateConfigurationSet outcome unknown — reconcile: %v", err)}
	case st == http.StatusOK || st == http.StatusCreated || sesIsAlreadyExists(st, body):
		// created or already there — fall through
	default:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("identity exists but CreateConfigurationSet failed (HTTP %d: %s) — reconcile the half-provisioned sender", st, sesErr(body))}
	}

	// (3) the BOUNCE+COMPLAINT event destination (idempotent: skip if already present).
	if dests, found, derr := d.getEventDestinations(region, plan.ConfigurationSetName); derr == nil && found && hasBounceComplaintSNS(dests) {
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	}
	edBody := []byte(jsonBody(map[string]any{
		"EventDestinationName": "bounces",
		"EventDestination": map[string]any{
			"Enabled":            true,
			"MatchingEventTypes": []any{"BOUNCE", "COMPLAINT"},
			"SnsDestination":     map[string]any{"TopicArn": plan.BounceTopicArn},
		},
	}))
	st, body, err = d.sesDo("POST", region, sesConfigSetsPath+"/"+plan.ConfigurationSetName+"/event-destinations", edBody)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("identity + configuration set exist but the bounce event destination outcome is unknown — reconcile: %v", err)}
	case st == http.StatusOK || st == http.StatusCreated || sesIsAlreadyExists(st, body):
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	default:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("identity + configuration set exist but the bounce event destination could not be attached "+
				"(HTTP %d: %s) — the sender claims tracking with no sink; reconcile the half-provisioned sender", st, sesErr(body))}
	}
}

// observeSESSending reverse-maps a live sending identity to capability.email.sending:
// authentication.dkim is TRUE only when signing is enabled AND verified
// (Status==SUCCESS); bounce.tracked is TRUE when the (deterministically-named)
// configuration set has a BOUNCE+COMPLAINT SNS event destination.
// sending.productionAccess is a MANUAL-GATE: OBSERVED from SESv2 GetAccount
// (ProductionAccessEnabled), never provisioned — a sandboxed account measures false.
// An unreadable identity is unknown (an error); an unreadable event-destination or
// account read OMITS its attribute with a diagnostic (never a fabricated "not
// tracked" / "sandboxed").
func (d *Driver) observeSESSending(capability, providerID string) ([]provider.Observation, []string, error) {
	region, domain, err := splitSESSendingProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	id, found, rerr := d.getEmailIdentity(region, domain)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"identity not found — nothing to observe"}, nil
	}
	dkim := id.DkimAttributes.SigningEnabled && id.DkimAttributes.Status == "SUCCESS"
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "authentication.dkim", Value: dkim, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	// bounce.tracked lives on the configuration set, keyed by a name recoverable from
	// the pid (capability + domain). An unreadable event-destination list is UNKNOWN:
	// omit the attribute with a diagnostic rather than fabricate "not tracked".
	configSet := sesConfigSetName(capability, domain)
	dests, csFound, csErr := d.getEventDestinations(region, configSet)
	if csErr != nil {
		diags = append(diags, "bounce.tracked not derivable ("+csErr.Error()+") — omitted rather than fabricated")
	} else {
		obs = append(obs, provider.Observation{
			Path: "bounce.tracked", Value: csFound && hasBounceComplaintSNS(dests), Derivation: "measured"})
	}
	// sending.productionAccess — a MANUAL-GATE. OBSERVED from SESv2 GetAccount
	// (ProductionAccessEnabled): true means the account is OUT of the sandbox. This is
	// account-level, not per-identity (sandbox/production access is a property of the
	// account in the region). groundhold NEVER sets it — the grant is a manual console
	// request. An unreadable account OMITS the attribute with a diagnostic rather than
	// fabricate "sandboxed".
	if prodAccess, aerr := d.getAccount(region); aerr != nil {
		diags = append(diags, "sending.productionAccess not derivable ("+aerr.Error()+") — omitted rather than fabricated")
	} else {
		obs = append(obs, provider.Observation{
			Path: "sending.productionAccess", Value: prodAccess, Derivation: "measured"})
		diags = append(diags,
			"sending.productionAccess is a manual-gate — leaving the SES sandbox is granted via a manual AWS console request, never an API create; "+
				"groundhold OBSERVES it (from SESv2 GetAccount ProductionAccessEnabled), it does NOT provision it")
	}
	return obs, diags, nil
}

// deleteSESSending tears the composite down in REVERSE order, ownership-guarded:
// pre-read the identity's tags (refuse a foreign identity), DeleteConfigurationSet
// (which drops its event destinations) then DeleteEmailIdentity. Idempotent on
// already-gone (404); a transport/5xx is unknown WITH the pid (reconcile), never a
// claimed success. The configuration-set name is the deterministic one recoverable
// from the pid (capability + domain).
func (d *Driver) deleteSESSending(region, capability, environment, providerID string) provider.CreateResult {
	rgn, domain, err := splitSESSendingProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if rgn != region && region != "" {
		// the pid carries the authoritative region; the driver's env region is advisory.
		region = rgn
	}
	if region == "" {
		region = rgn
	}
	id, found, rerr := d.getEmailIdentity(region, domain)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	// ownership guard: refuse a foreign identity at our domain.
	if !groundholdTagsMatch(id.tagMap(), capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "identity tags do not match — refusing to delete a resource that is not ours"}
	}
	// (1) DeleteConfigurationSet (removes its event destinations too). Idempotent on 404.
	if res := d.deleteSESConfigSet(region, providerID, sesConfigSetName(capability, domain)); res != nil {
		return *res
	}
	// (2) DeleteEmailIdentity.
	return d.deleteSESIdentity(region, providerID, domain)
}

// deleteSESConfigSet issues DeleteConfigurationSet and maps the outcome four-valued:
// nil on success or an idempotent already-gone (404 / NotFound); a non-nil unknown on
// transport/5xx (reconcile); a non-nil failed on a 4xx. Returning non-nil aborts the
// teardown before the identity delete.
func (d *Driver) deleteSESConfigSet(region, pid, configSet string) *provider.CreateResult {
	st, body, err := d.sesDo("DELETE", region, sesConfigSetsPath+"/"+configSet, nil)
	switch {
	case err != nil:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("DeleteConfigurationSet outcome unknown: %v", err)}
	case st == http.StatusOK || st == http.StatusNoContent || sesIsNotFound(st, body):
		return nil // deleted or idempotent already-gone
	case st >= 500:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("DeleteConfigurationSet HTTP %d (server error) — reconcile", st)}
	default:
		return &provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("DeleteConfigurationSet HTTP %d: %s", st, sesErr(body))}
	}
}

// deleteSESIdentity issues DeleteEmailIdentity, four-valued and idempotent on 404.
func (d *Driver) deleteSESIdentity(region, pid, domain string) provider.CreateResult {
	st, body, err := d.sesDo("DELETE", region, sesIdentitiesPath+"/"+domain, nil)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("DeleteEmailIdentity outcome unknown: %v", err)}
	case st == http.StatusOK || st == http.StatusNoContent || sesIsNotFound(st, body):
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("DeleteEmailIdentity HTTP %d (server error) — reconcile", st)}
	default:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("DeleteEmailIdentity HTTP %d: %s", st, sesErr(body))}
	}
}

// classifySESSendingChange (D46): PURE — can a capability.email.sending transition be
// honored in place? authentication.dkim and bounce.tracked are single-call mutable;
// location.region is unsupported (an SES identity is region-bound — a region change is
// a new identity, not a patch); service.managed / others are unsupported.
func classifySESSendingChange(path string) (string, string) {
	switch path {
	case "authentication.dkim":
		return "mutable", "in-place via PutEmailIdentityDkimAttributes (enable/disable Easy DKIM signing)"
	case "bounce.tracked":
		return "mutable", "in-place by adding/removing the configuration-set BOUNCE+COMPLAINT event destination"
	case "sending.productionAccess":
		return "unsupported", "manual-gate — leaving the SES sandbox is a manual request in the AWS console, not a patch API; groundhold observes production access, it does not provision it (and there is no updater — there cannot be one)"
	case "location.region":
		return "unsupported", "an SES email identity is region-bound — a region change is a new identity, not an in-place patch"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no SES sending in-place mapping for " + path
	}
}

// updateSESSending patches a bound sender in place (D46): authentication.dkim via
// PutEmailIdentityDkimAttributes, bounce.tracked by adding (configuration set + event
// destination) or removing (DeleteConfigurationSet) the bounce composite. Ownership
// tags gate the patch; the desired shape is re-derived (refuse-before-mutate) from
// the hash-pinned candidate attrs+impl; four-valued throughout (an ambiguous outcome
// is unknown WITH the providerId, never a silent success).
func (d *Driver) updateSESSending(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, domain, err := splitSESSendingProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// refuse-before-mutate: re-derive + validate the full desired shape (e.g.
	// bounce.tracked=true with no bounceTopicArn refuses here, before any patch).
	plan, err := BuildSESSending(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if plan.Domain != domain {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("candidate domain %q does not match the bound identity %q — refusing", plan.Domain, domain)}
	}
	// ownership re-check before mutating (refuse a foreign identity at our domain).
	id, found, rerr := d.getEmailIdentity(region, domain)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update ownership read gave no answer — reconcile before patching: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "identity no longer exists — cannot update"}
	}
	if !groundholdTagsMatch(id.tagMap(), capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "identity tags do not match — refusing to patch a resource that is not ours"}
	}

	for _, path := range changes {
		switch path {
		case "authentication.dkim":
			dkimBody := []byte(jsonBody(map[string]any{"SigningEnabled": plan.DKIM}))
			st, body, e := d.sesDo("PUT", region, sesIdentitiesPath+"/"+domain+"/dkim", dkimBody)
			switch {
			case e != nil:
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: fmt.Sprintf("PutEmailIdentityDkimAttributes outcome unknown (may have landed): %v", e)}
			case st == http.StatusOK:
				// patched
			case st >= 500:
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: fmt.Sprintf("PutEmailIdentityDkimAttributes HTTP %d (server error — may have landed)", st)}
			default:
				return provider.CreateResult{Status: "failed",
					Reason: fmt.Sprintf("PutEmailIdentityDkimAttributes HTTP %d: %s", st, sesErr(body))}
			}
		case "bounce.tracked":
			if plan.BounceTracked {
				// add: ensure the configuration set + the bounce event destination exist.
				if res := d.ensureSESComposite(region, providerID, plan); res.Status != "succeeded" {
					return res
				}
			} else {
				// remove: drop the configuration set (and with it the event destination).
				if res := d.deleteSESConfigSet(region, providerID, plan.ConfigurationSetName); res != nil {
					return *res
				}
			}
		default:
			// ClassifyChange gates this (unsupported); refuse honestly rather than no-op.
			return provider.CreateResult{Status: "failed",
				Reason: "no in-place SES sending mapping for " + path}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// discoverSESSending enumerates the region's SES domain sending identities as
// capability.email.sending — so `discover --provider aws` surfaces a sending
// domain for adoption. Reuses observeSESSending (two-step: list -> reverse map).
// A non-DOMAIN identity (a single verified address) is skipped: this capability
// governs domain senders, not per-address identities.
func (d *Driver) discoverSESSending(region string) ([]provider.Discovered, []string, error) {
	st, resp, err := d.sesDo("GET", region, "/v2/email/identities", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("ses ListEmailIdentities: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("ses ListEmailIdentities: HTTP %d", st)
	}
	var out struct {
		EmailIdentities []struct {
			IdentityName string `json:"IdentityName"`
			IdentityType string `json:"IdentityType"`
		} `json:"EmailIdentities"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return nil, nil, readBody("ListEmailIdentities", st)
	}
	var found []provider.Discovered
	var diags []string
	for _, id := range out.EmailIdentities {
		if id.IdentityType != "DOMAIN" {
			continue
		}
		pid := sesSendingProviderID(region, id.IdentityName)
		obs, od, oerr := d.observeSESSending("", pid)
		if oerr != nil {
			diags = append(diags, id.IdentityName+": "+oerr.Error())
			continue
		}
		diags = append(diags, od...)
		found = append(found, provider.Discovered{
			ProviderID: pid, ResourceType: "capability.email.sending", Observations: obs})
	}
	return found, diags, nil
}
