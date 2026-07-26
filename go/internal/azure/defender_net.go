// Microsoft Defender for Cloud network shell (D76 parity): the ARM half of the Azure
// capability.security.threatdetection driver. The governed plans
// (Microsoft.Security/pricings/{planName}) are per-subscription SINGLETONS; a config is
// a PUT of {properties:{pricingTier[,subPlan][,extensions]}}, applied synchronously
// (no LRO). This is the conceptual TWIN of internal/gcp/scc_net.go.
//
// Honesty per D29/D87, four-valued throughout:
//   - the SCOPE is deterministic (the subscription + the fixed plan names), so the
//     providerId is knowable BEFORE any write (D29) — a lost/garbled outcome carries it
//     so the posture that may have changed is never orphaned.
//   - a transport error or 5xx on a PUT is unknown WITH the pid (the setting may have
//     landed) — reconcile, never a silent success/failure.
//   - after a PUT that requested Standard, the returned pricingTier is re-read from the
//     response; if it is not Standard the truth is surfaced as unknown (the plan may be
//     unavailable on the subscription), never a claimed posture.
//
// OWNERSHIP. pricings carry no marker (no tags, no free-text), so there is NO owner
// gate — this is a SHARED per-subscription config singleton and groundhold is its
// CONFIGURATOR (see defender.go). Enabling detection is monotonic-safe; converge/update
// PUT the governed plans to Standard/Free, and delete sets them Free (posture off) — a
// stateless posture change (stateful:false), documented as affecting the shared
// subscription. Defender is consequently not claimable (claim_azure.go honest-refuses
// it — nothing to stamp).
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// defenderProviderID pins the identity: defender:<subscription> — self-describing and
// scope-complete (a pricing is per-subscription; the plan names are fixed).
func defenderProviderID(sub string) string { return "defender:" + sub }

// splitDefenderProviderID parses + VALIDATES a providerId before its subscription is
// interpolated into an ARM path (D73 boundary): the prefix is fixed and the id is a GUID.
func splitDefenderProviderID(providerID string) (sub string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 2 || parts[0] != "defender" {
		return "", fmt.Errorf("providerId %q is not defender:subscription", providerID)
	}
	if !subOK.MatchString(parts[1]) {
		return "", fmt.Errorf("providerId subscription %q is not a valid GUID", parts[1])
	}
	return parts[1], nil
}

// defenderPricingURL builds the subscription-scoped pricings URL (no resource group;
// pricings live directly under the subscription). The subscription is bounded by the
// caller (subOK) before it reaches here; the plan name is from a fixed closed set.
func (d *Driver) defenderPricingURL(sub, plan string) string {
	return fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Security/pricings/%s?api-version=%s",
		d.BaseURL, sub, plan, defenderAPIVersion)
}

// defenderPricing is the projection of a pricings.get the driver reads.
type defenderPricing struct {
	Properties struct {
		PricingTier string `json:"pricingTier"`
		SubPlan     string `json:"subPlan"`
		Extensions  []struct {
			Name      string `json:"name"`
			IsEnabled string `json:"isEnabled"`
		} `json:"extensions"`
	} `json:"properties"`
}

// malwareEnabled reports whether the on-upload malware extension is enabled.
func (p defenderPricing) malwareEnabled() bool {
	for _, e := range p.Properties.Extensions {
		if e.Name == defenderMalwareExtension && strings.EqualFold(e.IsEnabled, "True") {
			return true
		}
	}
	return false
}

// getDefenderPricing resolves one governed plan. (found, readable): a 404 is
// found=false+readable (the plan is not present for this subscription — Defender may
// not offer it); a transport error or any other non-200 is readable=false (unknown —
// never a fabricated absence).
// getDefenderPricing resolves one governed plan. D297: a 404 stays found=false
// with NO error (the plan is simply not present for this subscription —
// Defender may not offer it); every other failure returns an error NAMING the
// cause instead of a bare "unreadable".
func (d *Driver) getDefenderPricing(sub, plan string) (defenderPricing, bool, error) {
	var doc defenderPricing
	found, err := d.armGetURLInto("pricings.get", d.defenderPricingURL(sub, plan), &doc)
	return doc, found, err
}

// defenderBody builds the pricings PUT body for one desired plan shape.
func defenderBody(want defenderDesired) map[string]any {
	props := map[string]any{"pricingTier": want.tier}
	if want.subPlan != "" {
		props["subPlan"] = want.subPlan
	}
	if want.malware {
		props["extensions"] = []map[string]any{
			{"name": defenderMalwareExtension, "isEnabled": "True"},
		}
	}
	return map[string]any{"properties": props}
}

// atDesired reports whether the current pricing already matches the desired shape
// (idempotent no-op). Tier is the primary signal; when Standard, the subPlan and the
// malware extension must also match so a partial converge still re-PUTs.
func atDesired(cur defenderPricing, want defenderDesired) bool {
	if !strings.EqualFold(cur.Properties.PricingTier, want.tier) {
		return false
	}
	if want.tier != "Standard" {
		return true // Free: subPlan/extensions irrelevant
	}
	if want.subPlan != "" && !strings.EqualFold(cur.Properties.SubPlan, want.subPlan) {
		return false
	}
	if want.malware != cur.malwareEnabled() {
		return false
	}
	return true
}

// createDefender configures the subscription's threat-detection posture. Defender
// pricing is a SHARED singleton with no ownership marker, so create is a CONVERGE: PUT
// the governed plans to their desired shape (idempotent — a plan already at the desired
// shape is a no-op). The scope is deterministic, so the pid is knowable up front (D29).
func (d *Driver) createDefender(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildDefender(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := defenderProviderID(d.Subscription)
	return d.ensureDefenderPlans(pid, plan.desiredPlans())
}

// ensureDefenderPlans converges the governed plans to a desired shape map, walked in a
// deterministic order. Shared by create-converge and the in-place update path.
// Four-valued: an unreadable pre-read, a transport/5xx PUT, or a requested-Standard the
// subscription cannot honor is unknown WITH the pid (reconcile) — never a claimed success.
func (d *Driver) ensureDefenderPlans(pid string, desired map[string]defenderDesired) provider.CreateResult {
	sub, err := splitDefenderProviderID(pid)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	for _, plan := range defenderPlansSorted() {
		want := desired[plan]
		cur, found, rerr := d.getDefenderPricing(sub, plan)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("pre-configure read of Defender plan %q gave no answer — reconcile: %v", plan, rerr)}
		}
		// A 404 (plan not present) with a desired Free is nothing to do; a desired
		// Standard on an absent plan means the subscription does not offer it — the PUT
		// below decides, and the read-back guards a fake success.
		if found && atDesired(cur, want) {
			continue // already at the desired posture — no-op
		}
		st, body, perr := d.doARM("PUT", d.defenderPricingURL(sub, plan), mustJSON(defenderBody(want)))
		switch {
		case perr != nil:
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("configure Defender plan %q outcome unknown (may have landed) — reconcile: %v", plan, perr)}
		case st == http.StatusConflict || st == http.StatusPreconditionFailed:
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("concurrent Defender pricing change on %q — reconcile", plan)}
		case st >= 500:
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("configure Defender plan %q HTTP %d (server error — may have landed) — reconcile", plan, st)}
		case st < 200 || st >= 300:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("configure Defender plan %q HTTP %d: %s", plan, st, mutDetailAz(body))}
		}
		// honesty: a requested Standard the subscription cannot honor comes back with a
		// non-Standard tier — surface the truth as unknown, never a fabricated posture.
		if want.tier == "Standard" {
			var got defenderPricing
			if json.Unmarshal(body, &got) == nil && got.Properties.PricingTier != "" &&
				!strings.EqualFold(got.Properties.PricingTier, "Standard") {
				return provider.CreateResult{ProviderID: pid, Status: "unknown",
					Reason: fmt.Sprintf("Defender plan %q PUT requested Standard but returned tier=%s — the plan "+
						"may be unavailable on this subscription; verify, then reconcile",
						plan, got.Properties.PricingTier)}
			}
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// observeDefender reverse-maps the live posture to capability.security.threatdetection:
// detection.enabled (VirtualMachines tier==Standard), protection.kubernetes/malware
// (Containers tier / Storage tier+malware-extension), location.region=global,
// service.managed. An unreadable plan is unknown (an error); an absent core plan
// (VirtualMachines 404) is nothing-to-observe.
func (d *Driver) observeDefender(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, err := splitDefenderProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	servers, sf, sr := d.getDefenderPricing(sub, defenderPlanServers)
	if sr != nil {
		return nil, nil, sr
	}
	if !sf {
		return nil, []string{"Defender VirtualMachines plan not found — nothing to observe"}, nil
	}
	containers, cf, cr := d.getDefenderPricing(sub, defenderPlanContainers)
	if cr != nil {
		return nil, nil, cr
	}
	storage, stf, str := d.getDefenderPricing(sub, defenderPlanStorage)
	if str != nil {
		return nil, nil, str
	}
	standard := func(p defenderPricing) bool { return strings.EqualFold(p.Properties.PricingTier, "Standard") }
	obs := []provider.Observation{
		{Path: "location.region", Value: "global", Derivation: "measured"},
		{Path: "detection.enabled", Value: standard(servers), Derivation: "measured"},
		{Path: "protection.kubernetes", Value: cf && standard(containers), Derivation: "measured"},
		// malware is Standard tier AND the on-upload malware extension enabled — both,
		// so the observation never claims scanning that is not actually configured.
		{Path: "protection.malware", Value: stf && standard(storage) && storage.malwareEnabled(), Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	return obs, nil, nil
}

// updateDefender patches the bound posture IN PLACE (D46): detection.enabled and the
// protection.* surface all flow through a pricings PUT. The change-set is gated (every
// path must be one this service patches), the desired posture is re-derived
// (refuse-before-mutate) from the hash-pinned candidate, and the rebuilt scope must
// match the bound providerId (a forged binding must not redirect the mutation to another
// subscription). Four-valued throughout.
func (d *Driver) updateDefender(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	sub, err := splitDefenderProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's — refusing to redirect the mutation", sub)}
	}
	for _, path := range changes {
		if kind, reason := classifyDefenderChange(path); kind != "mutable" {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("defender cannot honor an in-place change to %q: %s", path, reason)}
		}
	}
	plan, err := BuildDefender(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	return d.ensureDefenderPlans(providerID, plan.desiredPlans())
}

// deleteDefender retires the posture: set the governed plans back to Free (detection
// off). Defender is stateless (stateful:false) — alerts/findings live in the service, so
// this is a POSTURE change, not the loss of a store. No ownership marker exists, so this
// is documented as a shared-subscription posture change (the operator retiring the
// contract is the consent). Idempotent on already-Free/absent; four-valued on the wire.
func (d *Driver) deleteDefender(capability, environment, providerID string) provider.CreateResult {
	sub, err := splitDefenderProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	free := defenderDesired{tier: "Free"}
	for _, plan := range defenderPlansSorted() {
		cur, found, rerr := d.getDefenderPricing(sub, plan)
		if rerr != nil {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("pre-delete read of Defender plan %q gave no answer — reconcile: %v", plan, rerr)}
		}
		if !found || strings.EqualFold(cur.Properties.PricingTier, "Free") {
			continue // nothing to disable — idempotent
		}
		st, body, perr := d.doARM("PUT", d.defenderPricingURL(sub, plan), mustJSON(defenderBody(free)))
		switch {
		case perr != nil:
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("disable Defender plan %q outcome unknown: %v", plan, perr)}
		case st == http.StatusConflict || st == http.StatusPreconditionFailed:
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("concurrent Defender pricing change on %q — reconcile", plan)}
		case st >= 500:
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("disable Defender plan %q HTTP %d (server error) — reconcile", plan, st)}
		case st < 200 || st >= 300:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("disable Defender plan %q HTTP %d: %s", plan, st, mutDetailAz(body))}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// discoverDefender surfaces the pinned subscription's Defender posture as
// capability.security.threatdetection — so `discover --provider azure` sees the
// threat-detection posture for adoption. Defender is subscription-global (region does
// not filter); a subscription with no VirtualMachines plan surfaces nothing.
func (d *Driver) discoverDefender(region string) ([]provider.Discovered, []string, error) {
	if !subOK.MatchString(d.Subscription) {
		return nil, nil, nil // no valid pinned scope to sweep
	}
	pid := defenderProviderID(d.Subscription)
	obs, diags, err := d.observeDefender("", pid)
	if err != nil {
		return nil, nil, fmt.Errorf("defender: %v", err)
	}
	if len(obs) == 0 {
		return nil, diags, nil // Defender not readable/absent — nothing to discover
	}
	return []provider.Discovered{{
		ProviderID:   pid,
		ResourceType: "capability.security.threatdetection",
		Observations: obs,
	}}, diags, nil
}

// mustJSON marshals a body that is always well-formed (fixed shapes) — an error here is
// a programmer bug, not a runtime condition.
func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
