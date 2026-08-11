// GCP Security Command Center network shell (D76): the Security Center Management
// API half of the capability.security.threatdetection driver. The governed modules
// (securityCenterServices) are per-parent SINGLETONS addressed at
// {parent}/locations/global/securityCenterServices/{module}; a config is a PATCH of
// intendedEnablementState with an updateMask, applied synchronously (no LRO).
//
// Honesty per D29/D87, four-valued throughout:
//   - the SCOPE is deterministic (organization/project + the fixed module ids), so
//     the providerId is knowable BEFORE any write (D29) — a lost/garbled outcome
//     carries it so the posture that may have changed is never orphaned.
//   - a transport error or 5xx on a PATCH is unknown WITH the pid (the setting may
//     have landed) — reconcile, never a silent success/failure.
//   - observe/discover read effectiveEnablementState (the REAL state the tier
//     actually produces), so a Premium-gated module that was requested but is not
//     effective reports the truth, never the intent.
//
// OWNERSHIP. securityCenterServices carry no marker (no labels, no free-text), so
// there is NO owner gate — this resource is a SHARED per-parent singleton and
// groundhold is its CONFIGURATOR (see scc.go). Enabling detection is monotonic-safe;
// converge/update PATCH the governed modules to the desired intended state, and
// delete DISABLES them (posture off) — a stateless posture change (stateful:false),
// documented as affecting the shared parent. scc is consequently not claimable
// (claim.go honest-refuses it — nothing to stamp).
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

const sccBaseURL = "https://securitycentermanagement.googleapis.com/v1"

// sccBaseURLOverride redirects the SCC endpoint to a test server. It lives here
// rather than on the Driver struct because this driver ships entirely in its own
// files (the Driver struct is not edited); the httptest tests in this package do not
// run in parallel, so a package-level override is safe. Empty = real GCP.
var sccBaseURLOverride string

func (d *Driver) sccBase() string {
	if sccBaseURLOverride != "" {
		return sccBaseURLOverride
	}
	return sccBaseURL
}

// sccProviderID pins the identity: gcp-scc:<scopeType>:<scopeId> — self-describing
// (organizations|projects), so the parser knows the parent kind without guessing.
func sccProviderID(scopeType, scopeID string) string {
	return "gcp-scc:" + scopeType + ":" + scopeID
}

// splitSCCProviderID parses + VALIDATES a providerId before its components are
// interpolated into a REST path (D73 boundary): the scope type is a closed set and
// the id is bounded by its kind (numeric org id / project-id charset).
func splitSCCProviderID(providerID string) (scopeType, scopeID string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "gcp-scc" {
		return "", "", fmt.Errorf("providerId %q is not gcp-scc:scopeType:scopeId", providerID)
	}
	scopeType, scopeID = parts[1], parts[2]
	switch scopeType {
	case "organizations":
		if !orgIDOK.MatchString(scopeID) {
			return "", "", fmt.Errorf("providerId org id %q is invalid", scopeID)
		}
	case "projects":
		if !projectOK.MatchString(scopeID) {
			return "", "", fmt.Errorf("providerId project %q is invalid", scopeID)
		}
	default:
		return "", "", fmt.Errorf("providerId scope type %q is not organizations|projects", scopeType)
	}
	return scopeType, scopeID, nil
}

func (d *Driver) sccServiceURL(scopeType, scopeID, module string) string {
	return fmt.Sprintf("%s/%s/%s/locations/global/securityCenterServices/%s",
		d.sccBase(), scopeType, scopeID, module)
}

// sccService is the projection of a securityCenterServices.get the driver reads.
// intendedEnablementState is what groundhold set; effectiveEnablementState is what the
// tier actually produces — observe/converge trust the EFFECTIVE state for the truth.
type sccService struct {
	Name                     string `json:"name"`
	IntendedEnablementState  string `json:"intendedEnablementState"`
	EffectiveEnablementState string `json:"effectiveEnablementState"`
}

// getSCCService resolves one governed module. (found, readable): a 404 is
// found=false+readable (the module is not present for this parent — e.g. SCC not
// provisioned at the required tier); a transport error or any other non-200 is
// readable=false (unknown — never a fabricated absence).
func (d *Driver) getSCCService(scopeType, scopeID, module string) (sccService, bool, error) {
	const op = "sCCService.get"
	st, body, err := d.call("GET", d.sccServiceURL(scopeType, scopeID, module), nil)
	if err != nil {
		return sccService{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return sccService{}, false, nil
	}
	if st != http.StatusOK {
		return sccService{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var s sccService
	if json.Unmarshal(body, &s) != nil {
		return sccService{}, false, readBody(op, st)
	}
	return s, true, nil
}

// createSCC configures the parent's threat-detection posture. SCC config is a
// SHARED singleton with no ownership marker, so create is a CONVERGE: PATCH the
// governed modules to their desired intendedEnablementState (idempotent — a module
// already at the desired state is a no-op). The scope is deterministic, so the pid
// is knowable up front (D29).
func (d *Driver) createSCC(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildSCC(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if plan.ScopeType == "projects" {
		if err := d.sameProject(plan.ScopeID); err != nil {
			return provider.CreateResult{Status: "failed", Reason: err.Error()}
		}
	}
	pid := sccProviderID(plan.ScopeType, plan.ScopeID)
	return d.ensureSCCModules(pid, plan.desiredModules())
}

// ensureSCCModules converges the governed modules to a desired intended-state map,
// walked in a deterministic order. Shared by create-converge and the in-place
// update path. Four-valued: a not-found module (SCC absent / tier), an unreadable
// read, or an ambiguous PATCH is unknown WITH the pid (reconcile) — never a claimed
// success. For an intended=ENABLED that the tier cannot make effective, the truth
// (effective) is surfaced as unknown, never a fake posture.
func (d *Driver) ensureSCCModules(pid string, desired map[string]string) provider.CreateResult {
	scopeType, scopeID, err := splitSCCProviderID(pid)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	for _, module := range sccModulesSorted() {
		want := desired[module]
		cur, found, rerr := d.getSCCService(scopeType, scopeID, module)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("pre-configure read of SCC module %q gave no answer — reconcile: %v", module, rerr)}
		}
		if !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("SCC module %q not found for %s/%s — is Security Command Center "+
					"provisioned at the required tier? reconcile", module, scopeType, scopeID)}
		}
		if cur.IntendedEnablementState == want {
			continue // already at the desired posture — no-op
		}
		st, body, err := d.call("PATCH",
			d.sccServiceURL(scopeType, scopeID, module)+"?updateMask=intendedEnablementState",
			map[string]any{"intendedEnablementState": want})
		switch {
		case err != nil:
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("configure SCC module %q outcome unknown (may have landed) — reconcile: %v", module, err)}
		case st == http.StatusConflict || st == http.StatusPreconditionFailed:
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("concurrent SCC settings change on %q — reconcile", module)}
		case st >= 500:
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("configure SCC module %q HTTP %d (server error — may have landed) — reconcile", module, st)}
		case st >= 400:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("configure SCC module %q HTTP %d: %s", module, st, mutDetail(body))}
		}
		// honesty: an intended=ENABLED that the tier cannot honor leaves effective
		// != ENABLED — surface the truth as unknown, never a fabricated posture.
		if want == "ENABLED" {
			var s sccService
			if json.Unmarshal(body, &s) == nil && s.EffectiveEnablementState != "" &&
				s.EffectiveEnablementState != "ENABLED" {
				return provider.CreateResult{ProviderID: pid, Status: "unknown",
					Reason: fmt.Sprintf("SCC module %q set to intended=ENABLED but effective=%s — the SCC "+
						"tier may not include this module; verify the subscription tier, then reconcile",
						module, s.EffectiveEnablementState)}
			}
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// observeSCC reverse-maps the live posture to capability.security.threatdetection:
// detection.enabled (event-threat effective==ENABLED), protection.kubernetes/malware
// (the container/VM module effective states), location.region=global, service.managed.
// An unreadable module is unknown (an error); an absent core module (event-threat
// 404) is nothing-to-observe.
func (d *Driver) observeSCC(capability, providerID string) ([]provider.Observation, []string, error) {
	scopeType, scopeID, err := splitSCCProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if scopeType == "projects" {
		if err := d.sameProject(scopeID); err != nil {
			return nil, nil, err
		}
	}
	event, ef, er := d.getSCCService(scopeType, scopeID, sccModuleEventThreat)
	if er != nil {
		return nil, nil, er
	}
	if !ef {
		// F-LC3 (D521): a BOUND resource the API says is GONE. A diagnostic
		// alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"SCC event-threat-detection not found — bound resource is gone (will re-create)"}, nil
	}
	container, cf, cr := d.getSCCService(scopeType, scopeID, sccModuleContainerThreat)
	if cr != nil {
		return nil, nil, cr
	}
	vm, vf, vr := d.getSCCService(scopeType, scopeID, sccModuleVMThreat)
	if vr != nil {
		return nil, nil, vr
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: "global", Derivation: "measured"},
		{Path: "detection.enabled", Value: event.EffectiveEnablementState == "ENABLED", Derivation: "measured"},
		{Path: "protection.kubernetes", Value: cf && container.EffectiveEnablementState == "ENABLED", Derivation: "measured"},
		{Path: "protection.malware", Value: vf && vm.EffectiveEnablementState == "ENABLED", Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	return obs, nil, nil
}

// updateSCC patches the bound posture IN PLACE (D46): detection.enabled and the
// protection.* surface all flow through securityCenterServices.patch. The change-set
// is gated (every path must be one this service patches), the desired posture is
// re-derived (refuse-before-mutate) from the hash-pinned candidate, and the rebuilt
// scope must match the bound providerId (a forged binding must not redirect the
// mutation to another parent). Four-valued throughout.
func (d *Driver) updateSCC(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	scopeType, scopeID, err := splitSCCProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if scopeType == "projects" {
		if err := d.sameProject(scopeID); err != nil {
			return provider.CreateResult{Status: "failed", Reason: err.Error()}
		}
	}
	for _, path := range changes {
		if kind, reason := classifySCCChange(path); kind != "mutable" {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("scc cannot honor an in-place change to %q: %s", path, reason)}
		}
	}
	plan, err := BuildSCC(d.Project, environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if plan.ScopeType != scopeType || plan.ScopeID != scopeID {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("rebuilt SCC scope %s/%s does not match the bound providerId %s/%s — refusing to redirect the mutation",
				plan.ScopeType, plan.ScopeID, scopeType, scopeID)}
	}
	return d.ensureSCCModules(providerID, plan.desiredModules())
}

// deleteSCC retires the posture: DISABLE the governed modules (detection off). SCC
// is stateless (stateful:false) — findings live in the service, so this is a POSTURE
// change, not the loss of a store. No ownership marker exists, so this is documented
// as a shared-parent posture change (the operator retiring the contract is the
// consent). Idempotent on already-disabled/absent; four-valued on the wire.
func (d *Driver) deleteSCC(capability, environment, providerID string) provider.CreateResult {
	scopeType, scopeID, err := splitSCCProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if scopeType == "projects" {
		if err := d.sameProject(scopeID); err != nil {
			return provider.CreateResult{Status: "failed", Reason: err.Error()}
		}
	}
	for _, module := range sccModulesSorted() {
		cur, found, rerr := d.getSCCService(scopeType, scopeID, module)
		if rerr != nil {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("pre-delete read of SCC module %q gave no answer — reconcile: %v", module, rerr)}
		}
		if !found || cur.IntendedEnablementState == "DISABLED" {
			continue // nothing to disable — idempotent
		}
		st, body, err := d.call("PATCH",
			d.sccServiceURL(scopeType, scopeID, module)+"?updateMask=intendedEnablementState",
			map[string]any{"intendedEnablementState": "DISABLED"})
		switch {
		case err != nil:
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("disable SCC module %q outcome unknown: %v", module, err)}
		case st == http.StatusConflict || st == http.StatusPreconditionFailed:
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("concurrent SCC settings change on %q — reconcile", module)}
		case st >= 500:
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("disable SCC module %q HTTP %d (server error) — reconcile", module, st)}
		case st >= 400:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("disable SCC module %q HTTP %d: %s", module, st, mutDetail(body))}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// discoverSCC surfaces the pinned project's SCC posture as
// capability.security.threatdetection — so `discover --provider gcp` sees the
// threat-detection posture for adoption. SCC is project-global (region does not
// filter); a project with no SCC provisioned (event-threat 404) surfaces nothing.
func (d *Driver) discoverSCC(region string) ([]provider.Discovered, []string, error) {
	if d.Project == "" {
		return nil, nil, nil // no pinned scope to sweep
	}
	pid := sccProviderID("projects", d.Project)
	obs, diags, err := d.observeSCC("", pid)
	if err != nil {
		return nil, nil, fmt.Errorf("scc: %v", err)
	}
	if len(obs) == 0 || provider.IsAbsent(obs) {
		return nil, diags, nil // SCC not provisioned — nothing to discover
	}
	return []provider.Discovered{{
		ProviderID:   pid,
		ResourceType: "capability.security.threatdetection",
		Observations: provider.WithoutAbsence(obs),
	}}, diags, nil
}
