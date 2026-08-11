// Load-balancer network shell: the httptest-covered half of the GCP
// capability.network.loadbalancer driver. groundhold must SEE GCP load balancers —
// Observe (forwardingRules.get) + a discovery sweep (forwardingRules.aggregatedList)
// — AND provision them: createLoadBalancer/deleteLoadBalancer stand up and tear
// down the GLOBAL EXTERNAL HTTP(S) composite (health check + backend service +
// url map + target proxy + global forwarding rule + reserved IP). Everything
// semantic (the composite plan, ownership, four-valued refusals) lives in the
// pure builder (loadbalancer.go); this file is the polled, ownership-guarded
// state machine over compute/v1. In-place update is not wired (scheme/inTransit
// are replacements; a healthCheckPath patch is the next step).
//
// providerId: "lb:<project>:<scope>:<forwardingRule>", where <scope> is "global"
// or a region. The scope is load-bearing: a regional forwarding rule cannot be
// re-fetched without its region (a global one lives under global/), so the read
// handle carries it — the same discipline gvpn/memorystore providerIds follow.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func lbProviderID(project, scope, name string) string {
	return "lb:" + project + ":" + scope + ":" + name
}

// splitLBProviderID validates every component before it is interpolated into a
// compute REST path (D73 confused-deputy boundary).
func splitLBProviderID(providerID string) (project, scope, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "lb" {
		return "", "", "", fmt.Errorf(
			"providerId %q is not lb:project:scope:forwardingRule", providerID)
	}
	for i, p := range parts[1:] {
		if !gcpName.MatchString(p) {
			return "", "", "", fmt.Errorf(
				"providerId component %d (%q) is not a valid GCP identifier — "+
					"refusing to interpolate it into an API path", i+1, p)
		}
	}
	return parts[1], parts[2], parts[3], nil
}

// lbForwardingRuleURL builds the forwardingRules.get URL for a scope. "global"
// lives under global/forwardingRules; any other scope is a region.
func (d *Driver) lbForwardingRuleURL(project, scope, name string) string {
	if scope == "global" {
		return fmt.Sprintf("%s/projects/%s/global/forwardingRules/%s",
			d.computeBase(), project, name)
	}
	return fmt.Sprintf("%s/projects/%s/regions/%s/forwardingRules/%s",
		d.computeBase(), project, scope, name)
}

// observeLoadBalancer reads one forwarding rule (the LB frontend) and reverse-maps
// it through the pure MapLoadBalancer. Read-only.
func (d *Driver) observeLoadBalancer(capability, providerID string) ([]provider.Observation, []string, error) {
	project, scope, name, err := splitLBProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	status, body, err := d.call("GET", d.lbForwardingRuleURL(project, scope, name), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("forwardingRules.get: %v", err)
	}
	if status == http.StatusNotFound {
		return []provider.Observation{
			// F-LC3 (D802): a BOUND resource the API authoritatively 404s is GONE. An
			// empty return leaves the last good observations standing as the freshest
			// word, so posture reads managed-ok and audit stays satisfied about a
			// resource that does not exist (D513/D518, fixed here last).
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"forwarding rule not found — bound resource is gone (will re-create)"}, nil
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("forwardingRules.get: HTTP %d", status)
	}
	var fr lbForwardingRule
	if json.Unmarshal(body, &fr) != nil {
		return nil, nil, readBody("forwardingRules.get", status)
	}
	observed, diags := MapLoadBalancer(fr)
	out := make([]provider.Observation, 0, len(observed))
	for _, o := range observed {
		out = append(out, provider.Observation{
			Path: o.Path, Value: o.Value, Derivation: o.Derivation})
	}
	return out, diags, nil
}

// createLoadBalancer stands up the GLOBAL EXTERNAL HTTP(S) load-balancer
// composite in dependency order (IP -> health check -> backend service -> URL
// map -> target proxy -> forwarding rule), polling each global operation to DONE.
// Ownership rides in each resource's description marker; a name conflict is
// classified ours/foreign/unreadable per the VPC discipline. Idempotent: a re-run
// finds our sub-resources by name and proceeds; a foreign one is refused.
//
// FOUR-VALUED partial handling (D29): the providerId is the deterministic
// forwarding-rule handle, knowable before any insert. Once ANY sub-resource is
// built, a later step that does not complete returns `unknown` WITH the
// providerId — a half-built composite (e.g. backend+proxy up, forwarding rule
// failed) is NEVER a silent success and NEVER a target-less orphan; retirement
// recomputes every sibling from the frName and tears it down.
func (d *Driver) createLoadBalancer(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildLoadBalancerPlan(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	cb := d.computeBase()
	pid := lbProviderID(d.Project, "global", plan.Names.ForwardingRule)
	built := false // has at least one of OUR sub-resources been created/adopted?

	for _, sub := range plan.Create {
		collURL := fmt.Sprintf("%s/projects/%s/global/%s", cb, d.Project, sub.Kind)
		getURL := collURL + "/" + sub.Name
		st, res := d.computeInsert(collURL, sub.Body, "global")

		if st == http.StatusConflict {
			desc, cfound, rerr := d.computeGet(getURL)
			switch {
			case rerr != nil:
				return provider.CreateResult{ProviderID: pid, Status: "unknown",
					Reason: fmt.Sprintf("name conflict on %s/%s, existing resource gave no answer — reconcile: %v",
						sub.Kind, sub.Name, rerr)}
			case !cfound:
				return provider.CreateResult{ProviderID: pid, Status: "unknown",
					Reason: fmt.Sprintf("name conflict on %s/%s, but it was gone on the follow-up read — reconcile",
						sub.Kind, sub.Name)}
			case !markerOurs(desc, capability, environment):
				if built {
					return provider.CreateResult{ProviderID: pid, Status: "unknown",
						Reason: fmt.Sprintf("partial composite: %s/%s name is taken by a FOREIGN "+
							"resource, downstream not built — reconcile/retire", sub.Kind, sub.Name)}
				}
				return provider.CreateResult{Status: "failed",
					Reason: fmt.Sprintf("%s/%s exists but is not ours (marker mismatch) — "+
						"refusing to adopt a foreign sub-resource", sub.Kind, sub.Name)}
			}
			built = true // ours already — converged for this phase
			continue
		}

		if res.Status == "succeeded" {
			built = true
			continue
		}

		// res is `failed` (4xx) or `unknown` (5xx/lost). A partial composite (built
		// through the previous step) is ALWAYS `unknown` WITH the pid — never a
		// silent success, never a bare failure that hides orphaned half-plumbing.
		if built {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("partial load-balancer composite: built through the "+
					"previous step, %s did not complete (%s) — reconcile/retire", sub.Kind, res.Reason)}
		}
		// nothing of ours built yet: a lost/5xx first step MAY have landed (D29) —
		// carry the pid; a clean 4xx failure has nothing to reconcile.
		if res.Status == "unknown" {
			res.ProviderID = pid
		}
		return res
	}

	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// updateLoadBalancer: in-place update is not wired in this slice. ClassifyChange
// routes the governed attributes (scheme/inTransit) to REPLACEMENT; the only
// mutable knob is the health-check path (an operand), whose in-place patch is the
// next step. Honest refusal beats a silent no-op.
func (d *Driver) updateLoadBalancer(capability, environment, providerID string) provider.CreateResult {
	return provider.CreateResult{Status: "failed",
		Reason: "loadbalancer in-place update is not wired in this slice — scheme/inTransit " +
			"changes are replacements (ClassifyChange); a healthCheckPath patch is the next step"}
}

// deleteLoadBalancer tears the composite down in REVERSE dependency order
// (forwarding rule -> target proxy -> url map -> backend service -> health check
// -> release IP), each guarded by the ownership marker. Sub-resource names are
// recomputed by SUFFIX from the forwarding-rule name carried in the providerId —
// no generation, no chain traversal. Idempotent on 404; a 5xx mid-teardown is
// `unknown` (the composite may be partly gone — reconcile), never a false success.
func (d *Driver) deleteLoadBalancer(capability, environment, providerID string) provider.CreateResult {
	project, scope, fr, err := splitLBProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if scope != "global" {
		return provider.CreateResult{Status: "failed",
			Reason: "this driver provisions only the GLOBAL external HTTP(S) LB — a " +
				scope + "-scoped forwarding rule is not managed by it"}
	}
	cb := d.computeBase()
	// reverse dependency order; both proxy variants are attempted (the absent one
	// 404s to an idempotent success), so delete needs no knowledge of inTransit.
	order := []struct{ kind, name string }{
		{"forwardingRules", fr},
		{"targetHttpProxies", fr + "-hp"},
		{"targetHttpsProxies", fr + "-sp"},
		{"urlMaps", fr + "-um"},
		{"backendServices", fr + "-bs"},
		{"healthChecks", fr + "-hc"},
		{"addresses", fr + "-ip"},
	}
	for _, r := range order {
		url := fmt.Sprintf("%s/projects/%s/global/%s/%s", cb, project, r.kind, r.name)
		res := d.lbDeleteOwned(url, "global", capability, environment)
		if res.Status != "succeeded" {
			res.ProviderID = providerID // still-present resources — keep the handle
			return res
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// lbDeleteOwned pre-reads one composite resource and deletes it only if it is
// ours. Absent (404) is an idempotent success; an unreadable/5xx pre-read is
// `unknown` (refuse an ambiguous delete); a foreign marker is `failed` (never
// delete what is not ours).
func (d *Driver) lbDeleteOwned(url, scope, capability, environment string) provider.CreateResult {
	status, body, err := d.call("GET", url, nil)
	if err != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("pre-delete read failed: %v", err)}
	}
	if status == http.StatusNotFound {
		return provider.CreateResult{Status: "succeeded"} // idempotent absence
	}
	if status != http.StatusOK {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("pre-delete read HTTP %d — refusing an ambiguous delete", status)}
	}
	var r struct {
		Description string `json:"description"`
	}
	if json.Unmarshal(body, &r) != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: "pre-delete read unparseable — refusing an ambiguous delete"}
	}
	if !markerOurs(r.Description, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "a resource under our deterministic name is not ours (marker mismatch) — " +
				"refusing to delete a foreign resource"}
	}
	return d.computeDelete(url, scope)
}

// lbScopeFromKey maps an aggregatedList scope key to a providerId scope.
// "global" stays "global"; "regions/us-central1" -> "us-central1". Zonal or
// unrecognized keys return "" (forwarding rules are only global or regional).
func lbScopeFromKey(key string) string {
	if key == "global" {
		return "global"
	}
	if strings.HasPrefix(key, "regions/") {
		return strings.TrimPrefix(key, "regions/")
	}
	return ""
}

// discoverLoadBalancers enumerates every forwarding rule in the project as
// capability.network.loadbalancer via a single aggregatedList (all scopes), then
// reverse-maps each through the same pure MapLoadBalancer Observe uses. region,
// when given, filters on the forwarding rule's scope (a region name); global
// forwarding rules are excluded by a region filter (they are not in that region).
func (d *Driver) discoverLoadBalancers(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/aggregated/forwardingRules", d.computeBase(), d.Project), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("forwardingRules.aggregatedList: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("forwardingRules.aggregatedList: HTTP %d", status)
	}
	var resp struct {
		Items map[string]struct {
			ForwardingRules []lbForwardingRule `json:"forwardingRules"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("forwardingRules.aggregatedList", status)
	}
	var out []provider.Discovered
	var diags []string
	for scopeKey, bucket := range resp.Items {
		scope := lbScopeFromKey(scopeKey)
		if scope == "" {
			continue // a zonal/unknown scope — forwarding rules are global or regional
		}
		if region != "" && scope != region {
			continue // another scope — not this sweep
		}
		for _, fr := range bucket.ForwardingRules {
			if fr.Name == "" {
				continue
			}
			observed, ds := MapLoadBalancer(fr)
			for _, dg := range ds {
				diags = append(diags, fr.Name+": "+dg)
			}
			obs := make([]provider.Observation, 0, len(observed))
			for _, o := range observed {
				obs = append(obs, provider.Observation{
					Path: o.Path, Value: o.Value, Derivation: o.Derivation})
			}
			out = append(out, provider.Discovered{
				ProviderID:   lbProviderID(d.Project, scope, fr.Name),
				ResourceType: "capability.network.loadbalancer",
				Observations: provider.WithoutAbsence(obs),
			})
		}
	}
	return out, diags, nil
}
