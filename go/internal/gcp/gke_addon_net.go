// GKE cluster-addon network shell (D76 parity): the bearer-signed REST half of
// the capability.cluster.addon GCP driver. Every mutation is a cluster
// SetAddonsConfig (an UpdateCluster op) — the addon is a FLAG, not a package, so
// create = enable the flag, delete = disable it, and there is NO in-place
// per-addon version patch (see gke_addon.go). Async throughout (LRO); the
// providerId is deterministic (project:location:cluster:addonName), so a lost
// response (D29) always carries the handle. Ownership is STRUCTURAL: the addon
// has no marker of its own, so identity is the (cluster, canonical name) tuple,
// gated by the cluster being ours-to-operate (readable) — never a tag match.
// D29/D87 four-valued honesty throughout.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func (d *Driver) gkeAddonBase() string {
	if gkeAddonBaseOverride != "" {
		return gkeAddonBaseOverride
	}
	return gkeAddonContainerBaseURL
}

// gkeAddonProviderID is the pinned identity:
// gke-addon:<project>:<location>:<cluster>:<addonName>. The canonical addon name
// carries no ':' (registry keys are hyphenated), so the 5-way split is
// unambiguous.
func gkeAddonProviderID(project, location, cluster, addon string) string {
	return "gke-addon:" + project + ":" + location + ":" + cluster + ":" + addon
}

func splitGKEAddonProviderID(providerID string) (project, location, cluster, addon string, err error) {
	parts := strings.SplitN(providerID, ":", 5)
	if len(parts) != 5 || parts[0] != "gke-addon" {
		return "", "", "", "", fmt.Errorf("providerId %q is not gke-addon:project:location:cluster:addon", providerID)
	}
	project, location, cluster, addon = parts[1], parts[2], parts[3], parts[4]
	if !projectOK.MatchString(project) {
		return "", "", "", "", fmt.Errorf("providerId project %q is invalid", project)
	}
	if !gkeAddonLocationOK.MatchString(location) {
		return "", "", "", "", fmt.Errorf("providerId location %q is invalid", location)
	}
	if !gkeAddonClusterOK.MatchString(cluster) {
		return "", "", "", "", fmt.Errorf("providerId cluster %q is invalid", cluster)
	}
	if _, known := gkeAddonRegistry[addon]; !known {
		return "", "", "", "", fmt.Errorf("providerId addon %q is not a known GKE addon", addon)
	}
	return project, location, cluster, addon, nil
}

func (d *Driver) gkeAddonClusterURL(project, location, cluster string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/clusters/%s",
		d.gkeAddonBase(), project, location, cluster)
}

// gkeAddonClusterDoc is the slice of the cluster GET this driver reads — the
// addonsConfig it toggles, plus status. It reads NOTHING about nodes or
// workloads (that is the gke [cluster] driver's concern).
type gkeAddonClusterDoc struct {
	Name         string         `json:"name"`
	Location     string         `json:"location"`
	Status       string         `json:"status"`
	AddonsConfig map[string]any `json:"addonsConfig"`
}

// getGKEAddonCluster resolves the cluster the addon lives on. (found, readable)
// mirror the family: a 404 is found=false+readable (gone), a transport/other
// error is readable=false (unknown — never a fabricated absence).
func (d *Driver) getGKEAddonCluster(project, location, cluster string) (gkeAddonClusterDoc, bool, error) {
	const op = "gKEAddonCluster.get"
	st, body, err := d.gcpGetRetry("GET", d.gkeAddonClusterURL(project, location, cluster), nil)
	if err != nil {
		return gkeAddonClusterDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return gkeAddonClusterDoc{}, false, nil
	}
	if st != http.StatusOK {
		return gkeAddonClusterDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc gkeAddonClusterDoc
	if json.Unmarshal(body, &doc) != nil {
		return gkeAddonClusterDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

// setAddon issues the SetAddonsConfig mutation (enable or disable the one
// addon), returning the LRO operation name. Four-valued status mapping is the
// caller's; this returns (opName, httpStatus, body, err).
func (d *Driver) setAddon(project, location, cluster string, spec gkeAddonSpec, enable bool) (string, int, []byte, error) {
	body := map[string]any{"addonsConfig": spec.configFragment(enable)}
	url := d.gkeAddonClusterURL(project, location, cluster) + ":setAddons"
	st, resp, err := d.call("POST", url, body)
	if err != nil {
		return "", st, resp, err
	}
	if st != http.StatusOK {
		return "", st, resp, nil
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(resp, &op) != nil || op.Name == "" {
		return "", st, resp, nil
	}
	return op.Name, st, resp, nil
}

// pollGKEAddonOperation polls the container LRO to DONE. A non-nil error object
// is a failure (fail-open closed, like pollOperation); the timeout is unknown
// WITH the operation name for reconciliation.
func (d *Driver) pollGKEAddonOperation(project, location, opName string) provider.CreateResult {
	opID := leafName(opName)
	deadline := d.Now().Add(d.gkeLROTimeout())
	for {
		st, body, err := d.call("GET", fmt.Sprintf("%s/projects/%s/locations/%s/operations/%s",
			d.gkeAddonBase(), project, location, opID), nil)
		if err == nil && st == http.StatusOK {
			var op struct {
				Status string `json:"status"`
				Error  *struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &op) == nil && op.Status == "DONE" {
				if op.Error != nil {
					return provider.CreateResult{OperationID: opName, Status: "failed",
						Reason: "operation failed: " + op.Error.Message}
				}
				return provider.CreateResult{OperationID: opName, Status: "succeeded"}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{OperationID: opName, Status: "unknown",
				Reason: "gke setAddons operation still running at poll timeout — reconcile via operations.get"}
		}
		time.Sleep(d.PollInterval)
	}
}

// createGKEAddon ENABLES the addon flag on its operand cluster, four-valued
// throughout. The cluster is an operand (D26): if it does not exist the create
// is a preflight refusal (never toggle an addon on a nonexistent cluster); if it
// is unreadable the outcome is unknown. An already-enabled addon is an idempotent
// success (no mutation).
func (d *Driver) createGKEAddon(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildGKEAddon(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := gkeAddonProviderID(d.Project, plan.Location, plan.ClusterName, plan.AddonName)

	doc, found, rerr := d.getGKEAddonCluster(d.Project, plan.Location, plan.ClusterName)
	if rerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "pre-create cluster read gave no answer — reconcile before toggling the addon: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("cluster %q not found in %s — the addon's operand cluster must exist; refusing to toggle an addon on a nonexistent cluster",
				plan.ClusterName, plan.Location)}
	}
	if plan.Spec.readState(doc.AddonsConfig) == addonOn {
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // idempotent — already enabled
	}

	opName, st, body, err := d.setAddon(d.Project, plan.Location, plan.ClusterName, plan.Spec, true)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("setAddons outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK && opName != "":
		// enabling — poll below
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "setAddons response carried no operation — reconcile"}
	case st == http.StatusNotFound:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("cluster %q vanished before setAddons — cannot enable the addon", plan.ClusterName)}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("setAddons HTTP %d (server error — may have landed): %s", st, mutDetail(body))}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("setAddons HTTP %d: %s", st, mutDetail(body))}
	}
	res := d.pollGKEAddonOperation(d.Project, plan.Location, opName)
	if res.Status == "succeeded" || res.ProviderID == "" {
		res.ProviderID = pid
	}
	return res
}

// observeGKEAddon reverse-maps the addon flag to capability.cluster.addon. The
// honest divergence from eks-addon: addon.version is NEVER emitted — GKE does not
// version addons independently, so it is reported as a diagnostic, never a
// fabricated value. An unreadable cluster is an error (unknown); a missing
// cluster, or a disabled/absent flag, is "nothing to observe".
func (d *Driver) observeGKEAddon(capability, providerID string) ([]provider.Observation, []string, error) {
	project, location, cluster, addon, err := splitGKEAddonProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getGKEAddonCluster(project, location, cluster)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"cluster not found — bound resource is gone (will re-create)"}, nil
	}
	spec := gkeAddonRegistry[addon] // validated by splitGKEAddonProviderID
	switch spec.readState(doc.AddonsConfig) {
	case addonUnreadable:
		// D801/D306: a config block we cannot parse is not an addon that is off. Refuse
		// to answer rather than report the estate as quieter than it is.
		return nil, nil, fmt.Errorf("addon %q on cluster %q: the addonsConfig block is "+
			"present but not readable — refusing to report it as disabled", addon, cluster)
	case addonAbsent, addonOff:
		return []provider.Observation{
			// D802: an addon that is OFF (or was never configured) is a bound subject
			// that is not there. Saying nothing left posture reading managed-ok from the
			// last observation taken while it was still on.
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{fmt.Sprintf("addon %q is not enabled on cluster %q — bound resource is gone (will re-create)", addon, cluster)}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: location, Derivation: "measured"},
		{Path: "addon.name", Value: addon, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	diags := []string{
		"addon.version not observed — GKE addon versions track the cluster version, " +
			"not independently observable (managed-by-cluster)",
	}
	return obs, diags, nil
}

// updateGKEAddon: GKE addons have NO in-place, per-addon patchable attribute
// (addon.name is identity; addon.version is unsupported — GKE does not version
// addons independently; enable/disable is create/delete). classifyGKEAddonChange
// returns nothing mutable, so a reviewed plan never routes a legitimate change
// here — but it refuses honestly rather than silently no-op.
func (d *Driver) updateGKEAddon(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	if _, _, _, _, err := splitGKEAddonProviderID(providerID); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	for _, path := range changes {
		return provider.CreateResult{Status: "failed",
			Reason: "no in-place GKE addon mapping for " + path +
				" — a GKE addon is a cluster flag (enable=create, disable=delete); there is nothing to patch"}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// deleteGKEAddon DISABLES the addon flag, four-valued. Idempotent on a
// gone/already-disabled addon; a transport/5xx is unknown WITH the pid
// (reconcile), never a claimed success.
func (d *Driver) deleteGKEAddon(capability, environment, providerID string) provider.CreateResult {
	project, location, cluster, addon, err := splitGKEAddonProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	spec := gkeAddonRegistry[addon]
	doc, found, rerr := d.getGKEAddonCluster(project, location, cluster)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete cluster read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // cluster gone — the flag is gone with it
	}
	switch spec.readState(doc.AddonsConfig) {
	case addonOff, addonAbsent:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // already off — idempotent
	case addonUnreadable:
		// D801: this used to be folded into "never enabled — idempotent", so a delete
		// answered SUCCEEDED about a control whose state nobody could read.
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "the addonsConfig block for " + addon + " is present but not readable — " +
				"cannot tell whether the addon is on, and will not report a removal that " +
				"may not have happened"}
	}

	opName, st, body, e := d.setAddon(project, location, cluster, spec, false)
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("setAddons(disable) outcome unknown: %v", e)}
	case st == http.StatusOK && opName != "":
		// disabling — poll below
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "setAddons(disable) response carried no operation — reconcile"}
	case st == http.StatusNotFound:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // gone
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("setAddons(disable) HTTP %d (server error) — reconcile", st)}
	default:
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("setAddons(disable) HTTP %d: %s", st, mutDetail(body))}
	}
	res := d.pollGKEAddonOperation(project, location, opName)
	if res.Status == "succeeded" || res.ProviderID == "" {
		res.ProviderID = providerID
	}
	return res
}

// discoverGKEAddon enumerates every ENABLED addon flag across every cluster in
// the location as capability.cluster.addon (a disabled flag is not a resource).
// The aggregated list (locations/-) spans regions; region, when given, filters
// on the cluster's own location. Reuses observeGKEAddon for the reverse map.
func (d *Driver) discoverGKEAddon(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.call("GET", fmt.Sprintf("%s/projects/%s/locations/-/clusters", d.gkeAddonBase(), d.Project), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("container clusters.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("container clusters.list: HTTP %d", st)
	}
	var resp struct {
		Clusters []gkeAddonClusterDoc `json:"clusters"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil, nil, readBody("clusters.list", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, c := range resp.Clusters {
		if c.Name == "" || c.Location == "" {
			continue
		}
		if region != "" && c.Location != region {
			continue // another location — not this sweep
		}
		for name, spec := range gkeAddonRegistry {
			switch spec.readState(c.AddonsConfig) {
			case addonUnreadable:
				// D801/D513: an unreadable block is neither reported nor claimed absent.
				diags = append(diags, c.Name+"/"+name+": the addonsConfig block is present "+
					"but not readable — the addon is neither reported nor called absent")
				continue
			case addonAbsent, addonOff:
				continue
			}
			pid := gkeAddonProviderID(d.Project, c.Location, c.Name, name)
			obs, odiags, oerr := d.observeGKEAddon("", pid)
			if oerr != nil {
				diags = append(diags, c.Name+"/"+name+": "+oerr.Error())
				continue
			}
			diags = append(diags, odiags...)
			out = append(out, provider.Discovered{
				ProviderID: pid, ResourceType: "capability.cluster.addon", Observations: provider.WithoutAbsence(obs)})
		}
	}
	return out, diags, nil
}
