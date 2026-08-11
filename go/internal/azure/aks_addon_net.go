// AKS cluster-addon network shell (D76 fala-3 parity): the ARM half of the Azure
// capability.cluster.addon driver. Every mutation is a managed-cluster PUT that
// toggles ONE entry in properties.addonProfiles — the addon is a FLAG, not a
// package, so create = enable it, delete = disable it, and there is NO in-place
// per-addon version patch (see aks_addon.go). Because ARM has no dedicated
// enable-addons sub-operation, the toggle is a READ-MODIFY-WRITE of the whole
// managedCluster (the same discipline `az aks enable-addons` follows and the
// claim_azure tag merge follows): GET the cluster, set the ONE profile, PUT the
// UNION back, so the operator's agentPoolProfiles / networkProfile / everything
// else survives (a partial PUT would clobber them). PUT is async, polled to
// properties.provisioningState == Succeeded; a lost response (D29) always carries
// the deterministic providerId. Ownership is STRUCTURAL: the addon has no marker
// of its own, so identity is the (cluster, canonical name) tuple, gated by the
// cluster being readable — never a tag match. D29/D87 four-valued throughout.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"groundhold/internal/provider"
)

// aksAddonProviderID is the pinned identity:
// aks-addon:<sub>:<rg>:<cluster>:<addonName>. The canonical addon name carries no
// ':' (registry keys are hyphenated), so the 5-way split is unambiguous.
func aksAddonProviderID(sub, rg, cluster, addon string) string {
	return "aks-addon:" + sub + ":" + rg + ":" + cluster + ":" + addon
}

func splitAKSAddonProviderID(providerID string) (sub, rg, cluster, addon string, err error) {
	parts := strings.SplitN(providerID, ":", 5)
	if len(parts) != 5 || parts[0] != "aks-addon" {
		return "", "", "", "", fmt.Errorf("providerId %q is not aks-addon:sub:rg:cluster:addon", providerID)
	}
	sub, rg, cluster, addon = parts[1], parts[2], parts[3], parts[4]
	if !subOK.MatchString(sub) {
		return "", "", "", "", fmt.Errorf("providerId subscription %q is invalid", sub)
	}
	if !rgOK.MatchString(rg) {
		return "", "", "", "", fmt.Errorf("providerId resource group %q is invalid", rg)
	}
	if !aksAddonClusterOK.MatchString(cluster) {
		return "", "", "", "", fmt.Errorf("providerId cluster %q is invalid", cluster)
	}
	if _, known := aksAddonRegistry[addon]; !known {
		return "", "", "", "", fmt.Errorf("providerId addon %q is not a known AKS addon", addon)
	}
	return sub, rg, cluster, addon, nil
}

// aksAddonClusterPath is the ARM provider path for a managed cluster. It is
// addon-specific (prefixed) so the parallel aks [cluster] author's own path
// helper never collides with this one.
func (d *Driver) aksAddonClusterPath(cluster string) string {
	return "Microsoft.ContainerService/managedClusters/" + cluster
}

// getAKSAddonCluster GETs the WHOLE managed cluster as a generic map — the shape
// a read-modify-write PUT needs (so the toggle preserves every other cluster
// field). (found, err) mirror the family: a 404 is found=false with a nil error
// (gone), a transport/other error names itself (unknown — never a fabricated
// absence).
func (d *Driver) getAKSAddonCluster(rg, cluster string) (map[string]any, bool, error) {
	var doc map[string]any
	found, err := d.armGetInto("managedClusters.get", rg,
		d.aksAddonClusterPath(cluster), aksAddonAPIVersion, &doc)
	if err != nil || !found {
		return nil, false, err
	}
	return doc, true, nil
}

// aksAddonProfiles extracts properties.addonProfiles from a cluster doc (nil-safe).
func aksAddonProfiles(cluster map[string]any) map[string]any {
	props, _ := cluster["properties"].(map[string]any)
	if props == nil {
		return nil
	}
	profiles, _ := props["addonProfiles"].(map[string]any)
	return profiles
}

// aksAddonReadEnabled reverse-reads one addon's enablement from a cluster doc.
// present=false means the profile is absent or malformed — the caller must NOT
// treat that as "disabled" blindly (parity with the GKE readEnabled discipline).
// aksAddonState is what the cluster's profile actually tells us about one addon. It
// replaces a pair of booleans whose false/false carried three different meanings at once
// (D801, and the same shape one cloud over on GKE).
type aksAddonState int

const (
	aksAddonAbsent     aksAddonState = iota // no profile — the addon is not configured
	aksAddonOn                              // configured and on
	aksAddonOff                             // configured and off
	aksAddonUnreadable                      // a profile we cannot interpret
)

func aksAddonReadState(cluster map[string]any, profileKey string) aksAddonState {
	raw, exists := aksAddonProfiles(cluster)[profileKey]
	if !exists {
		return aksAddonAbsent
	}
	profile, ok := raw.(map[string]any)
	if !ok {
		return aksAddonUnreadable
	}
	// ARM serializes false explicitly, so unlike GKE an absent flag is not a default
	// here — it is a profile shaped in a way this driver does not understand.
	v, ok := profile["enabled"].(bool)
	if !ok {
		return aksAddonUnreadable
	}
	if v {
		return aksAddonOn
	}
	return aksAddonOff
}

// setAKSAddonInCluster mutates the cluster doc IN PLACE, setting the ONE addon's
// enabled flag (+ optional config), creating the nested maps if absent. The rest
// of the doc is untouched — the PUT carries the union.
func setAKSAddonInCluster(cluster map[string]any, profileKey string, enable bool, config map[string]any) {
	props, _ := cluster["properties"].(map[string]any)
	if props == nil {
		props = map[string]any{}
		cluster["properties"] = props
	}
	profiles, _ := props["addonProfiles"].(map[string]any)
	if profiles == nil {
		profiles = map[string]any{}
		props["addonProfiles"] = profiles
	}
	entry := map[string]any{"enabled": enable}
	if enable && len(config) > 0 {
		entry["config"] = config
	}
	profiles[profileKey] = entry
	// provisioningState is read-only; drop it so the write body is clean and the
	// post-PUT poll observes the fresh transition (ARM ignores it either way).
	delete(props, "provisioningState")
}

// putAKSCluster issues the read-modify-write PUT and returns the raw wire outcome
// for the caller's four-valued mapping.
func (d *Driver) putAKSCluster(rg, cluster string, doc map[string]any) (int, []byte, error) {
	url, err := d.armURL(rg, d.aksAddonClusterPath(cluster), aksAddonAPIVersion)
	if err != nil {
		return 0, nil, err
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return 0, nil, err
	}
	return d.doARM("PUT", url, body)
}

// aksAddonClusterState reads properties.provisioningState from a fresh GET.
func (d *Driver) aksAddonClusterState(rg, cluster string) (string, bool) {
	doc, found, rerr := d.getAKSAddonCluster(rg, cluster)
	if rerr != nil || !found {
		return "", false
	}
	props, _ := doc["properties"].(map[string]any)
	state, _ := props["provisioningState"].(string)
	return state, true
}

// pollAKSAddonReady polls the managed cluster provisioningState to a terminal
// value. Succeeded is succeeded WITH the pid; Failed/Canceled is failed WITH the
// pid (the cluster exists — reconcile); the timeout is unknown WITH the pid.
func (d *Driver) pollAKSAddonReady(rg, cluster, pid string) provider.CreateResult {
	deadline := d.Now().Add(d.aksLROTimeout())
	for {
		state, ok := d.aksAddonClusterState(rg, cluster)
		if ok {
			switch state {
			case "Succeeded":
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			case "Failed", "Canceled":
				return provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "managed cluster entered provisioningState " + state + " — reconcile"}
			}
			// Updating/Creating -> keep polling
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "cluster still updating at poll timeout — reconcile via managedClusters.get"}
		}
		time.Sleep(d.PollInterval)
	}
}

// createAKSAddon ENABLES the addon in its operand cluster's addonProfiles,
// four-valued throughout. The cluster is an operand (D26): if it does not exist
// the create is a preflight refusal (never toggle an addon on a nonexistent
// cluster); if it is unreadable the outcome is unknown. An already-enabled addon
// is an idempotent success (no mutation).
func (d *Driver) createAKSAddon(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAKSAddon(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := aksAddonProviderID(d.Subscription, plan.ResourceGrp, plan.ClusterName, plan.AddonName)

	doc, found, rerr := d.getAKSAddonCluster(plan.ResourceGrp, plan.ClusterName)
	if rerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "pre-create cluster read gave no answer — reconcile before toggling the addon: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("cluster %q not found in resource group %s — the addon's operand cluster must exist; refusing to toggle an addon on a nonexistent cluster",
				plan.ClusterName, plan.ResourceGrp)}
	}
	if aksAddonReadState(doc, plan.ProfileKey) == aksAddonOn {
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // idempotent — already enabled
	}

	setAKSAddonInCluster(doc, plan.ProfileKey, true, plan.Config)
	st, body, err := d.putAKSCluster(plan.ResourceGrp, plan.ClusterName, doc)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("managedCluster PUT outcome unknown (may have landed): %v", err)}
	case st == http.StatusNotFound:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("cluster %q vanished before the addon PUT — cannot enable the addon", plan.ClusterName)}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("managedCluster PUT HTTP %d (server error — may have landed): %s", st, mutDetailAz(body))}
	case st < 200 || st >= 300:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("managedCluster PUT HTTP %d: %s", st, mutDetailAz(body))}
	}
	return d.pollAKSAddonReady(plan.ResourceGrp, plan.ClusterName, pid)
}

// observeAKSAddon reverse-maps the addon flag to capability.cluster.addon. The
// honest divergence from eks-addon: addon.version is NEVER emitted — AKS does not
// version addons independently, so it is reported as a diagnostic, never a
// fabricated value. An unreadable cluster is an error (unknown); a missing
// cluster, or a disabled/absent profile, is "nothing to observe".
func (d *Driver) observeAKSAddon(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, cluster, addon, err := splitAKSAddonProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	profileKey := aksAddonRegistry[addon] // validated by splitAKSAddonProviderID
	doc, found, rerr := d.getAKSAddonCluster(rg, cluster)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"cluster not found — bound resource is gone (will re-create)"}, nil
	}
	switch aksAddonReadState(doc, profileKey) {
	case aksAddonUnreadable:
		// D801/D306: a profile we cannot parse is not an addon that is off.
		return nil, nil, fmt.Errorf("addon %q on cluster %q: the addon profile is present "+
			"but not readable — refusing to report it as disabled", addon, cluster)
	case aksAddonAbsent, aksAddonOff:
		return []provider.Observation{
			// D802: same as the GKE twin — an addon that is off is a bound subject that
			// is not there, and silence let posture keep calling it managed.
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{fmt.Sprintf("addon %q is not enabled on cluster %q — bound resource is gone (will re-create)", addon, cluster)}, nil
	}
	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "addon.name", Value: addon, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if loc, _ := doc["location"].(string); loc != "" {
		obs = append([]provider.Observation{
			{Path: "location.region", Value: azRegion(loc), Derivation: "measured"},
		}, obs...)
	}
	diags := []string{
		"addon.version not observed — AKS addon versions track the cluster version, " +
			"not independently observable (managed-by-cluster)",
	}
	return obs, diags, nil
}

// updateAKSAddon: AKS addons have NO in-place, per-addon patchable attribute
// (addon.name is identity; addon.version is unsupported — AKS does not version
// addons independently; enable/disable is create/delete). classifyAKSAddonChange
// returns nothing mutable, so a reviewed plan never routes a legitimate change
// here — but it refuses honestly rather than silently no-op (parity with
// gke-addon; never a mutable-without-updater claim).
func (d *Driver) updateAKSAddon(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	if _, _, _, _, err := splitAKSAddonProviderID(providerID); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	for _, path := range changes {
		return provider.CreateResult{Status: "failed",
			Reason: "no in-place AKS addon mapping for " + path +
				" — an AKS addon is a cluster addonProfile (enable=create, disable=delete); there is nothing to patch"}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// deleteAKSAddon DISABLES the addon flag, four-valued. Idempotent on a
// gone/already-disabled addon; a transport/5xx is unknown WITH the pid
// (reconcile), never a claimed success.
func (d *Driver) deleteAKSAddon(capability, environment, providerID string) provider.CreateResult {
	_, rg, cluster, addon, err := splitAKSAddonProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	profileKey := aksAddonRegistry[addon]
	doc, found, rerr := d.getAKSAddonCluster(rg, cluster)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete cluster read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // cluster gone — the flag is gone with it
	}
	switch aksAddonReadState(doc, profileKey) {
	case aksAddonAbsent, aksAddonOff:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // already off — idempotent
	case aksAddonUnreadable:
		// D801: folded into "never enabled" before, so a delete claimed a removal of a
		// control whose state nobody could read.
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "the addon profile for " + addon + " is present but not readable — " +
				"cannot tell whether the addon is on, and will not report a removal that " +
				"may not have happened"}
	}

	setAKSAddonInCluster(doc, profileKey, false, nil)
	st, body, e := d.putAKSCluster(rg, cluster, doc)
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("managedCluster PUT(disable) outcome unknown: %v", e)}
	case st == http.StatusNotFound:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // gone
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("managedCluster PUT(disable) HTTP %d (server error) — reconcile", st)}
	case st < 200 || st >= 300:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("managedCluster PUT(disable) HTTP %d: %s", st, mutDetailAz(body))}
	}
	return d.pollAKSAddonReady(rg, cluster, providerID)
}

// discoverAKSAddon enumerates every ENABLED addonProfile across every managed
// cluster in the region as capability.cluster.addon (a disabled/absent profile is
// not a resource; an addonProfiles key we do not map back to a canonical name is
// skipped honestly). Reuses observeAKSAddon for the reverse map.
func (d *Driver) discoverAKSAddon(region string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.ContainerService/managedClusters?api-version=%s",
		d.BaseURL, d.Subscription, aksAddonAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("managedClusters.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("managedClusters.list: HTTP %d", st)
	}
	var clusters struct {
		Value []struct {
			ID       string         `json:"id"`
			Name     string         `json:"name"`
			Location string         `json:"location"`
			Props    map[string]any `json:"properties"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &clusters) != nil {
		return nil, nil, &armReadError{Op: "managedClusters.list", Cause: "body", Status: st}
	}

	// stable canonical order for deterministic output
	canon := make([]string, 0, len(aksAddonRegistry))
	for name := range aksAddonRegistry {
		canon = append(canon, name)
	}
	sort.Strings(canon)

	want := azRegion(region)
	var out []provider.Discovered
	var diags []string
	for _, c := range clusters.Value {
		if azRegion(c.Location) != want {
			continue // another region — not this sweep
		}
		rg := resourceGroupOf(c.ID)
		if rg == "" {
			diags = append(diags, c.Name+": resource group unparseable from id")
			continue
		}
		item := map[string]any{"properties": c.Props}
		for _, name := range canon {
			key := aksAddonRegistry[name]
			switch aksAddonReadState(item, key) {
			case aksAddonUnreadable:
				diags = append(diags, "addon profile "+key+" is present but not readable — "+
					"the addon is neither reported nor called absent")
				continue
			case aksAddonAbsent, aksAddonOff:
				continue
			}
			pid := aksAddonProviderID(d.Subscription, rg, c.Name, name)
			obs, odiags, oerr := d.observeAKSAddon("", pid)
			if oerr != nil {
				diags = append(diags, c.Name+"/"+name+": "+oerr.Error())
				continue
			}
			for _, dg := range odiags {
				diags = append(diags, c.Name+"/"+name+": "+dg)
			}
			out = append(out, provider.Discovered{
				ProviderID: pid, ResourceType: "capability.cluster.addon", Observations: provider.WithoutAbsence(obs)})
		}
	}
	return out, diags, nil
}
