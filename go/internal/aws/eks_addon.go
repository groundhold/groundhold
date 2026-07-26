// EKS managed-addon driver (D149): the AWS half of capability.cluster.addon — a
// managed EKS addon (vpc-cni, coredns, kube-proxy, aws-ebs-csi-driver,
// eks-pod-identity-agent) governed as a sub-resource UNDER a cluster. The cluster
// is an OPERAND (implementation.clusterName, D26), never provisioned here; the
// addon.name identifies which managed addon and addon.version drives the in-place
// version bump. Speaks the EKS REST-JSON API at eks.<region>.amazonaws.com (SigV4
// service "eks") via the shared eksDo plumbing. Four-valued throughout (D29/D87):
// an ambiguous outcome (transport / 5xx / already-exists) is unknown WITH the
// providerId; a foreign addon (tags do not match) is refused; ownership tags gate
// every mutation. D53: never read a secret.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

// eksAddonProviderID is the pinned identity: eks-addon:<region>:<cluster>/<addonName>.
func eksAddonProviderID(region, cluster, addon string) string {
	return "eks-addon:" + region + ":" + cluster + "/" + addon
}

func splitEKSAddonProviderID(providerID string) (region, cluster, addon string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "eks-addon" {
		return "", "", "", fmt.Errorf("providerId %q is not eks-addon:region:cluster/addon", providerID)
	}
	region = parts[1]
	if !regionOK.MatchString(region) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", region)
	}
	ca := strings.SplitN(parts[2], "/", 2)
	if len(ca) != 2 || ca[0] == "" || ca[1] == "" {
		return "", "", "", fmt.Errorf("providerId %q is missing cluster/addon", providerID)
	}
	return region, ca[0], ca[1], nil
}

// EKSAddonPlan is the attribute+operand-derived shape a create assembles. The
// SHAPE (addon.name, addon.version) is driven by CAPABILITY attributes; the
// cluster and the optional service role are OPERATOR operands (implementation:
// block, D26) — separate capabilities, never provisioned by this driver.
type EKSAddonPlan struct {
	ClusterName    string // operand (required)
	AddonName      string // capability (required)
	AddonVersion   string // capability (required)
	ServiceRoleArn string // operand (optional — for addons that assume a role)
}

// BuildEKSAddon maps capability.cluster.addon attributes + implementation operands
// to a plan, or REFUSES. Every error is a preflight refusal (never a half-build):
// an unmapped attribute, or a missing required attribute/operand, is refused here,
// before the first EKS mutation (invariant #4, D26). generation is unused (the
// addon identity is the name, not a hashed discriminator) but kept for a uniform
// Build signature across the driver family.
func BuildEKSAddon(environment, capability string,
	attrs, impl map[string]any, generation int) (EKSAddonPlan, error) {
	p := EKSAddonPlan{}
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "addon.name":
			v, ok := raw.(string)
			if !ok || strings.TrimSpace(v) == "" {
				return EKSAddonPlan{}, fmt.Errorf("addon.name must be a non-empty string (e.g. \"aws-ebs-csi-driver\")")
			}
			p.AddonName = strings.TrimSpace(v)
		case "addon.version":
			v, ok := raw.(string)
			if !ok || strings.TrimSpace(v) == "" {
				return EKSAddonPlan{}, fmt.Errorf("addon.version must be a non-empty string (e.g. \"v1.29.0-eksbuild.1\")")
			}
			p.AddonVersion = strings.TrimSpace(v)
		case "service.managed":
			if raw != true {
				return EKSAddonPlan{}, fmt.Errorf("service.managed=false cannot be honored by EKS (a managed addon IS managed by construction)")
			}
		case "location.region":
			// location.region scopes the create (resolved by the dispatch, not here);
			// cost.monthly is a projection — neither is a build input.
		default:
			return EKSAddonPlan{}, fmt.Errorf(
				"attribute %s has no EKS addon mapping — refusing rather than silently dropping it "+
					"(the cluster.addon vocab governs addon.name + addon.version)", path)
		}
	}
	if p.AddonName == "" {
		return EKSAddonPlan{}, fmt.Errorf("addon.name is required — refusing to guess which managed addon to install")
	}
	if p.AddonVersion == "" {
		return EKSAddonPlan{}, fmt.Errorf("addon.version is required — refusing to let AWS pick a default addon version")
	}

	// --- OPERATOR operands (implementation: block, D26) ---
	if p.ClusterName = strings.TrimSpace(implString(impl, "clusterName")); p.ClusterName == "" {
		return EKSAddonPlan{}, fmt.Errorf("implementation.clusterName is required (the EKS cluster the addon installs into — a separate capability/operand)")
	}
	// serviceAccountRoleArn is OPTIONAL — only addons that assume an IAM role
	// (e.g. aws-ebs-csi-driver) supply one. It is a REFERENCE (an ARN), never key
	// material — safe to carry (D53).
	p.ServiceRoleArn = strings.TrimSpace(implString(impl, "serviceRoleArn"))
	return p, nil
}

// createBody is the CreateAddon request body: the addon name + version, the
// optional service-account role, and ownership tags. Cited: EKS CreateAddon.
func (p EKSAddonPlan) createBody(capability, environment string) []byte {
	body := map[string]any{
		"addonName":    p.AddonName,
		"addonVersion": p.AddonVersion,
		"tags": map[string]any{
			"groundhold-capability":  sanitizeTag(capability),
			"groundhold-environment": sanitizeTag(environment),
		},
	}
	if p.ServiceRoleArn != "" {
		body["serviceAccountRoleArn"] = p.ServiceRoleArn
	}
	return []byte(jsonBody(body))
}

// eksAddon is the projection of DescribeAddon this driver governs. Status drives
// the create/update polls; Tags drive the ownership gate for every mutation.
type eksAddon struct {
	AddonName             string            `json:"addonName"`
	AddonVersion          string            `json:"addonVersion"`
	Status                string            `json:"status"`
	ServiceAccountRoleArn string            `json:"serviceAccountRoleArn"`
	Tags                  map[string]string `json:"tags"`
}

// describeEKSAddon resolves the addon our name identifies. (found, readable)
// mirror the cluster describe: a 404 is found=false+readable (gone), a
// transport/other error is readable=false (unknown — never a fabricated absence).
func (d *Driver) describeEKSAddon(region, cluster, addon string) (eksAddon, bool, error) {
	const op = "DescribeAddon"
	st, resp, err := d.eksGet(region, "/clusters/"+cluster+"/addons/"+addon)
	if err != nil {
		return eksAddon{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return eksAddon{}, false, nil
	}
	if st != http.StatusOK {
		return eksAddon{}, false, readHTTP(op, st, eksErr(resp))
	}
	var out struct {
		Addon eksAddon `json:"addon"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return eksAddon{}, false, readBody(op, st)
	}
	return out.Addon, true, nil
}

// createEKSAddon installs a managed addon, four-valued throughout. Ownership
// pre-read refuses a foreign addon already at our name; an ours-already addon is
// polled to ACTIVE (idempotent repair). Transport/5xx/already-exists are unknown
// WITH the pid (the addon may have landed); CREATE_FAILED is a failed WITH the pid
// (the addon object exists — reconcile).
func (d *Driver) createEKSAddon(region, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildEKSAddon(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := eksAddonProviderID(region, plan.ClusterName, plan.AddonName)

	a, found, rerr := d.describeEKSAddon(region, plan.ClusterName, plan.AddonName)
	if rerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "addon ownership pre-read gave no answer after retry — a persistent DescribeAddon failure : " + rerr.Error() +
				"(check the acting identity's eks:DescribeAddon permission; a transient throttle/5xx is retried) — reconcile"}
	}
	if found {
		if !groundholdTagsMatch(a.Tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "an addon with this name exists and is not ours (tags do not match) — refusing to adopt it"}
		}
		return d.pollEKSAddonActive(region, pid, plan.ClusterName, plan.AddonName)
	}

	st, body, err := d.eksDo("POST", region, "/clusters/"+plan.ClusterName+"/addons",
		plan.createBody(capability, environment))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateAddon outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK || st == http.StatusCreated:
		// creating — fall through to poll
	case st == http.StatusConflict:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "CreateAddon says the addon now exists — reconcile ownership"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateAddon HTTP %d (server error — may have landed): %s", st, eksErr(body))}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateAddon HTTP %d: %s", st, eksErr(body))}
	}
	return d.pollEKSAddonActive(region, pid, plan.ClusterName, plan.AddonName)
}

// pollEKSAddonActive polls DescribeAddon until ACTIVE (succeeded WITH the pid). A
// CREATE_FAILED / DEGRADED / UPDATE_FAILED addon is a failed WITH the pid (the
// addon object exists — reconcile); the poll timeout is unknown WITH the pid.
func (d *Driver) pollEKSAddonActive(region, pid, cluster, addon string) provider.CreateResult {
	deadline := d.Now().Add(d.eksLROTimeout())
	for {
		a, found, rerr := d.describeEKSAddon(region, cluster, addon)
		if rerr == nil && found {
			switch a.Status {
			case "ACTIVE":
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			case "CREATE_FAILED", "DEGRADED", "UPDATE_FAILED":
				return provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "addon entered " + a.Status + " — reconcile"}
			}
			// CREATING / UPDATING -> keep polling
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "addon still creating at poll timeout — reconcile via DescribeAddon"}
		}
		time.Sleep(d.PollInterval)
	}
}

// observeEKSAddon reverse-maps an addon to capability.cluster.addon. An unreadable
// addon is an error (unknown), never a fabricated absence; a 404 is "nothing to
// observe".
func (d *Driver) observeEKSAddon(capability, providerID string) ([]provider.Observation, []string, error) {
	region, cluster, addon, err := splitEKSAddonProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	a, found, rerr := d.describeEKSAddon(region, cluster, addon)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"addon not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "addon.name", Value: a.AddonName, Derivation: "measured"},
		{Path: "addon.version", Value: a.AddonVersion, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	return obs, nil, nil
}

// updateEKSAddon patches a bound addon in place: addon.version via UpdateAddon
// (async — polled to ACTIVE). Ownership tags gate the patch; four-valued
// throughout (an ambiguous outcome is unknown WITH the providerId).
func (d *Driver) updateEKSAddon(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, cluster, addon, err := splitEKSAddonProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	a, found, rerr := d.describeEKSAddon(region, cluster, addon)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update ownership read gave no answer — reconcile before patching: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "addon no longer exists — cannot update"}
	}
	if !groundholdTagsMatch(a.Tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "addon tags do not match — refusing to patch a resource that is not ours"}
	}

	for _, path := range changes {
		switch path {
		case "addon.version":
			ver, _ := attrs["addon.version"].(string)
			if strings.TrimSpace(ver) == "" {
				return provider.CreateResult{Status: "failed", Reason: "addon.version must be a non-empty string"}
			}
			reqBody := map[string]any{"addonVersion": strings.TrimSpace(ver)}
			if role := strings.TrimSpace(implString(impl, "serviceRoleArn")); role != "" {
				reqBody["serviceAccountRoleArn"] = role
			}
			jb, _ := json.Marshal(reqBody)
			st, resp, err := d.eksDo("POST", region, "/clusters/"+cluster+"/addons/"+addon+"/update", jb)
			switch {
			case err != nil:
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: fmt.Sprintf("UpdateAddon outcome unknown (may have landed): %v", err)}
			case st == http.StatusOK:
				// accepted — poll to ACTIVE below
			case st >= 500:
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: fmt.Sprintf("UpdateAddon HTTP %d (server error — may have landed): %s", st, eksErr(resp))}
			default:
				return provider.CreateResult{Status: "failed",
					Reason: fmt.Sprintf("UpdateAddon HTTP %d: %s", st, eksErr(resp))}
			}
			if res := d.pollEKSAddonActive(region, providerID, cluster, addon); res.Status != "succeeded" {
				return res
			}
		default:
			// ClassifyChange gates this (unsupported/immutable), so a reviewed plan
			// never reaches here — but refuse honestly rather than silently no-op.
			return provider.CreateResult{Status: "failed",
				Reason: "no in-place EKS addon mapping for " + path}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// deleteEKSAddon removes the addon, ownership-guarded. Idempotent on already-gone
// (404); a transport/5xx is unknown WITH the pid (reconcile), never a claimed
// success; a foreign addon is refused.
func (d *Driver) deleteEKSAddon(capability, environment, providerID string) provider.CreateResult {
	region, cluster, addon, err := splitEKSAddonProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	a, found, rerr := d.describeEKSAddon(region, cluster, addon)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	if !groundholdTagsMatch(a.Tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "addon tags do not match — refusing to delete a resource that is not ours"}
	}
	st, body, err := d.eksDo("DELETE", region, "/clusters/"+cluster+"/addons/"+addon, nil)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("DeleteAddon outcome unknown: %v", err)}
	case st == http.StatusNotFound:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	case st == http.StatusOK || st == http.StatusAccepted:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("DeleteAddon HTTP %d (server error) — reconcile", st)}
	default:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("DeleteAddon HTTP %d: %s", st, eksErr(body))}
	}
}

// classifyEKSAddonChange (D46): PURE. addon.version is mutable in place
// (UpdateAddon); addon.name is the identity (immutable — a different addon is a
// different resource); the rest are platform/projection (unsupported).
func classifyEKSAddonChange(path string) (string, string) {
	switch path {
	case "addon.version":
		return "mutable", "in-place via UpdateAddon (a managed addon version change)"
	case "addon.name":
		return "immutable", "the addon name is the identity — a different addon is a different resource, not an in-place patch"
	case "service.managed", "location.region":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no EKS addon in-place mapping for " + path
	}
}

// discoverEKSAddon enumerates every managed addon UNDER every cluster in the
// region as capability.cluster.addon (addons live under a cluster, so a
// region-level discover first lists the clusters, then ListAddons per cluster).
// Reuses observeEKSAddon for the reverse map.
func (d *Driver) discoverEKSAddon(region string) ([]provider.Discovered, []string, error) {
	st, resp, err := d.eksDo("GET", region, "/clusters", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("eks ListClusters: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("eks ListClusters: HTTP %d", st)
	}
	var cl struct {
		Clusters []string `json:"clusters"`
	}
	if json.Unmarshal(resp, &cl) != nil {
		return nil, nil, readBody("ListClusters", st)
	}
	var found []provider.Discovered
	var diags []string
	for _, cluster := range cl.Clusters {
		const addonsOp = "ListAddons"
		st, resp, err := d.eksDo("GET", region, "/clusters/"+cluster+"/addons", nil)
		if err != nil {
			diags = append(diags, cluster+": "+readTransport(addonsOp, err).Error()+" — skipped")
			continue
		}
		if st != http.StatusOK {
			diags = append(diags, cluster+": "+readHTTP(addonsOp, st, eksErr(resp)).Error()+" — skipped")
			continue
		}
		var al struct {
			Addons []string `json:"addons"`
		}
		if json.Unmarshal(resp, &al) != nil {
			diags = append(diags, cluster+": "+readBody(addonsOp, st).Error()+" — skipped")
			continue
		}
		for _, name := range al.Addons {
			pid := eksAddonProviderID(region, cluster, name)
			obs, od, oerr := d.observeEKSAddon("", pid)
			if oerr != nil {
				diags = append(diags, name+": "+oerr.Error())
				continue
			}
			diags = append(diags, od...)
			found = append(found, provider.Discovered{
				ProviderID: pid, ResourceType: "capability.cluster.addon", Observations: obs})
		}
	}
	return found, diags, nil
}
