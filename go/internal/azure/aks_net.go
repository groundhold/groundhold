// Azure Kubernetes Service network shell (D76 wave-3 parity): the ARM half of the
// Azure capability.cluster.kubernetes driver. AKS speaks ARM at
// Microsoft.ContainerService/managedClusters; create/update/delete are ASYNC (LRO),
// polled via provisioningState on the resource. The deterministic cluster name means
// the providerId is knowable BEFORE the PUT response, so a lost/garbled outcome (D29)
// always carries the handle. Ownership is ARM tags; foreign clusters are refused. The
// four-valued PARTIAL-composite crux (D29/D87): a PUT that reaches provisioningState
// Succeeded on the control plane while an agent pool is Failed, or a PUT that lands a
// cluster object in Failed, is `unknown` WITH the pid — the cluster exists to
// reconcile, never a bare "failed" that hides it and never a silent success.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/perr"
	"groundhold/internal/provider"
)

const aksAPIVersion = "2024-05-01"

// aksProviderID is service-PREFIXED (D76): the token qualifies the identity so a
// forged/stale binding cannot route a Cosmos/Redis id into container-service paths.
func aksProviderID(sub, rg, name string) string {
	return "aks:" + sub + ":" + rg + ":" + name
}

// splitAKSProviderID validates every component BEFORE it is interpolated into an ARM
// path (the D73 confused-deputy boundary). The service token is matched by exact
// string, never interpolated.
func splitAKSProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "aks" {
		return "", "", "", fmt.Errorf("providerId %q is not aks:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || !aksNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) aksPath(name string) string {
	return "Microsoft.ContainerService/managedClusters/" + name
}

// aksDoc is the projection of a managed cluster this driver governs. Overall +
// per-agent-pool provisioningState drive the create/health polls; Tags drive the
// ownership gate; the config fields reverse-map to the governed capability attributes.
type aksDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState        string `json:"provisioningState"`
		KubernetesVersion        string `json:"kubernetesVersion"`
		CurrentKubernetesVersion string `json:"currentKubernetesVersion"`
		AgentPoolProfiles        []struct {
			Name              string   `json:"name"`
			ProvisioningState string   `json:"provisioningState"`
			AvailabilityZones []string `json:"availabilityZones"`
		} `json:"agentPoolProfiles"`
		APIServerAccessProfile struct {
			EnablePrivateCluster *bool    `json:"enablePrivateCluster"`
			AuthorizedIPRanges   []string `json:"authorizedIPRanges"`
		} `json:"apiServerAccessProfile"`
		SecurityProfile struct {
			AzureKeyVaultKms struct {
				Enabled bool `json:"enabled"`
			} `json:"azureKeyVaultKms"`
		} `json:"securityProfile"`
	} `json:"properties"`
}

// getAKS resolves the cluster our providerId identifies, returning the raw body too
// (updateAKS read-modify-writes the full resource — an AKS PUT is create-or-update).
// (doc, raw, found, err): a 404 is found=false with a nil error (a vanished cluster,
// not a failure); a transport error or any other non-200 returns a named read error
// (unknown — never a fabricated absence).
func (d *Driver) getAKS(rg, name string) (aksDoc, []byte, bool, error) {
	const op = "getAKS.get"
	url, err := d.armURL(rg, d.aksPath(name), aksAPIVersion)
	if err != nil {
		return aksDoc{}, nil, false, &armReadError{Op: op, Cause: "scope", Detail: err.Error()}
	}
	st, resp, err := d.armGet(url)
	if err != nil {
		return aksDoc{}, nil, false, armTransport(op, err)
	}
	if st == http.StatusNotFound {
		return aksDoc{}, nil, false, nil
	}
	if st != http.StatusOK {
		return aksDoc{}, nil, false, armHTTP(op, st, resp)
	}
	var doc aksDoc
	if json.Unmarshal(resp, &doc) != nil {
		return aksDoc{}, nil, false, armBody(op, st)
	}
	return doc, resp, true, nil
}

// aksOwned: the ownership gate — ARM tags carry groundhold's marker, sanitized
// identically on write and read.
func aksOwned(doc aksDoc, capability, environment string) bool {
	return doc.Tags["groundhold-capability"] == sanitizeAzTag(capability) &&
		doc.Tags["groundhold-environment"] == sanitizeAzTag(environment)
}

// aksHealthy: the composite is fully up only when the control plane is Succeeded AND
// every agent pool is Succeeded. A control plane that reaches Succeeded with a Failed
// agent pool is a partial composite (the crux) — the caller reports unknown.
func aksHealthy(doc aksDoc) bool {
	if doc.Properties.ProvisioningState != "Succeeded" {
		return false
	}
	for _, ap := range doc.Properties.AgentPoolProfiles {
		if ap.ProvisioningState != "" && ap.ProvisioningState != "Succeeded" {
			return false
		}
	}
	return true
}

// createAKS provisions the composite (D26) — the CLUSTER + one system agent pool —
// in ONE managedClusters PUT (an LRO). Ownership-guarded: refuse a foreign cluster at
// our deterministic name; an ours-already healthy cluster is the idempotent success,
// an ours-but-unhealthy cluster is re-PUT to converge. Four-valued throughout
// (D29/D87): once the name is knowable the pid rides every ambiguous outcome, and a
// cluster that STANDS in Failed, or a control plane up with a failed agent pool, is
// unknown WITH the pid, never a bare "failed" and never a silent success.
func (d *Driver) createAKS(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAKS(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure aks requires implementation.resource_group (a valid Azure resource group)"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := aksProviderID(d.Subscription, rg, plan.Name)

	// ownership pre-read: refuse a foreign cluster; adopt our own (idempotent success
	// when healthy, re-PUT to converge when half-provisioned).
	doc, _, found, rerr := d.getAKS(rg, plan.Name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "pre-create ownership read gave no answer — reconcile before provisioning: " + rerr.Error()}
	}
	if found {
		if !aksOwned(doc, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a cluster with this name exists and is not ours (tags do not match) — refusing to adopt it"}
		}
		if aksHealthy(doc) {
			return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // ours, already up
		}
		// ours but half-provisioned — fall through to a re-PUT (idempotent converge).
	}

	// D261: an explicit adopt name (implementation.clusterName) that resolves to NO
	// cluster must NEVER create one — an AKS PUT is create-OR-UPDATE (upsert), so falling
	// through to it at an adoption name would CREATE the duplicate (the exact Acme bug: a
	// custom-named brownfield cluster never matched a deterministic name, so a SECOND
	// cluster was stood up). Refuse BEFORE the PUT. (An ours-but-half-provisioned cluster
	// was found above and legitimately falls through to converge — this fires only when
	// the named cluster is genuinely absent.)
	if !found && plan.AdoptByName {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("implementation.clusterName=%q names a cluster to adopt, but no such cluster "+
				"exists in %s — refusing to create one at an adoption name (run `groundhold discover "+
				"--provider azure --project %s --region <region> %s` then `adopt`, or check "+
				"the name)", plan.Name, rg, d.Subscription, perr.AtNow)}
	}

	url, _ := d.armURL(rg, d.aksPath(plan.Name), aksAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	st, resp, err := d.doARM("PUT", url, body)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("managedClusters PUT outcome unknown (may have landed): %v", err)}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("managedClusters PUT HTTP %d (server error — may have landed) — reconcile", st)}
	case st < 200 || st >= 300:
		return provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("managedClusters PUT HTTP %d: %s", st, mutDetailAz(resp))}
	}

	// poll provisioningState to a terminal outcome, then the partial-composite guard.
	deadline := d.Now().Add(d.aksLROTimeout())
	for {
		cur, _, f, r := d.getAKS(rg, plan.Name)
		if r == nil && f {
			switch cur.Properties.ProvisioningState {
			case "Succeeded":
				if !aksHealthy(cur) {
					return provider.CreateResult{ProviderID: pid, Status: "unknown",
						Reason: "cluster control plane Succeeded but an agent pool is not Succeeded — reconcile the half-provisioned cluster (the cluster exists)"}
				}
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			case "Failed", "Canceled":
				// the cluster object STANDS in Failed — a partial composite, unknown WITH
				// the pid (never a bare "failed" that implies nothing was created).
				return provider.CreateResult{ProviderID: pid, Status: "unknown",
					Reason: "cluster entered provisioningState " + cur.Properties.ProvisioningState +
						" but the cluster object exists — reconcile the half-provisioned cluster (the cluster exists)"}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "cluster still provisioning at poll timeout — reconcile via managedClusters GET"}
		}
		time.Sleep(d.PollInterval)
	}
}

// observeAKS reverse-maps a live cluster to capability.cluster.kubernetes. Every
// governed attribute is derived from ONE managedClusters GET — availability.class is
// the zone spread of the system agent pool (>1 zone -> regional).
func (d *Driver) observeAKS(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitAKSProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	doc, _, found, rerr := d.getAKS(rg, name)
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

	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region",
			Value: azRegion(doc.Location), Derivation: "measured"})
	}

	// cluster.version: reduce the running version to its governed MINOR version.
	ver := doc.Properties.CurrentKubernetesVersion
	if ver == "" {
		ver = doc.Properties.KubernetesVersion
	}
	if mv := aksMinorVersion(ver); mv != "" {
		obs = append(obs, provider.Observation{Path: "cluster.version", Value: mv, Derivation: "measured"})
	} else {
		diags = append(diags, "cluster.version not derivable (no readable kubernetesVersion) — omitted rather than fabricated")
	}

	// network.apiExposure: private cluster -> private; public API server restricted by
	// authorized IP ranges -> mixed; otherwise public.
	exposure := "public"
	ap := doc.Properties.APIServerAccessProfile
	switch {
	case ap.EnablePrivateCluster != nil && *ap.EnablePrivateCluster:
		exposure = "private"
	case len(ap.AuthorizedIPRanges) > 0:
		exposure = "mixed"
	}
	obs = append(obs, provider.Observation{Path: "network.apiExposure", Value: exposure, Derivation: "measured"})

	// encryption.secrets: KMS etcd encryption via azureKeyVaultKms.
	obs = append(obs, provider.Observation{Path: "encryption.secrets",
		Value: doc.Properties.SecurityProfile.AzureKeyVaultKms.Enabled, Derivation: "measured"})

	// availability.class: the system agent pool's zone spread IS the topology.
	if class, ok := aksAvailabilityClass(doc); ok {
		obs = append(obs, provider.Observation{Path: "availability.class", Value: class, Derivation: "measured"})
	} else {
		diags = append(diags, "availability.class not derivable (no readable agent pool zones) — omitted rather than fabricated")
	}
	return obs, diags, nil
}

// aksAvailabilityClass derives availability.class from the system pool's zone spread:
// >1 zone -> regional, ==1 or 0 -> zonal. ok=false (the caller omits) when there is no
// readable agent pool — an honest omission, never a fabricated class.
func aksAvailabilityClass(doc aksDoc) (string, bool) {
	if len(doc.Properties.AgentPoolProfiles) == 0 {
		return "", false
	}
	if len(doc.Properties.AgentPoolProfiles[0].AvailabilityZones) > 1 {
		return "regional", true
	}
	return "zonal", true
}

// updateAKS patches a bound cluster in place via a read-modify-write of the full
// managedClusters resource (an AKS PUT is create-or-update; RMW preserves the
// operator's other properties): cluster.version -> kubernetesVersion,
// network.apiExposure -> authorizedIPRanges (public<->mixed only; the enablePrivateCluster
// toggle is immutable and refused honestly). Ownership tags gate the patch;
// four-valued throughout (an ambiguous outcome is unknown WITH the pid).
func (d *Driver) updateAKS(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	sub, rg, name, err := splitAKSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	doc, raw, found, rerr := d.getAKS(rg, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update ownership read gave no answer — reconcile before patching: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "cluster no longer exists — cannot update"}
	}
	if !aksOwned(doc, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "cluster tags do not match — refusing to patch a resource that is not ours"}
	}

	// parse the full resource for the read-modify-write; strip read-only fields ARM
	// rejects on a PUT.
	var res map[string]any
	if json.Unmarshal(raw, &res) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read unparseable — reconcile"}
	}
	delete(res, "id")
	delete(res, "systemData")
	delete(res, "sku")
	props, _ := res["properties"].(map[string]any)
	if props == nil {
		props = map[string]any{}
		res["properties"] = props
	}

	for _, path := range changes {
		switch path {
		case "cluster.version":
			ver, _ := attrs["cluster.version"].(string)
			if strings.TrimSpace(ver) == "" {
				return provider.CreateResult{Status: "failed", Reason: "cluster.version must be a non-empty string"}
			}
			props["kubernetesVersion"] = strings.TrimSpace(ver)
		case "network.apiExposure":
			exp, _ := attrs["network.apiExposure"].(string)
			ap, uerr := aksExposureUpdate(exp, toStringSlice(impl["authorizedIPRanges"]),
				doc.Properties.APIServerAccessProfile.EnablePrivateCluster)
			if uerr != nil {
				return provider.CreateResult{Status: "failed", Reason: uerr.Error()}
			}
			props["apiServerAccessProfile"] = ap
		default:
			// ClassifyChange gates this (unsupported/immutable), so a reviewed plan never
			// reaches here — but refuse honestly rather than silently no-op.
			return provider.CreateResult{Status: "failed", Reason: "no in-place AKS mapping for " + path}
		}
	}

	url, _ := d.armURL(rg, d.aksPath(name), aksAPIVersion)
	body, _ := json.Marshal(res)
	// D265: an AKS control-plane upgrade runs 20-40 min — poll against the generous
	// AKS LRO ceiling, not the 20-min generic PollTimeout (else a healthy slow upgrade
	// reports unknown; the D264 class on the AKS UPGRADE path specifically).
	if r := d.putAndPollT(url, body, providerID, "aks", d.aksLROTimeout()); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// aksExposureUpdate builds the apiServerAccessProfile for an apiExposure transition.
// The enablePrivateCluster flag is IMMUTABLE on AKS: a public<->private conversion is
// a replacement, refused honestly here (never a silent no-op). Only the
// authorized-IP-range set (public<->mixed) is patched in place.
func aksExposureUpdate(exposure string, ranges []string, currentPrivate *bool) (map[string]any, error) {
	isPrivate := currentPrivate != nil && *currentPrivate
	switch exposure {
	case "public":
		if isPrivate {
			return nil, fmt.Errorf(
				"network.apiExposure=public on a private AKS cluster requires toggling enablePrivateCluster, " +
					"which is immutable (a public<->private conversion is a replacement) — refusing")
		}
		return map[string]any{"enablePrivateCluster": false, "authorizedIPRanges": []any{}}, nil
	case "mixed":
		if isPrivate {
			return nil, fmt.Errorf(
				"network.apiExposure=mixed on a private AKS cluster requires toggling enablePrivateCluster, " +
					"which is immutable (a private->public conversion is a replacement) — refusing")
		}
		if len(ranges) == 0 {
			return nil, fmt.Errorf(
				"network.apiExposure=mixed requires implementation.authorizedIPRanges (>=1 CIDR) to restrict the public API server")
		}
		rs := make([]any, 0, len(ranges))
		for _, r := range ranges {
			rs = append(rs, r)
		}
		return map[string]any{"enablePrivateCluster": false, "authorizedIPRanges": rs}, nil
	case "private":
		if !isPrivate {
			return nil, fmt.Errorf(
				"network.apiExposure=private on a public AKS cluster requires toggling enablePrivateCluster, " +
					"which is immutable (a public->private conversion is a replacement) — refusing")
		}
		return map[string]any{"enablePrivateCluster": true}, nil
	}
	return nil, fmt.Errorf("network.apiExposure must be public|private|mixed")
}

// deleteAKS tears the composite down, ownership-guarded: pre-read the tags (refuse a
// foreign cluster), DELETE the cluster (AKS removes its agent pools with it), poll the
// LRO until the cluster is readably gone. Idempotent on already-gone (404); a
// transport/5xx or a poll timeout is unknown WITH the pid (reconcile), never a claimed
// success.
func (d *Driver) deleteAKS(capability, environment, providerID string) provider.CreateResult {
	_, rg, name, err := splitAKSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, _, found, rerr := d.getAKS(rg, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	if !aksOwned(doc, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "cluster tags do not match — refusing to delete a resource that is not ours"}
	}
	url, _ := d.armURL(rg, d.aksPath(name), aksAPIVersion)
	st, body, derr := d.doARM("DELETE", url, nil)
	switch {
	case derr != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", derr)}
	case st == http.StatusNotFound:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	case st < 200 || st >= 300:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetailAz(body))}
	}
	// poll until the cluster is readably gone (a still-Deleting cluster is not-yet-gone).
	deadline := d.Now().Add(d.aksLROTimeout())
	for {
		_, _, stillThere, r := d.getAKS(rg, name)
		if r == nil && !stillThere {
			return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "cluster still deleting at poll timeout — reconcile via managedClusters GET"}
		}
		time.Sleep(d.PollInterval)
	}
}

// discoverAKS enumerates the subscription's managed clusters (filtered to the region)
// as capability.cluster.kubernetes — so `discover --provider azure` surfaces an
// az/TF-stood cluster for adoption. Reuses observeAKS (aggregate list -> per-cluster
// reverse map).
func (d *Driver) discoverAKS(region string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.ContainerService/managedClusters?api-version=%s",
		d.BaseURL, d.Subscription, aksAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("managedClusters.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("managedClusters.list: HTTP %d", st)
	}
	var clusters struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &clusters) != nil {
		return nil, nil, &armReadError{Op: "managedClusters.list", Cause: "body", Status: st}
	}
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
		pid := aksProviderID(d.Subscription, rg, c.Name)
		obs, od, oerr := d.observeAKS("", pid)
		if oerr != nil {
			diags = append(diags, c.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range od {
			diags = append(diags, c.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID: pid, ResourceType: "capability.cluster.kubernetes", Observations: provider.WithoutAbsence(obs)})
	}
	return out, diags, nil
}
