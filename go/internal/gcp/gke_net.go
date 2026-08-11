// GKE network shell (D76, wave-3 parity): the bearer-signed REST half of the GCP
// capability.cluster.kubernetes driver. GKE speaks container.googleapis.com/v1 at
// projects/{p}/locations/{loc}/clusters; create/update/delete are ASYNC (LRO), polled
// via projects/{p}/locations/{loc}/operations/{op}. The deterministic cluster name
// means the providerId is knowable BEFORE the create response, so a lost/garbled
// outcome (D29) always carries the handle. Ownership is resourceLabels; foreign
// clusters are refused. The four-valued PARTIAL-composite crux (D29/D87): a
// CreateCluster LRO that fails while a cluster object stands, or a cluster that
// reaches RUNNING with an unhealthy node pool, is `unknown` WITH the pid — the
// control plane exists to reconcile, never a bare "failed" that hides it.
//
// NOTE (integration): the base-URL override rides a package var here because the
// Driver struct lives in the SHARED driver.go this slice does not edit. The
// integrated form adds a `GKEBaseURL string` field to Driver and switches gkeBase()
// to prefer it — reported as an integration snippet.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/perr"
	"groundhold/internal/provider"
)

const gkeBaseURL = "https://container.googleapis.com/v1"

// gkeBaseURLOverride points the container API at a stub in tests (see the package
// note above). Empty in production.
var gkeBaseURLOverride string

func (d *Driver) gkeBase() string {
	if gkeBaseURLOverride != "" {
		return gkeBaseURLOverride
	}
	return gkeBaseURL
}

// gkeProviderID is service-PREFIXED (D76): the token qualifies the identity so a
// forged/stale binding cannot route a Cloud SQL id into container paths. Never the
// slash-form REST name — that embeds '/', the char class D73's boundary keeps out
// of stored identities.
func gkeProviderID(project, location, cluster string) string {
	return "gke:" + project + ":" + location + ":" + cluster
}

// splitGKEProviderID validates every component BEFORE it is interpolated into a
// REST path (D73 confused-deputy boundary). The service token is matched by exact
// string, never interpolated. Location is a region OR a zone.
func splitGKEProviderID(providerID string) (project, location, cluster string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "gke" {
		return "", "", "", fmt.Errorf("providerId %q is not gke:project:location:cluster", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !gkeRegionOK.MatchString(parts[2]) && !gkeZoneOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId location %q is not a valid GCP region/zone", parts[2])
	}
	if !gkeNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId cluster %q is not a valid GKE cluster name", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) gkeClusterURL(project, location, cluster string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/clusters/%s",
		d.gkeBase(), project, location, cluster)
}

// gkeReadAttempts bounds the transient-retry budget for a single-shot GKE-family read.
const gkeReadAttempts = 4

// gcpGetRetry issues a call and RETRIES a bounded number of times on a TRANSIENT
// failure (transport error, 429 throttle, or 5xx) — the read layer's answer to the
// D260 class. Every GKE-family ownership pre-read is a single-shot read (clusters.get
// for the cluster + addon drivers, getIamPolicy for workload identity); WITHOUT retry
// a momentary throttle/503 turns into a fatal `unknown` that aborts the whole converge.
// A DEFINITIVE status returns at once: 2xx, 404 (a real absence), 403 or any other 4xx
// (a real permission/validation gap is NOT something to spin on). Only the transient
// class is retried, d.PollInterval apart (0 in tests). This never converts a genuine
// failure into a success — it only rides out the noise a live read is guaranteed to hit.
// It mirrors the AWS eksGet helper.
func (d *Driver) gcpGetRetry(method, url string, body map[string]any) (int, []byte, error) {
	var st int
	var resp []byte
	var err error
	for attempt := 0; attempt < gkeReadAttempts; attempt++ {
		st, resp, err = d.call(method, url, body)
		if err == nil && st != http.StatusTooManyRequests && st < 500 {
			return st, resp, err // definitive (2xx / 4xx incl. 403 / 404)
		}
		if attempt < gkeReadAttempts-1 {
			time.Sleep(d.PollInterval) // transient: transport error / 429 / 5xx
		}
	}
	return st, resp, err
}

// gkeLROTimeout is the poll deadline for GKE long-running operations. A configured
// GKELROTimeout wins; 0 falls back to the generic PollTimeout. Mirrors eksLROTimeout.
func (d *Driver) gkeLROTimeout() time.Duration {
	if d.GKELROTimeout > 0 {
		return d.GKELROTimeout
	}
	return d.PollTimeout
}

// LROTimeout is the public budget the provider.LROBudgeter interface reads: the
// generous GKE long-running-operation timeout (never the terse PollTimeout).
func (d *Driver) LROTimeout() time.Duration { return d.gkeLROTimeout() }

// gkeCluster is the projection of a cluster this driver governs. Status drives the
// create/health polls; ResourceLabels drive the ownership gate; the config fields
// reverse-map to the governed capability attributes.
type gkeCluster struct {
	Name                  string            `json:"name"`
	Status                string            `json:"status"` // PROVISIONING|RUNNING|RECONCILING|STOPPING|ERROR|DEGRADED
	Location              string            `json:"location"`
	CurrentMasterVersion  string            `json:"currentMasterVersion"`
	InitialClusterVersion string            `json:"initialClusterVersion"`
	ResourceLabels        map[string]string `json:"resourceLabels"`
	PrivateClusterConfig  struct {
		EnablePrivateNodes    bool `json:"enablePrivateNodes"`
		EnablePrivateEndpoint bool `json:"enablePrivateEndpoint"`
	} `json:"privateClusterConfig"`
	MasterAuthorizedNetworksConfig struct {
		Enabled bool `json:"enabled"`
	} `json:"masterAuthorizedNetworksConfig"`
	DatabaseEncryption struct {
		State   string `json:"state"` // ENCRYPTED | DECRYPTED
		KeyName string `json:"keyName"`
	} `json:"databaseEncryption"`
	NodePools []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"nodePools"`
}

// getGKE resolves the cluster our providerId identifies. Returns (cluster, found,
// readable): a 404 is found=false+readable (a vanished cluster, not an error); a
// transport error or any other non-200 is readable=false (unknown — never a
// fabricated absence).
func (d *Driver) getGKE(project, location, cluster string) (gkeCluster, bool, error) {
	const op = "gKE.get"
	st, body, err := d.gcpGetRetry("GET", d.gkeClusterURL(project, location, cluster), nil)
	if err != nil {
		return gkeCluster{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return gkeCluster{}, false, nil
	}
	if st != http.StatusOK {
		return gkeCluster{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var c gkeCluster
	if json.Unmarshal(body, &c) != nil {
		return gkeCluster{}, false, readBody(op, st)
	}
	return c, true, nil
}

// gkeOwned: the ownership gate — resourceLabels carry groundhold's marker, sanitized
// identically on write and read.
func gkeOwned(c gkeCluster, capability, environment string) bool {
	return c.ResourceLabels["groundhold-capability"] == sanitizeLabel(capability) &&
		c.ResourceLabels["groundhold-environment"] == sanitizeLabel(environment)
}

// gkeHealthy: the composite is fully up only when the control plane is RUNNING AND
// every node pool is RUNNING. A DEGRADED cluster, or a node pool in ERROR /
// RECONCILING, is a partial composite (the crux) — the caller reports unknown.
func gkeHealthy(c gkeCluster) bool {
	if c.Status != "RUNNING" {
		return false
	}
	for _, np := range c.NodePools {
		if np.Status != "" && np.Status != "RUNNING" {
			return false
		}
	}
	return true
}

// createGKE provisions the composite (D26) — the CLUSTER + one autoscaling NODE
// POOL — in ONE CreateCluster LRO. Ownership-guarded: refuse a foreign cluster at
// our deterministic name; an ours-already cluster is the idempotent repair path.
// Four-valued throughout (D29/D87): once the name is knowable the pid rides every
// ambiguous outcome, and a failed operation that leaves a cluster STANDING is
// unknown WITH the pid (a half-provisioned cluster to reconcile), never a bare
// "failed" and never a silent success.
func (d *Driver) createGKE(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildGKE(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := gkeProviderID(d.Project, plan.Location, plan.Name)

	// ownership pre-read: refuse a foreign cluster; adopt our own repair-in-place.
	c, found, rerr := d.getGKE(d.Project, plan.Location, plan.Name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "pre-create ownership read gave no answer — reconcile before provisioning: " + rerr.Error()}
	}
	if found {
		if !gkeOwned(c, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("a cluster with this name exists and is not ours (labels do not match) — "+
					"refusing to adopt it; to take over a foreign cluster run `groundhold discover "+
					"--provider gcp --project %s --region %s %s` then `adopt` (the gated "+
					"adoption flow), never a bare converge", d.Project, plan.Location, perr.AtNow)}
		}
		if gkeHealthy(c) {
			return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // ours, already up
		}
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "an ours-labeled cluster exists but is not yet RUNNING/healthy — reconcile the half-provisioned cluster"}
	}

	// ADOPT-BY-NAME (mirror AWS EKS D261): an explicit adopt name
	// (implementation.clusterName) that resolves to NO cluster must NEVER create one —
	// that is exactly the brownfield duplicate (the real cluster has a custom name; a
	// deterministic-name miss stood up a SECOND cluster). Refuse instead.
	if plan.AdoptByName {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("implementation.clusterName=%q names a cluster to adopt, but no such cluster "+
				"exists in %s — refusing to create one at an adoption name (check the name/location, or "+
				"run `groundhold discover --provider gcp --project %[3]s --region %[2]s %[4]s` then "+
				"`adopt` first)", plan.Name, plan.Location, d.Project, perr.AtNow)}
	}

	url := fmt.Sprintf("%s/projects/%s/locations/%s/clusters", d.gkeBase(), d.Project, plan.Location)
	st, body, err := d.call("POST", url, plan.createClusterBody(capability, environment))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateCluster outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK || st == http.StatusCreated:
		// LRO started — poll below
	case st == http.StatusConflict:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "CreateCluster says the name now exists — reconcile ownership"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateCluster HTTP %d (server error — may have landed): %s", st, mutDetail(body))}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateCluster HTTP %d: %s", st, mutDetail(body))}
	}

	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "CreateCluster response carried no operation — reconcile"}
	}
	res := d.pollGKEOperation(d.Project, plan.Location, op.Name)
	switch res.Status {
	case "succeeded":
		// partial-composite guard: the op is DONE, but confirm the cluster is
		// RUNNING with a healthy node pool before claiming success.
		c2, found2, readable2 := d.getGKE(d.Project, plan.Location, plan.Name)
		if readable2 == nil && found2 && !gkeHealthy(c2) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "CreateCluster operation is DONE but the cluster is not RUNNING / a node pool is unhealthy — reconcile the half-provisioned cluster"}
		}
		res.ProviderID = pid
	case "failed":
		// the LRO failed — but the cluster object may STAND in ERROR (a partial
		// composite). A standing cluster is unknown WITH the pid, never a bare
		// "failed" that implies nothing was created.
		_, found2, readable2 := d.getGKE(d.Project, plan.Location, plan.Name)
		if readable2 == nil && found2 {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "CreateCluster operation failed but a cluster object exists — reconcile the half-provisioned cluster (the cluster exists)"}
		}
		// truly nothing stands — the clean failure the op reported.
	default: // unknown / timeout
		if res.ProviderID == "" {
			res.ProviderID = pid
		}
	}
	return res
}

// pollGKEOperation polls a container LRO to DONE. A DONE op carrying an error (a
// google.rpc.Status object, or a non-empty statusMessage) is a failure; a lost
// response is not consulted for a verdict; the timeout is unknown WITH the op id.
func (d *Driver) pollGKEOperation(project, location, opName string) provider.CreateResult {
	deadline := d.Now().Add(d.gkeLROTimeout())
	opURL := fmt.Sprintf("%s/projects/%s/locations/%s/operations/%s",
		d.gkeBase(), project, location, opName)
	for {
		st, body, err := d.call("GET", opURL, nil)
		if err == nil && st == http.StatusOK {
			var op struct {
				Status        string `json:"status"`
				StatusMessage string `json:"statusMessage"`
				Error         *struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &op) == nil && op.Status == "DONE" {
				if op.Error != nil || strings.TrimSpace(op.StatusMessage) != "" {
					msg := op.StatusMessage
					if op.Error != nil && op.Error.Message != "" {
						msg = op.Error.Message
					}
					return provider.CreateResult{OperationID: opName, Status: "failed",
						Reason: "operation failed: " + msg}
				}
				return provider.CreateResult{OperationID: opName, Status: "succeeded"}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{OperationID: opName, Status: "unknown",
				Reason: "GKE operation still running at poll timeout — reconcile via operations.get"}
		}
		time.Sleep(d.PollInterval)
	}
}

// observeGKE reverse-maps a live cluster to capability.cluster.kubernetes. Every
// governed attribute is derived from ONE clusters.get — no node-group round trip is
// needed (unlike EKS): availability.class falls straight out of whether the
// cluster's own LOCATION is a region (regional, HA control plane) or a zone (zonal).
func (d *Driver) observeGKE(capability, providerID string) ([]provider.Observation, []string, error) {
	project, location, name, err := splitGKEProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	c, found, rerr := d.getGKE(project, location, name)
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

	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: gkeRegionOf(location), Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string

	// cluster.version: reduce the master version to its governed MINOR version.
	ver := c.CurrentMasterVersion
	if ver == "" {
		ver = c.InitialClusterVersion
	}
	if mv := gkeMinorVersion(ver); mv != "" {
		obs = append(obs, provider.Observation{Path: "cluster.version", Value: mv, Derivation: "measured"})
	} else {
		diags = append(diags, "cluster.version not derivable (no readable master version) — omitted rather than fabricated")
	}

	// network.apiExposure: private endpoint -> private; public endpoint restricted
	// by authorized networks -> mixed; otherwise public.
	exposure := "public"
	switch {
	case c.PrivateClusterConfig.EnablePrivateEndpoint:
		exposure = "private"
	case c.MasterAuthorizedNetworksConfig.Enabled:
		exposure = "mixed"
	}
	obs = append(obs, provider.Observation{Path: "network.apiExposure", Value: exposure, Derivation: "measured"})

	// encryption.secrets: application-layer database encryption ENCRYPTED with a key.
	obs = append(obs, provider.Observation{Path: "encryption.secrets",
		Value: c.DatabaseEncryption.State == "ENCRYPTED", Derivation: "measured"})

	// availability.class: the cluster's own location IS the topology.
	switch {
	case gkeZoneOK.MatchString(location):
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "zonal", Derivation: "measured"})
	case gkeRegionOK.MatchString(location):
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "regional", Derivation: "measured"})
	default:
		diags = append(diags, "availability.class not derivable (location is neither a region nor a zone) — omitted rather than fabricated")
	}
	return obs, diags, nil
}

// updateGKE patches a bound cluster in place: cluster.version via clusters.update
// desiredMasterVersion, network.apiExposure via the authorized-networks /
// private-endpoint config. GKE applies ONE ClusterUpdate at a time, so the changed
// paths are applied SEQUENTIALLY, each polled to DONE. Ownership labels gate the
// patch; four-valued throughout (an ambiguous outcome is unknown WITH the pid).
func (d *Driver) updateGKE(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	project, location, name, err := splitGKEProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	c, found, rerr := d.getGKE(project, location, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update ownership read gave no answer — reconcile before patching: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "cluster no longer exists — cannot update"}
	}
	if !gkeOwned(c, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "cluster labels do not match — refusing to patch a resource that is not ours"}
	}

	for _, path := range changes {
		switch path {
		case "cluster.version":
			ver, _ := attrs["cluster.version"].(string)
			if strings.TrimSpace(ver) == "" {
				return provider.CreateResult{Status: "failed", Reason: "cluster.version must be a non-empty string"}
			}
			body := map[string]any{"update": map[string]any{"desiredMasterVersion": strings.TrimSpace(ver)}}
			if res := d.applyGKEUpdate(project, location, name, providerID, body); res != nil {
				return *res
			}
		case "network.apiExposure":
			exp, _ := attrs["network.apiExposure"].(string)
			upd, err := gkeExposureUpdate(exp, gkeStrs(impl, "masterAuthorizedCidrs"))
			if err != nil {
				return provider.CreateResult{Status: "failed", Reason: err.Error()}
			}
			if res := d.applyGKEUpdate(project, location, name, providerID, map[string]any{"update": upd}); res != nil {
				return *res
			}
		default:
			// ClassifyChange gates this (unsupported/immutable), so a reviewed plan
			// never reaches here — but refuse honestly rather than silently no-op.
			return provider.CreateResult{Status: "failed", Reason: "no in-place GKE mapping for " + path}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// gkeExposureUpdate builds the ClusterUpdate for an apiExposure transition. mixed
// requires the authorized-network CIDRs (the same operand the create requires).
func gkeExposureUpdate(exposure string, cidrs []string) (map[string]any, error) {
	switch exposure {
	case "public":
		return map[string]any{
			"desiredEnablePrivateEndpoint":          false,
			"desiredMasterAuthorizedNetworksConfig": map[string]any{"enabled": false},
		}, nil
	case "private":
		return map[string]any{"desiredEnablePrivateEndpoint": true}, nil
	case "mixed":
		if len(cidrs) == 0 {
			return nil, fmt.Errorf(
				"network.apiExposure=mixed requires implementation.masterAuthorizedCidrs (>=1 CIDR) to restrict the public endpoint")
		}
		return map[string]any{
			"desiredEnablePrivateEndpoint":          false,
			"desiredMasterAuthorizedNetworksConfig": gkeAuthorizedNetworks(cidrs),
		}, nil
	}
	return nil, fmt.Errorf("network.apiExposure must be public|private|mixed")
}

// applyGKEUpdate PUTs one ClusterUpdate and polls the returned operation to DONE.
// Returns nil on success, or a four-valued result on ambiguity/failure.
func (d *Driver) applyGKEUpdate(project, location, name, pid string, body map[string]any) *provider.CreateResult {
	st, resp, err := d.call("PUT", d.gkeClusterURL(project, location, name), body)
	switch {
	case err != nil:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("update outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// accepted — poll the returned operation below
	case st >= 500:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("update HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	default:
		return &provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("update HTTP %d: %s", st, mutDetail(resp))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(resp, &op) != nil || op.Name == "" {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "update response carried no operation — reconcile via clusters.get"}
	}
	res := d.pollGKEOperation(project, location, op.Name)
	if res.Status == "succeeded" {
		return nil
	}
	if res.ProviderID == "" {
		res.ProviderID = pid
	}
	return &res
}

// deleteGKE tears the composite down, ownership-guarded: pre-read the labels (refuse
// a foreign cluster), DELETE the cluster (GKE removes its node pools with it), poll
// the LRO to gone. Idempotent on already-gone (404); a transport/5xx or a poll
// timeout is unknown WITH the pid (reconcile), never a claimed success.
func (d *Driver) deleteGKE(capability, environment, providerID string) provider.CreateResult {
	project, location, name, err := splitGKEProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	c, found, rerr := d.getGKE(project, location, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	if !gkeOwned(c, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "cluster labels do not match — refusing to delete a resource that is not ours"}
	}
	st, body, err := d.call("DELETE", d.gkeClusterURL(project, location, name), nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	switch {
	case st == http.StatusNotFound:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	case st == http.StatusOK:
		// deleting — poll the returned operation below
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	default:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "delete response carried no operation — reconcile"}
	}
	res := d.pollGKEOperation(project, location, op.Name)
	if res.Status == "succeeded" {
		res.ProviderID = providerID
	} else if res.ProviderID == "" {
		res.ProviderID = providerID
	}
	return res
}

// discoverGKE enumerates the project's clusters (across all locations) as
// capability.cluster.kubernetes — so `discover --provider gcp` surfaces a
// gcloud/TF-stood cluster for adoption. Reuses observeGKE (aggregate list ->
// per-cluster reverse map); region, when given, filters on the cluster's residency
// region parsed from its own location.
func (d *Driver) discoverGKE(region string) ([]provider.Discovered, []string, error) {
	url := fmt.Sprintf("%s/projects/%s/locations/-/clusters", d.gkeBase(), d.Project)
	st, body, err := d.call("GET", url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("gke clusters.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("gke clusters.list: HTTP %d", st)
	}
	var resp struct {
		Clusters []struct {
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"clusters"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil, nil, readBody("clusters.list", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, cl := range resp.Clusters {
		if cl.Name == "" || cl.Location == "" {
			continue
		}
		if region != "" && gkeRegionOf(cl.Location) != region {
			continue // another region — not this sweep
		}
		pid := gkeProviderID(d.Project, cl.Location, cl.Name)
		obs, od, oerr := d.observeGKE("", pid)
		if oerr != nil {
			diags = append(diags, cl.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range od {
			diags = append(diags, cl.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID: pid, ResourceType: "capability.cluster.kubernetes", Observations: provider.WithoutAbsence(obs)})
	}
	return out, diags, nil
}
