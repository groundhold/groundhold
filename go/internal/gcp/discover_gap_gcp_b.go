package gcp

// Read-only discovery sweeps for a second batch of GCP services (the D52
// brownfield discover -> adopt path). Each sweep is the LIST half of a driver
// whose Observe reverse map already exists: List yields deterministic
// providerIds, Observe (a per-resource GET) yields the attributes. The two
// steps stay separate — a sweep never fabricates an all-unknown record, and a
// per-resource observe failure becomes a diagnostic, never a hidden gap.
//
// These live in their own file (never touching discover_gcp.go) and every new
// package-level helper is service-prefixed so a parallel GCP expansion cannot
// collide. Strictly read-only; no secret value is ever read (D53).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// gapbLocAndName pulls the location and leaf name out of a GCP resource name of
// the shape projects/<p>/locations/<loc>/<collection>/<name>. It mirrors
// runLocationName but is parameterized on the collection segment (jobs /
// instances / clusters), so the three aggregated (locations/-) sweeps below
// share one parser without duplicating the index arithmetic.
func gapbLocAndName(resourceName, collection string) (loc, name string, ok bool) {
	li := strings.Index(resourceName, "/locations/")
	ci := strings.Index(resourceName, "/"+collection+"/")
	if li < 0 || ci < 0 || ci < li {
		return "", "", false
	}
	loc = resourceName[li+len("/locations/") : ci]
	name = resourceName[ci+len("/"+collection+"/"):]
	if loc == "" || name == "" {
		return "", "", false
	}
	return loc, name, true
}

// discoverCloudRunJobs enumerates Cloud Run Jobs as capability.container.job,
// reusing observeCloudRunJob's reverse map. The aggregated list (locations/-)
// spans every region; region, when given, filters on the job's own location
// parsed from its resource name.
func (d *Driver) discoverCloudRunJobs(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", d.runBase()+"/projects/"+d.Project+"/locations/-/jobs", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("jobs.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("jobs.list: HTTP %d", status)
	}
	var resp struct {
		Jobs []struct {
			Name string `json:"name"`
		} `json:"jobs"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("jobs.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, j := range resp.Jobs {
		loc, name, ok := gapbLocAndName(j.Name, "jobs")
		if !ok {
			continue
		}
		if region != "" && loc != region {
			continue // another location — not this sweep
		}
		pid := cloudRunJobProviderID(d.Project, loc, name)
		obs, odiags, err := d.observeCloudRunJob("", pid)
		if err != nil {
			diags = append(diags, name+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.container.job",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverFilestore enumerates Filestore instances as
// capability.storage.filesystem, reusing observeFilestore. The aggregated list
// (locations/-) spans every location; region, when given, filters on the
// instance's own location.
func (d *Driver) discoverFilestore(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", d.filestoreBase()+"/projects/"+d.Project+"/locations/-/instances", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("instances.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("instances.list: HTTP %d", status)
	}
	var resp struct {
		Instances []struct {
			Name string `json:"name"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("instances.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, inst := range resp.Instances {
		loc, name, ok := gapbLocAndName(inst.Name, "instances")
		if !ok {
			continue
		}
		if region != "" && loc != region {
			continue // another location — not this sweep
		}
		pid := filestoreProviderID(d.Project, loc, name)
		obs, odiags, err := d.observeFilestore("", pid)
		if err != nil {
			diags = append(diags, name+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.storage.filesystem",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverManagedKafka enumerates Managed Service for Apache Kafka clusters as
// capability.messaging.kafka, reusing observeManagedKafka. The aggregated list
// (locations/-) spans every location; region, when given, filters on the
// cluster's own location.
func (d *Driver) discoverManagedKafka(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", d.managedKafkaBase()+"/projects/"+d.Project+"/locations/-/clusters", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("clusters.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("clusters.list: HTTP %d", status)
	}
	var resp struct {
		Clusters []struct {
			Name string `json:"name"`
		} `json:"clusters"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("clusters.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, c := range resp.Clusters {
		loc, name, ok := gapbLocAndName(c.Name, "clusters")
		if !ok {
			continue
		}
		if region != "" && loc != region {
			continue // another location — not this sweep
		}
		pid := managedKafkaProviderID(d.Project, loc, name)
		obs, odiags, err := d.observeManagedKafka("", pid)
		if err != nil {
			diags = append(diags, name+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.messaging.kafka",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverDashboards enumerates Cloud Monitoring dashboards as
// capability.monitoring.dashboard, reusing observeDashboard. Dashboards are
// project-global; region does not filter.
func (d *Driver) discoverDashboards(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/dashboards", d.dashboardBase(), d.Project), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("dashboards.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("dashboards.list: HTTP %d", status)
	}
	var resp struct {
		Dashboards []struct {
			Name string `json:"name"`
		} `json:"dashboards"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("dashboards.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, dash := range resp.Dashboards {
		id := leafName(dash.Name)
		if id == "" {
			continue
		}
		pid := gdashProviderID(d.Project, id)
		obs, odiags, err := d.observeDashboard("", pid)
		if err != nil {
			diags = append(diags, id+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, id+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.monitoring.dashboard",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverLogMetrics enumerates log-based metrics as
// capability.monitoring.logmetric, reusing observeLogMetric. A LogMetric's name
// is the bare client-assigned identifier (not a projects/.../metrics/... path),
// so it is used verbatim as the providerId leaf. Log metrics are
// project-global; region does not filter.
func (d *Driver) discoverLogMetrics(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/metrics", d.loggingBase(), d.Project), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("metrics.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("metrics.list: HTTP %d", status)
	}
	var resp struct {
		Metrics []struct {
			Name string `json:"name"`
		} `json:"metrics"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("metrics.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, m := range resp.Metrics {
		if m.Name == "" {
			continue
		}
		pid := glogmetricProviderID(d.Project, m.Name)
		obs, odiags, err := d.observeLogMetric("", pid)
		if err != nil {
			diags = append(diags, m.Name+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, m.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.monitoring.logmetric",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// schedLocations lists the Cloud Scheduler locations available to the project.
// jobs.list requires a concrete location (no `-` wildcard), so a full-estate
// sweep enumerates locations first — the same shape discoverArtifactRegistries
// uses.
func (d *Driver) schedLocations() ([]string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/locations", d.schedBase(), d.Project), nil)
	if err != nil {
		return nil, fmt.Errorf("locations.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("locations.list: HTTP %d", status)
	}
	var resp struct {
		Locations []struct {
			LocationID string `json:"locationId"`
		} `json:"locations"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, readBody("locations.list", status)
	}
	var out []string
	for _, l := range resp.Locations {
		if l.LocationID != "" {
			out = append(out, l.LocationID)
		}
	}
	return out, nil
}

// discoverCloudScheduler enumerates Cloud Scheduler jobs as
// capability.scheduler.cron, reusing observeCloudScheduler. A given region is
// swept directly; an empty region enumerates the project's locations first
// (jobs.list has no cross-location wildcard). A per-location list failure is a
// diagnostic — it never hides the jobs another location did return.
func (d *Driver) discoverCloudScheduler(region string) ([]provider.Discovered, []string, error) {
	var locations []string
	var diags []string
	if region != "" {
		locations = []string{region}
	} else {
		locs, err := d.schedLocations()
		if err != nil {
			return nil, nil, err
		}
		locations = locs
	}
	var out []provider.Discovered
	for _, loc := range locations {
		status, body, err := d.call("GET", fmt.Sprintf(
			"%s/projects/%s/locations/%s/jobs", d.schedBase(), d.Project, loc), nil)
		if err != nil {
			diags = append(diags, "jobs.list "+loc+": "+err.Error())
			continue
		}
		if status != http.StatusOK {
			diags = append(diags, fmt.Sprintf("jobs.list %s: HTTP %d", loc, status))
			continue
		}
		var resp struct {
			Jobs []struct {
				Name string `json:"name"`
			} `json:"jobs"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			diags = append(diags, loc+": "+readBody("jobs.list", status).Error())
			continue
		}
		for _, j := range resp.Jobs {
			jobID := leafName(j.Name)
			if jobID == "" {
				continue
			}
			pid := schedProviderID(d.Project, loc, jobID)
			obs, odiags, err := d.observeCloudScheduler("", pid)
			if err != nil {
				diags = append(diags, jobID+": "+err.Error())
				continue
			}
			for _, dg := range odiags {
				diags = append(diags, jobID+": "+dg)
			}
			out = append(out, provider.Discovered{
				ProviderID:   pid,
				ResourceType: "capability.scheduler.cron",
				Observations: obs,
			})
		}
	}
	return out, diags, nil
}

// discoverVPNGateways enumerates HA VPN gateways as capability.vpn.gateway,
// reusing observeCloudVPN. VPN gateways are a regional compute resource, so a
// single aggregatedList (all scopes) enumerates the estate; region, when given,
// filters on the gateway's scope. Scope keys are mapped through the existing
// lbScopeFromKey compute-scope parser; global/zonal/unknown scopes are skipped
// (VPN gateways are only regional).
func (d *Driver) discoverVPNGateways(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/aggregated/vpnGateways", d.computeBase(), d.Project), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("vpnGateways.aggregatedList: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("vpnGateways.aggregatedList: HTTP %d", status)
	}
	var resp struct {
		Items map[string]struct {
			VPNGateways []struct {
				Name string `json:"name"`
			} `json:"vpnGateways"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("vpnGateways.aggregatedList", status)
	}
	var out []provider.Discovered
	var diags []string
	for scopeKey, bucket := range resp.Items {
		scope := lbScopeFromKey(scopeKey)
		if scope == "" || scope == "global" {
			continue // VPN gateways are regional only
		}
		if region != "" && scope != region {
			continue // another scope — not this sweep
		}
		for _, gw := range bucket.VPNGateways {
			if gw.Name == "" {
				continue
			}
			pid := cloudVPNProviderID(d.Project, scope, gw.Name)
			obs, odiags, err := d.observeCloudVPN("", pid)
			if err != nil {
				diags = append(diags, gw.Name+": "+err.Error())
				continue
			}
			for _, dg := range odiags {
				diags = append(diags, gw.Name+": "+dg)
			}
			out = append(out, provider.Discovered{
				ProviderID:   pid,
				ResourceType: "capability.vpn.gateway",
				Observations: obs,
			})
		}
	}
	return out, diags, nil
}
