// Compute Engine instance network shell (D359): auth, HTTP, operation polling
// and the reverse mapping. No semantics here — those are in computeinstance.go.
//
// The long-running-operation handling is NOT reimplemented: `computeInsert` and
// `pollComputeOperation` already carry the D29 discipline for this API family
// (5xx unknown, empty operation unknown, DONE-with-any-error failed, timeout
// unknown with a reconcilable operation id), and the scope argument takes
// "zones/<zone>" as readily as the "global"/"regions/<r>" the VPC driver uses.
// Writing a second poller would have been the easy mistake: a copy diverges, and
// the copy is always the one missing the fix.
//
// The 409 continuation is what makes the deterministic name an idempotency
// mechanism: a name conflict is resolved by READING the existing instance and
// checking OUR labels. A machine with the right name and someone else's labels
// is a refusal, never an adoption — binding it would put a stranger's server
// under our contract.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// gceProviderID is zone-scoped: an instance name is unique per zone.
func gceProviderID(project, zone, name string) string {
	return "gce:" + project + ":" + zone + ":" + name
}

func splitGCEProviderID(providerID string) (project, zone, name string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "gce" {
		return "", "", "", fmt.Errorf("providerId %q is not gce:project:zone:name", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !gceZoneOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId zone %q is invalid", parts[2])
	}
	if !gcpName.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId instance name %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

// gceInstanceDoc is the slice of instances.get this driver reads.
type gceInstanceDoc struct {
	Name              string            `json:"name"`
	Status            string            `json:"status"`
	Labels            map[string]string `json:"labels"`
	NetworkInterfaces []struct {
		AccessConfigs []struct {
			NatIP string `json:"natIP"`
		} `json:"accessConfigs"`
	} `json:"networkInterfaces"`
	Disks []struct {
		Boot              bool `json:"boot"`
		DiskEncryptionKey *struct {
			KmsKeyName string `json:"kmsKeyName"`
		} `json:"diskEncryptionKey"`
	} `json:"disks"`
}

// getGCEInstance reads one instance. `found=false` with no error means the API
// answered and the instance is not there — different from "the read failed", and
// the difference is what keeps a delete idempotent instead of guessing.
func (d *Driver) getGCEInstance(project, zone, name string) (gceInstanceDoc, bool, error) {
	st, body, err := d.call("GET", fmt.Sprintf("%s/projects/%s/zones/%s/instances/%s",
		d.computeBase(), project, zone, name), nil)
	if err != nil {
		return gceInstanceDoc{}, false, readTransport("instances.get", err)
	}
	if st == http.StatusNotFound {
		return gceInstanceDoc{}, false, nil
	}
	if st != http.StatusOK {
		return gceInstanceDoc{}, false, readHTTP("instances.get", st, gcpErrCode(body))
	}
	var doc gceInstanceDoc
	if json.Unmarshal(body, &doc) != nil {
		return gceInstanceDoc{}, false, readBody("instances.get", st)
	}
	return doc, true, nil
}

func (d *Driver) createGCEInstance(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {

	plan, err := BuildGCEInstanceCreate(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := gceProviderID(d.Project, plan.Zone, plan.Name)
	url := fmt.Sprintf("%s/projects/%s/zones/%s/instances", d.computeBase(), d.Project, plan.Zone)

	st, res := d.computeInsert(url, plan.createBody(capability, environment), "zones/"+plan.Zone)
	if st == http.StatusConflict {
		// The deterministic name already exists. It is ours only if the labels say
		// so — otherwise we would bind a stranger's machine to this contract.
		doc, found, rerr := d.getGCEInstance(d.Project, plan.Zone, plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing instance gave no answer — reconcile: " + rerr.Error()}
		}
		if !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "insert reported a name conflict but the instance is not readable — reconcile"}
		}
		if doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
			doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "an instance with this name exists and is not ours (labels do not match) — refusing to bind it"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	}
	if res.Status == "succeeded" {
		res.ProviderID = pid
	} else if res.ProviderID == "" {
		// Even an unknown outcome carries the pid: the name is deterministic, so
		// the resource is findable whatever the operation did.
		res.ProviderID = pid
	}
	return res
}

// observeGCEInstance is the reverse mapping. encryption.atRest is reported as a
// CONSTANT true because Compute Engine encrypts every persistent disk and offers
// no way to disable it — this is a fact about the platform, not a reading of the
// resource, so it is tagged config-intent rather than measured.
func (d *Driver) observeGCEInstance(capability, providerID string) ([]provider.Observation, []string, error) {
	project, zone, name, err := splitGCEProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getGCEInstance(project, zone, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"instance not found — nothing to observe"}, nil
	}
	public := false
	for _, nic := range doc.NetworkInterfaces {
		if len(nic.AccessConfigs) > 0 {
			public = true
			break
		}
	}
	cmk := false
	for _, disk := range doc.Disks {
		if disk.Boot && disk.DiskEncryptionKey != nil && disk.DiskEncryptionKey.KmsKeyName != "" {
			cmk = true
			break
		}
	}
	return []provider.Observation{
		{Path: "location.region", Value: gceRegionOfZone(zone), Derivation: "measured"},
		{Path: "availability.class", Value: "zonal", Derivation: "measured"},
		{Path: "network.publicExposure", Value: public, Derivation: "measured"},
		{Path: "encryption.atRest", Value: true, Derivation: "config-intent"},
		{Path: "encryption.customerManagedKeys", Value: cmk, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}, nil, nil
}

func (d *Driver) deleteGCEInstance(capability, environment, providerID string) provider.CreateResult {
	project, zone, name, err := splitGCEProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getGCEInstance(project, zone, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
		doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "instance labels do not match — refusing to delete a machine that is not ours"}
	}
	st, body, e := d.call("DELETE", fmt.Sprintf("%s/projects/%s/zones/%s/instances/%s",
		d.computeBase(), project, zone, name), nil)
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	case st == http.StatusNotFound:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	case st >= 400:
		r := mutationResult("delete", st, body)
		r.ProviderID = providerID
		return r
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "delete response carried no operation — reconcile"}
	}
	r := d.pollComputeOperation("zones/"+zone, op.Name)
	r.ProviderID = providerID
	return r
}

// discoverGCEInstances enumerates machines in the region's zones. Every
// observable service must be discoverable (spec/drivers.md §2) — a machine the
// proactive posture cannot see is a machine nobody is watching.
//
// aggregatedList is one call for the whole project; the zone keys are filtered
// to the region asked for, so a per-region sweep does not become a per-zone fan-out.
func (d *Driver) discoverGCEInstances(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.call("GET", fmt.Sprintf("%s/projects/%s/aggregated/instances",
		d.computeBase(), d.Project), nil)
	if err != nil {
		return nil, nil, readTransport("instances.aggregatedList", err)
	}
	if st != http.StatusOK {
		return nil, nil, readHTTP("instances.aggregatedList", st, gcpErrCode(body))
	}
	var page struct {
		Items map[string]struct {
			Instances []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"instances"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &page) != nil {
		return nil, nil, readBody("instances.aggregatedList", st)
	}
	var out []provider.Discovered
	var diags []string
	for scope, group := range page.Items {
		zone := strings.TrimPrefix(scope, "zones/")
		if zone == scope || gceRegionOfZone(zone) != region {
			continue
		}
		for _, inst := range group.Instances {
			if inst.Name == "" || inst.Status == "TERMINATED" {
				continue
			}
			pid := gceProviderID(d.Project, zone, inst.Name)
			obs, odiags, oerr := d.observeGCEInstance("", pid)
			if oerr != nil {
				diags = append(diags, inst.Name+": "+oerr.Error())
				continue
			}
			for _, dg := range odiags {
				diags = append(diags, inst.Name+": "+dg)
			}
			out = append(out, provider.Discovered{
				ProviderID:   pid,
				ResourceType: "capability.compute.instance",
				Observations: obs,
			})
		}
	}
	return out, diags, nil
}
