// Persistent Disk network shell (D368): auth, HTTP, operation polling and the
// reverse mapping. No semantics here — those are in persistentdisk.go.
//
// The long-running-operation handling is NOT reimplemented: `computeInsert` and
// `pollComputeOperation` already carry the D29 discipline for this API family
// (5xx unknown, empty operation unknown, DONE-with-any-error failed, timeout
// unknown with a reconcilable operation id), and the scope argument takes
// "regions/<r>" as readily as the "zones/<z>" the instance driver uses. Writing a
// second poller would have been the easy mistake: a copy diverges, and the copy
// is always the one missing the fix.
//
// Zonal and regional disks live at DIFFERENT URLs (/zones/<z>/disks and
// /regions/<r>/disks) and are different resources, not two settings of one. The
// providerId carries the scope verbatim, so a read never has to guess which
// endpoint holds the disk — guessing wrong would report a disk as absent while it
// exists, and an absent disk is an idempotent delete.
//
// The 409 continuation is what makes the deterministic name an idempotency
// mechanism: a name conflict is resolved by READING the existing disk and
// checking OUR labels. A disk with the right name and someone else's labels is a
// refusal, never an adoption — and on a stateful capability, binding it would put
// a stranger's DATA under our contract, and our delete gate over it.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// pdProviderID is scope-qualified: a disk name is unique per zone (zonal) or per
// region (regional), and the two namespaces are distinct.
func pdProviderID(project, scope, name string) string {
	return "pd:" + project + ":" + scope + ":" + name
}

func splitPDProviderID(providerID string) (project, scope, name string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "pd" {
		return "", "", "", fmt.Errorf("providerId %q is not pd:project:scope:name", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	// The scope is a zone OR a region, and which one decides the endpoint.
	if !gceZoneOK.MatchString(parts[2]) && !pdRegionOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId scope %q is neither a zone nor a region", parts[2])
	}
	if !gcpName.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId disk name %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

// pdScopeIsRegional reports whether a providerId scope names a region. A zone
// always carries the trailing letter a region does not.
func pdScopeIsRegional(scope string) bool {
	return !gceZoneOK.MatchString(scope)
}

// pdCollectionURL is the collection a disk of this scope lives in.
func (d *Driver) pdCollectionURL(project, scope string) string {
	if pdScopeIsRegional(scope) {
		return fmt.Sprintf("%s/projects/%s/regions/%s/disks", d.computeBase(), project, scope)
	}
	return fmt.Sprintf("%s/projects/%s/zones/%s/disks", d.computeBase(), project, scope)
}

// pdOperationScope is the scope `pollComputeOperation` needs for this disk.
func pdOperationScope(scope string) string {
	if pdScopeIsRegional(scope) {
		return "regions/" + scope
	}
	return "zones/" + scope
}

// pdDoc is the slice of disks.get this driver reads.
type pdDoc struct {
	Name              string            `json:"name"`
	Status            string            `json:"status"`
	Labels            map[string]string `json:"labels"`
	ReplicaZones      []string          `json:"replicaZones"`
	DiskEncryptionKey *struct {
		KmsKeyName string `json:"kmsKeyName"`
	} `json:"diskEncryptionKey"`
}

// getPD reads one disk. `found=false` with no error means the API answered and
// the disk is not there — different from "the read failed", and the difference is
// what keeps a delete idempotent instead of guessing.
func (d *Driver) getPD(project, scope, name string) (pdDoc, bool, error) {
	st, body, err := d.call("GET", d.pdCollectionURL(project, scope)+"/"+name, nil)
	if err != nil {
		return pdDoc{}, false, readTransport("disks.get", err)
	}
	if st == http.StatusNotFound {
		return pdDoc{}, false, nil
	}
	if st != http.StatusOK {
		return pdDoc{}, false, readHTTP("disks.get", st, gcpErrCode(body))
	}
	var doc pdDoc
	if json.Unmarshal(body, &doc) != nil {
		return pdDoc{}, false, readBody("disks.get", st)
	}
	return doc, true, nil
}

func (d *Driver) createPD(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {

	plan, err := BuildPDCreate(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	scope := plan.Zone
	if plan.Regional {
		scope = plan.Region
	}
	pid := pdProviderID(d.Project, scope, plan.Name)

	st, res := d.computeInsert(d.pdCollectionURL(d.Project, scope),
		plan.createBody(capability, environment), pdOperationScope(scope))
	if st == http.StatusConflict {
		// The deterministic name already exists. It is ours only if the labels say
		// so — otherwise we would bind a stranger's DATA to this contract, and put
		// our delete gate over it.
		doc, found, rerr := d.getPD(d.Project, scope, plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing disk gave no answer — reconcile: " + rerr.Error()}
		}
		if !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "insert reported a name conflict but the disk is not readable — reconcile"}
		}
		if doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
			doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a disk with this name exists and is not ours (labels do not match) — refusing to bind it"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	}
	if res.Status == "succeeded" || res.ProviderID == "" {
		// Even an unknown outcome carries the pid: the name is deterministic, so
		// the disk is findable whatever the operation did.
		res.ProviderID = pid
	}
	return res
}

// observePD is the reverse mapping. encryption.atRest is reported as a CONSTANT
// true because Compute Engine encrypts every persistent disk and offers no way to
// disable it — a fact about the platform, not a reading of the resource, so it is
// tagged config-intent rather than measured.
//
// availability.class is read from the RESOURCE (replicaZones), not inferred from
// the providerId scope. The scope says where we looked; replicaZones says what the
// disk actually is, and on a durability guarantee the difference is the whole
// point of observing rather than assuming.
func (d *Driver) observePD(capability, providerID string) ([]provider.Observation, []string, error) {
	project, scope, name, err := splitPDProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getPD(project, scope, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"disk not found — nothing to observe"}, nil
	}
	region := scope
	class := "regional"
	if !pdScopeIsRegional(scope) {
		region = gceRegionOfZone(scope)
		class = "zonal"
	}
	if len(doc.ReplicaZones) > 1 {
		class = "regional"
	}
	cmk := doc.DiskEncryptionKey != nil && doc.DiskEncryptionKey.KmsKeyName != ""
	return []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "availability.class", Value: class, Derivation: "measured"},
		{Path: "encryption.atRest", Value: true, Derivation: "config-intent"},
		{Path: "encryption.customerManagedKeys", Value: cmk, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}, nil, nil
}

// deletePD destroys the disk AND the data on it, and refuses to touch one whose
// ownership labels are not ours.
//
// The stateful gates (D47) sit above this in the executor: reaching here at all
// means the plan pinned this disk as a retirement target and the operator
// consented to the data loss. What this function owes them is that it deletes
// exactly what was pinned and nothing else.
func (d *Driver) deletePD(capability, environment, providerID string) provider.CreateResult {
	project, scope, name, err := splitPDProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getPD(project, scope, name)
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
			Reason: "disk labels do not match — refusing to destroy data that is not ours"}
	}
	st, body, e := d.call("DELETE", d.pdCollectionURL(project, scope)+"/"+name, nil)
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
	r := d.pollComputeOperation(pdOperationScope(scope), op.Name)
	r.ProviderID = providerID
	return r
}

// discoverPD enumerates disks in the region, ZONAL AND REGIONAL BOTH. Every
// observable service must be discoverable (spec/drivers.md §2) — and an
// unmanaged, unencrypted disk nobody is watching is one of the more expensive
// blind spots a proactive posture can have, because the data on it is already
// there.
//
// aggregatedList is one call for the whole project and its keys carry both
// scopes, which is why it is used rather than a per-zone fan-out: a sweep that
// enumerated zones only would silently miss every regional disk, and report the
// account as clean.
func (d *Driver) discoverPD(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.call("GET", fmt.Sprintf("%s/projects/%s/aggregated/disks",
		d.computeBase(), d.Project), nil)
	if err != nil {
		return nil, nil, readTransport("disks.aggregatedList", err)
	}
	if st != http.StatusOK {
		return nil, nil, readHTTP("disks.aggregatedList", st, gcpErrCode(body))
	}
	var page struct {
		Items map[string]struct {
			Disks []struct {
				Name string `json:"name"`
			} `json:"disks"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &page) != nil {
		return nil, nil, readBody("disks.aggregatedList", st)
	}
	var out []provider.Discovered
	var diags []string
	for key, group := range page.Items {
		scope := ""
		switch {
		case strings.HasPrefix(key, "zones/"):
			z := strings.TrimPrefix(key, "zones/")
			if gceRegionOfZone(z) != region {
				continue
			}
			scope = z
		case strings.HasPrefix(key, "regions/"):
			r := strings.TrimPrefix(key, "regions/")
			if r != region {
				continue
			}
			scope = r
		default:
			continue
		}
		for _, disk := range group.Disks {
			if disk.Name == "" {
				continue
			}
			pid := pdProviderID(d.Project, scope, disk.Name)
			obs, odiags, oerr := d.observePD("", pid)
			if oerr != nil {
				diags = append(diags, disk.Name+": "+oerr.Error())
				continue
			}
			for _, dg := range odiags {
				diags = append(diags, disk.Name+": "+dg)
			}
			out = append(out, provider.Discovered{
				ProviderID:   pid,
				ResourceType: "capability.storage.block",
				Observations: obs,
			})
		}
	}
	return out, diags, nil
}
