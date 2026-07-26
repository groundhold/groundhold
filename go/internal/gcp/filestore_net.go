// GCP Filestore network shell (D111): the bearer-signed REST half of the
// capability.storage.filesystem driver. Create/delete are async (LRO) — the
// deterministic instance name means the providerId is knowable BEFORE the create
// response, so a lost/garbled outcome (D29) always carries the handle. Ownership
// is labels. observe reverse-maps region / tier→availability / CMK; the NFS
// version is derived from the tier (Filestore stores no version field), marked
// config-intent. D29/D87 honesty throughout.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func (d *Driver) filestoreBase() string {
	if d.FilestoreBaseURL != "" {
		return d.FilestoreBaseURL
	}
	return filestoreBaseURL
}

func filestoreProviderID(project, location, name string) string {
	return "filestore:" + project + ":" + location + ":" + name
}

func splitFilestoreProviderID(providerID string) (project, location, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "filestore" {
		return "", "", "", fmt.Errorf("providerId %q is not filestore:project:location:name", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !fsLocationOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId location %q is invalid", parts[2])
	}
	if !gcpName.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId instance %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) filestoreInstanceURL(project, location, name string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/instances/%s",
		d.filestoreBase(), project, location, name)
}

type filestoreDoc struct {
	Name       string            `json:"name"`
	Labels     map[string]string `json:"labels"`
	Tier       string            `json:"tier"`
	KmsKeyName string            `json:"kmsKeyName"`
	State      string            `json:"state"`
}

func (d *Driver) getFilestore(project, location, name string) (filestoreDoc, bool, error) {
	const op = "filestore.get"
	st, body, err := d.call("GET", d.filestoreInstanceURL(project, location, name), nil)
	if err != nil {
		return filestoreDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return filestoreDoc{}, false, nil
	}
	if st != http.StatusOK {
		return filestoreDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc filestoreDoc
	if json.Unmarshal(body, &doc) != nil {
		return filestoreDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createFilestore(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildFilestoreCreate(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := filestoreProviderID(d.Project, plan.Location, plan.Name)
	url := fmt.Sprintf("%s/projects/%s/locations/%s/instances?instanceId=%s",
		d.filestoreBase(), d.Project, plan.Location, plan.Name)
	st, body, err := d.call("POST", url, plan.createBody(capability, environment))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// LRO started — poll below
	case st == http.StatusConflict:
		doc, found, rerr := d.getFilestore(d.Project, plan.Location, plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing instance gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
			doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "an instance with this name exists and is not ours (labels do not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // ours, already present
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "create response carried no operation — reconcile"}
	}
	res := d.pollFilestoreOperation(op.Name)
	if res.Status == "succeeded" || res.ProviderID == "" {
		res.ProviderID = pid
	}
	return res
}

// pollFilestoreOperation polls an LRO to done. A still-running op at timeout is
// unknown WITH the operation id (never a confident success).
func (d *Driver) pollFilestoreOperation(opName string) provider.CreateResult {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		st, body, err := d.call("GET", d.filestoreBase()+"/"+opName, nil)
		if err == nil && st == http.StatusOK {
			var op struct {
				Done  bool `json:"done"`
				Error *struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &op) == nil && op.Done {
				if op.Error != nil {
					return provider.CreateResult{Status: "failed", OperationID: opName,
						Reason: fmt.Sprintf("operation failed: %s", op.Error.Message)}
				}
				return provider.CreateResult{Status: "succeeded", OperationID: opName}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{Status: "unknown", OperationID: opName,
				Reason: "filestore operation still running at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

// filestoreProtocolForTier derives the NFS version from the tier (Filestore
// stores no version field): ENTERPRISE speaks NFSv4.1, BASIC tiers NFSv3.
func filestoreProtocolForTier(tier string) string {
	if strings.HasPrefix(tier, "ENTERPRISE") || strings.HasPrefix(tier, "REGIONAL") {
		return "nfs/4.1"
	}
	return "nfs/3"
}

func (d *Driver) observeFilestore(capability, providerID string) ([]provider.Observation, []string, error) {
	project, location, name, err := splitFilestoreProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getFilestore(project, location, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"file share not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: location, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "encryption.atRest", Value: true, Derivation: "config-intent"},
		{Path: "protocol", Value: filestoreProtocolForTier(doc.Tier), Derivation: "config-intent"},
	}
	switch {
	case strings.HasPrefix(doc.Tier, "ENTERPRISE"), strings.HasPrefix(doc.Tier, "REGIONAL"):
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "regional", Derivation: "measured"})
	case doc.Tier != "":
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "zonal", Derivation: "measured"})
	}
	if doc.KmsKeyName != "" {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
			Value: true, Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteFilestore(capability, environment, providerID string) provider.CreateResult {
	project, location, name, err := splitFilestoreProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getFilestore(project, location, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
		doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "instance labels do not match — refusing to delete a resource that is not ours"}
	}
	st, body, e := d.call("DELETE", d.filestoreInstanceURL(project, location, name), nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		if r := provider.MutationResult(st, gcpErrCode(body), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "delete response carried no operation — reconcile"}
	}
	res := d.pollFilestoreOperation(op.Name)
	if res.Status == "succeeded" || res.ProviderID == "" {
		res.ProviderID = providerID
	}
	return res
}
