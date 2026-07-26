// GCP Certificate Manager network shell (D117): the bearer-signed REST half of the
// capability.certificate.tls driver. Create/delete are async (LRO). The certificateId
// is deterministic, so the providerId is knowable before the create response (D29).
// Ownership is labels. The private KEY never transits groundhold (D53). D29/D87 honesty.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func (d *Driver) certManagerBase() string {
	if d.CertManagerBaseURL != "" {
		return d.CertManagerBaseURL
	}
	return certManagerBaseURL
}

func certManagerProviderID(project, location, certID string) string {
	return "gcert:" + project + ":" + location + ":" + certID
}

func splitCertManagerProviderID(providerID string) (project, location, certID string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "gcert" {
		return "", "", "", fmt.Errorf("providerId %q is not gcert:project:location:certId", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !certLocationValid(parts[2]) {
		return "", "", "", fmt.Errorf("providerId location %q is invalid", parts[2])
	}
	if !certIDOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId certId %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

// certLocationOK accepts "global" or a region token (europe-west1).
var certLocationOK = redisRegionOK // reuse the region regex; "global" handled below

func certLocationValid(loc string) bool {
	return loc == "global" || certLocationOK.MatchString(loc)
}

func (d *Driver) certManagerURL(project, location, certID string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/certificates/%s",
		d.certManagerBase(), project, location, certID)
}

type certManagerDoc struct {
	Name    string            `json:"name"`
	Labels  map[string]string `json:"labels"`
	Managed struct {
		Domains []string `json:"domains"`
		State   string   `json:"state"`
	} `json:"managed"`
}

func (d *Driver) getCertManager(project, location, certID string) (certManagerDoc, bool, error) {
	const op = "certManager.get"
	st, body, err := d.call("GET", d.certManagerURL(project, location, certID), nil)
	if err != nil {
		return certManagerDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return certManagerDoc{}, false, nil
	}
	if st != http.StatusOK {
		return certManagerDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc certManagerDoc
	if json.Unmarshal(body, &doc) != nil {
		return certManagerDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createCertManager(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildCertManager(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !certLocationValid(plan.Location) {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("location %q is not a valid region or 'global'", plan.Location)}
	}
	pid := certManagerProviderID(d.Project, plan.Location, plan.CertID)
	url := fmt.Sprintf("%s/projects/%s/locations/%s/certificates?certificateId=%s",
		d.certManagerBase(), d.Project, plan.Location, plan.CertID)
	st, body, err := d.call("POST", url, plan.createBody(capability, environment))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// LRO started — poll below
	case st == http.StatusConflict:
		doc, found, rerr := d.getCertManager(d.Project, plan.Location, plan.CertID)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing certificate gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
			doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a certificate with this id exists and is not ours (labels do not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // ours, present
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
	res := d.pollCertManagerOperation(op.Name)
	if res.Status == "succeeded" || res.ProviderID == "" {
		res.ProviderID = pid
	}
	return res
}

func (d *Driver) pollCertManagerOperation(opName string) provider.CreateResult {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		st, body, err := d.call("GET", d.certManagerBase()+"/"+opName, nil)
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
				Reason: "certificate manager operation still running at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

func (d *Driver) observeCertManager(capability, providerID string) ([]provider.Observation, []string, error) {
	project, location, certID, err := splitCertManagerProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getCertManager(project, location, certID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"certificate not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: location, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// a Certificate Manager managed certificate is DNS-validated and auto-renewing.
		{Path: "validation.method", Value: "dns", Derivation: "config-intent"},
		{Path: "auto.renew", Value: true, Derivation: "config-intent"},
	}
	if len(doc.Managed.Domains) > 0 {
		obs = append(obs, provider.Observation{Path: "domain", Value: doc.Managed.Domains[0], Derivation: "measured"})
	}
	diags := []string{fmt.Sprintf("managed certificate state is %s (provisions once the DNS authorization resolves)", doc.Managed.State)}
	return obs, diags, nil
}

func (d *Driver) deleteCertManager(capability, environment, providerID string) provider.CreateResult {
	project, location, certID, err := splitCertManagerProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getCertManager(project, location, certID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
		doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "certificate labels do not match — refusing to delete a resource that is not ours"}
	}
	st, body, e := d.call("DELETE", d.certManagerURL(project, location, certID), nil)
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
	res := d.pollCertManagerOperation(op.Name)
	if res.Status == "succeeded" || res.ProviderID == "" {
		res.ProviderID = providerID
	}
	return res
}
