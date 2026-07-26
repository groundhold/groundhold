// Cloud Functions (Gen 2) network shell (D84 slice 2): the thin, httptest-
// covered half of the fifth service. Single-resource with LABELS (ownership is
// the label discipline, not VPC's description marker). The Gen2 LRO uses the
// google.longrunning shape ({done, error}), NOT the {status:DONE} of Compute/
// Cloud SQL (verified live). Public exposure is TWO gates like Cloud Run: the
// function's ingressSettings AND an allUsers invoker binding on its BACKING
// Cloud Run service (serviceConfig.service) — a create that cannot complete the
// invoker grant NEVER reports succeeded.
//
// Residual (verified live): Cloud Functions v2 functions.delete accepts only
// `name` — no etag/validation precondition, and the Function has no etag — so
// the pre-read-ownership -> DELETE window is a TOCTOU the API cannot close. We
// keep the immediate pre-read + label gate; there is no fake CAS to invent.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func (d *Driver) cfBase() string {
	if d.CfBaseURL != "" {
		return d.CfBaseURL
	}
	return cloudfunctionsBaseURL
}

func functionProviderID(project, region, name string) string {
	return "cloudfunctions:" + project + ":" + region + ":" + name
}

// splitFunctionProviderID validates every component before path interpolation.
// Note: the function NAME is letters-and-hyphens only (Gen2), a subset of
// gcpName's charset, so gcpName is a safe validator.
func splitFunctionProviderID(providerID string) (project, region, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "cloudfunctions" {
		return "", "", "", fmt.Errorf("providerId %q is not cloudfunctions:project:region:name", providerID)
	}
	for i, p := range parts[1:] {
		if !gcpName.MatchString(p) {
			return "", "", "", fmt.Errorf(
				"providerId component %d (%q) is not a valid GCP identifier", i+1, p)
		}
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) functionURL(project, region, name string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/functions/%s",
		d.cfBase(), project, region, name)
}

// pollFunctionOperation polls a google.longrunning Operation ({done, error}).
// done+error is failed; done+no-error is succeeded; a lost read is unknown.
func (d *Driver) pollFunctionOperation(opName string) provider.CreateResult {
	if opName == "" {
		return provider.CreateResult{Status: "unknown",
			Reason: "operation name missing — reconcile"}
	}
	deadline := d.Now().Add(d.PollTimeout)
	for {
		status, body, err := d.call("GET", d.cfBase()+"/"+opName, nil)
		if err == nil && status == http.StatusOK {
			var op struct {
				Done  bool `json:"done"`
				Error *struct {
					Message string `json:"message"`
					Code    int    `json:"code"`
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
				Reason: "cloud function operation still running at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

type functionDoc struct {
	Labels        map[string]string `json:"labels"`
	ServiceConfig struct {
		IngressSettings  string `json:"ingressSettings"`
		Service          string `json:"service"` // backing Cloud Run service path
		MinInstanceCount int    `json:"minInstanceCount"`
	} `json:"serviceConfig"`
}

func (d *Driver) getFunction(project, region, name string) (functionDoc, error) {
	const op = "functions.get"
	status, body, cerr := d.call("GET", d.functionURL(project, region, name), nil)
	if cerr != nil {
		return functionDoc{}, readTransport(op, cerr)
	}
	if status != http.StatusOK {
		return functionDoc{}, readHTTP(op, status, gcpErrCode(body))
	}
	var doc functionDoc
	if json.Unmarshal(body, &doc) != nil {
		return functionDoc{}, readBody(op, status)
	}
	return doc, nil
}

// backingService parses "projects/P/locations/R/services/SVC" into the pieces
// the Cloud Run IAM helpers need. Every component is charset-validated.
func backingService(path string) (project, region, name string, ok bool) {
	// tolerate a leading host if present
	if i := strings.Index(path, "/projects/"); i >= 0 {
		path = path[i+1:]
	}
	parts := strings.Split(path, "/")
	if len(parts) != 6 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "services" {
		return "", "", "", false
	}
	project, region, name = parts[1], parts[3], parts[5]
	if !gcpName.MatchString(project) || !gcpName.MatchString(region) || !gcpName.MatchString(name) {
		return "", "", "", false
	}
	return project, region, name, true
}

// createCloudFunction: POST create (LRO) -> poll -> (if public) grant allUsers
// invoker on the backing Run service. The providerId is attached once the
// function op succeeds; a failed invoker grant is failed/unknown WITH the pid.
func (d *Driver) createCloudFunction(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	req, err := BuildCloudFunctionCreateRequest(d.Project, environment, capability,
		attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	region, _ := attrs["location.region"].(string)
	name := FunctionName(d.Project, environment, capability, generation)
	public, _ := attrs["network.publicExposure"].(bool)
	// the function name is deterministic, so the providerId is knowable BEFORE
	// the create response — a lost/garbled outcome (D29) must carry it so a
	// function that may have landed is never orphaned (handle never lost).
	pid := functionProviderID(d.Project, region, name)
	wantIngress := "ALLOW_INTERNAL_ONLY"
	if public {
		wantIngress = "ALLOW_ALL"
	}
	// rebuild the URL against the (possibly test) base
	req.URL = fmt.Sprintf("%s/projects/%s/locations/%s/functions?functionId=%s",
		d.cfBase(), d.Project, region, name)

	status, body, err := d.call(req.Method, req.URL, req.Body)
	if err != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown: %v", err)}
	}
	switch {
	case status == http.StatusConflict:
		doc, rerr := d.getFunction(d.Project, region, name)
		switch {
		case rerr != nil:
			return provider.CreateResult{Status: "unknown",
				Reason: "name conflict, existing function gave no answer — reconcile: " + rerr.Error()}
		case doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
			doc.Labels["groundhold-environment"] != sanitizeLabel(environment):
			return provider.CreateResult{Status: "failed",
				Reason: "a function with this name exists but is not ours (labels do not match)"}
		case doc.ServiceConfig.IngressSettings != "" && doc.ServiceConfig.IngressSettings != wantIngress:
			// in-place update is not wired, so a mismatched ingress cannot be
			// repaired here — reporting success would lie about the exposure the
			// contract exists for (mirrors createCloudRun's ingress guard).
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf(
				"existing function ingress %q does not match desired %q and cloud "+
					"functions update is not wired", doc.ServiceConfig.IngressSettings, wantIngress)}
		}
		// ours + ingress matches — fall through to the exposure gate
	case status >= 400:
		res := mutationResult("create", status, body)
		if res.Status == "unknown" {
			res.ProviderID = pid // 5xx may have landed — keep the handle
		}
		return res
	default:
		var op struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(body, &op) != nil || op.Name == "" {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "create response carried no operation — reconcile"}
		}
		if res := d.pollFunctionOperation(op.Name); res.Status != "succeeded" {
			return res
		}
	}

	if public {
		// second gate: grant allUsers invoker on the BACKING Run service. Read
		// the function to discover it; a create that cannot make the function
		// public NEVER reports succeeded (it would lie about the exposure the
		// contract exists for).
		doc, rerr := d.getFunction(d.Project, region, name)
		if rerr != nil || doc.ServiceConfig.Service == "" {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "function created but its backing service is not yet readable — reconcile"}
		}
		sp, sr, sn, ok := backingService(doc.ServiceConfig.Service)
		if !ok {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "function backing-service path is unparseable — reconcile"}
		}
		if sp != d.Project {
			// never redirect an allUsers-grant mutation into a project the D75
			// preflight never vetted (a poisoned/malformed serviceConfig.service).
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "backing service is outside the function's project — reconcile"}
		}
		if unknown, err := d.setPublicInvoker(sp, sr, sn); err != nil {
			st := "failed"
			if unknown {
				st = "unknown"
			}
			return provider.CreateResult{ProviderID: pid, Status: st, Reason: err.Error()}
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// observeCloudFunction reverse-maps a live function. publicExposure is TWO gates:
// ingressSettings ALLOW_ALL AND an allUsers invoker on the backing service.
func (d *Driver) observeCloudFunction(capability, providerID string) ([]provider.Observation, []string, error) {
	project, region, name, err := splitFunctionProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, rerr := d.getFunction(project, region, name)
	if rerr != nil {
		return nil, nil, rerr
	}

	var obs []provider.Observation
	var diags []string
	obs = append(obs,
		provider.Observation{Path: "location.region", Value: region, Derivation: "measured"},
		provider.Observation{Path: "service.managed", Value: true, Derivation: "measured"},
		provider.Observation{Path: "availability.class", Value: "regional", Derivation: "config-intent"},
		provider.Observation{Path: "tls.enforced", Value: true, Derivation: "config-intent"},
	)
	if doc.ServiceConfig.MinInstanceCount > 0 {
		obs = append(obs, provider.Observation{Path: "replicas.minimum",
			Value: float64(doc.ServiceConfig.MinInstanceCount), Derivation: "measured"})
	}
	// publicExposure: ingress must be ALLOW_ALL AND the backing service must
	// carry an allUsers invoker binding. An unknown ingress or an unreadable
	// backing IAM emits a diagnostic and NOTHING (never a default-safe value).
	ingress := doc.ServiceConfig.IngressSettings
	knownIngress := ingress == "ALLOW_ALL" || ingress == "ALLOW_INTERNAL_ONLY" ||
		ingress == "ALLOW_INTERNAL_AND_GCLB"
	switch {
	case !knownIngress:
		diags = append(diags, "network.publicExposure not observed: the function "+
			"ingress value is absent or unknown")
	case ingress != "ALLOW_ALL":
		obs = append(obs, provider.Observation{Path: "network.publicExposure",
			Value: false, Derivation: "measured"})
	default:
		sp, sr, sn, ok := backingService(doc.ServiceConfig.Service)
		if !ok || sp != project {
			// unparseable, or a backing service outside the function's project
			// (never attribute a foreign service's exposure to this capability).
			diags = append(diags, "network.publicExposure not observed: the backing "+
				"service path does not parse, or names another project")
			break
		}
		// TWO reachability paths, like Cloud Run: invokerIamDisabled OR an
		// allUsers invoker binding. Missing invokerIamDisabled defense would
		// measure a world-invocable function as private.
		disabled, svcErr := d.runInvokerDisabled(sp, sr, sn)
		if svcErr != nil {
			diags = append(diags, "network.publicExposure not observed on the backing "+
				"service: "+svcErr.Error())
			break
		}
		if disabled {
			obs = append(obs, provider.Observation{Path: "network.publicExposure",
				Value: true, Derivation: "measured"})
			break
		}
		iamPublic, iamErr := d.readInvoker(sp, sr, sn)
		if iamErr != nil {
			diags = append(diags, "network.publicExposure not observed on the backing "+
				"service: "+iamErr.Error())
		} else {
			obs = append(obs, provider.Observation{Path: "network.publicExposure",
				Value: iamPublic, Derivation: "measured"})
		}
	}
	return obs, diags, nil
}

// runInvokerDisabled reads the backing Cloud Run service's invokerIamDisabled
// flag — a public mode independent of any allUsers binding. Unreadable is
// three-valued (never a default-safe false).
func (d *Driver) runInvokerDisabled(project, region, name string) (disabled bool, err error) {
	const op = "services.get"
	status, body, cerr := d.call("GET", d.runServiceURL(project, region, name), nil)
	if cerr != nil {
		return false, readTransport(op, cerr)
	}
	if status != http.StatusOK {
		return false, readHTTP(op, status, gcpErrCode(body))
	}
	var svc struct {
		InvokerIamDisabled bool `json:"invokerIamDisabled"`
	}
	if json.Unmarshal(body, &svc) != nil {
		return false, readBody(op, status)
	}
	return svc.InvokerIamDisabled, nil
}

// deleteCloudFunction: ownership pre-read (labels), then DELETE (LRO), then
// poll. 404 is idempotent success; never delete a function that is not ours.
func (d *Driver) deleteCloudFunction(capability, environment, providerID string) provider.CreateResult {
	project, region, name, err := splitFunctionProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	status, body, err := d.call("GET", d.functionURL(project, region, name), nil)
	if err != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("pre-delete read failed: %v", err)}
	}
	if status == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if status != http.StatusOK {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("pre-delete read: HTTP %d", status)}
	}
	var doc functionDoc
	if json.Unmarshal(body, &doc) != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: "pre-delete read unparseable — refusing an ambiguous delete"}
	}
	if doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
		doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "function labels do not match — refusing to delete a resource that is not ours"}
	}
	status, respBody, err := d.call("DELETE", d.functionURL(project, region, name), nil)
	if err != nil {
		// a lost delete response (D29) — keep the pinned handle so reconcile can
		// conclude a delete that may have landed, never drop it.
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if status == http.StatusNotFound {
		// concurrently deleted between the pre-read and the DELETE — the desired
		// end-state (gone) holds, so this is idempotent success, not failure.
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if status >= 400 {
		res := mutationResult("delete", status, respBody)
		if res.Status == "unknown" {
			res.ProviderID = providerID
		}
		return res
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(respBody, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "delete response carried no operation — reconcile"}
	}
	res := d.pollFunctionOperation(op.Name)
	if res.Status == "succeeded" {
		res.ProviderID = providerID
	}
	return res
}
