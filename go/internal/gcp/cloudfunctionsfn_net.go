// Cloud Functions (Gen 2) network shell for capability.function.serverless — the
// httptest-covered half of the second Cloud Functions service token (`cffn:` ids).
// It shares the Cloud Functions v2 API host and helpers with the workload-container
// driver (cloudfunctions_net.go) but carries the function.serverless attribute set
// (timeout.maximum, replicas.minimum) and its own providerId namespace so the two
// never collide. The Gen2 LRO is the RESPONSE-DERIVED operation name polled on the
// canonical operations endpoint (pollFunctionOperation), never a constructed path.
// Public exposure is TWO gates (ingressSettings ALLOW_ALL + an allUsers invoker on
// the backing Cloud Run service); a create that cannot complete both NEVER succeeds.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// splitFnServerlessProviderID validates every component before path interpolation.
func splitFnServerlessProviderID(providerID string) (project, region, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "cffn" {
		return "", "", "", fmt.Errorf("providerId %q is not cffn:project:region:name", providerID)
	}
	for i, p := range parts[1:] {
		if !gcpName.MatchString(p) {
			return "", "", "", fmt.Errorf(
				"providerId component %d (%q) is not a valid GCP identifier", i+1, p)
		}
	}
	return parts[1], parts[2], parts[3], nil
}

// fnServerlessDoc is the projection this driver reverse-maps — a superset of
// functionDoc that also carries the execution timeout.
type fnServerlessDoc struct {
	Labels        map[string]string `json:"labels"`
	ServiceConfig struct {
		IngressSettings  string `json:"ingressSettings"`
		Service          string `json:"service"` // backing Cloud Run service path
		MinInstanceCount int    `json:"minInstanceCount"`
		TimeoutSeconds   int    `json:"timeoutSeconds"`
	} `json:"serviceConfig"`
}

// getFnServerless reads functions.get. (doc, status, readable): readable=false on a
// transport error, a non-200 (404 included — this getter does NOT distinguish a
// vanished function from an unreadable one, unchanged), or an unparseable body. The
// HTTP status rides out so a caller can NAME why a read produced nothing (D296).
func (d *Driver) getFnServerless(project, region, name string) (fnServerlessDoc, error) {
	const op = "functions.get"
	status, body, cerr := d.call("GET", d.functionURL(project, region, name), nil)
	if cerr != nil {
		return fnServerlessDoc{}, readTransport(op, cerr)
	}
	if status != http.StatusOK {
		return fnServerlessDoc{}, readHTTP(op, status, gcpErrCode(body))
	}
	var doc fnServerlessDoc
	if json.Unmarshal(body, &doc) != nil {
		return fnServerlessDoc{}, readBody(op, status)
	}
	return doc, nil
}

// fnServerlessPublicURL reads the function's public HTTPS trigger via one
// functions.get (D330 output derivation). It returns the url ONLY for a PUBLIC
// function (serviceConfig.ingressSettings == ALLOW_ALL) — a private function
// returns "" (no url, no-public-output), the exact mirror of AWS lambda's
// functionUrl for a private function. A transport error, non-200 or unparseable
// body is an ERROR (reconcile), never a fabricated absence. (Ingress is the
// primary public control here; an ALLOW_ALL function still lacking an allUsers
// invoker would 403 an anonymous probe, which the reach probe reports as unknown,
// never a false success — so gating on ingress cannot manufacture a false green.)
func (d *Driver) fnServerlessPublicURL(project, region, name string) (string, error) {
	const op = "functions.get"
	status, body, cerr := d.call("GET", d.functionURL(project, region, name), nil)
	if cerr != nil {
		return "", readTransport(op, cerr)
	}
	if status != http.StatusOK {
		return "", readHTTP(op, status, gcpErrCode(body))
	}
	var doc struct {
		URL           string `json:"url"`
		ServiceConfig struct {
			IngressSettings string `json:"ingressSettings"`
			URI             string `json:"uri"`
		} `json:"serviceConfig"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return "", readBody(op, status)
	}
	if doc.ServiceConfig.IngressSettings != "ALLOW_ALL" {
		return "", nil // deliberately private — nothing public to publish
	}
	// prefer the top-level url (the deployed function's public https trigger);
	// fall back to the backing Cloud Run uri if the API omits it.
	if doc.URL != "" {
		return doc.URL, nil
	}
	if doc.ServiceConfig.URI != "" {
		return doc.ServiceConfig.URI, nil
	}
	return "", fmt.Errorf("functions.get returned ALLOW_ALL but no url yet — reconcile")
}

// runFnInvokerState reads the backing Cloud Run service's invokerIamDisabled flag.
// A read that gives no answer names the cause (D296).
func (d *Driver) runFnInvokerState(project, region, name string) (disabled bool, err error) {
	const op = "services.get"
	st, body, cerr := d.call("GET", d.runServiceURL(project, region, name), nil)
	if cerr != nil {
		return false, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return false, readHTTP(op, st, gcpErrCode(body))
	}
	var svc struct {
		InvokerIamDisabled bool `json:"invokerIamDisabled"`
	}
	if json.Unmarshal(body, &svc) != nil {
		return false, readBody(op, st)
	}
	return svc.InvokerIamDisabled, nil
}

// readFnInvokerPolicy reads the backing service's IAM policy for an allUsers
// run.invoker binding (D296 — a policy that gives no answer names why).
func (d *Driver) readFnInvokerPolicy(project, region, name string) (public bool, err error) {
	const op = "services.getIamPolicy"
	st, body, cerr := d.call("GET", fmt.Sprintf("%s:getIamPolicy?options.requestedPolicyVersion=%d",
		d.runServiceURL(project, region, name), iamPolicyVersion), nil)
	if cerr != nil {
		return false, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return false, readHTTP(op, st, gcpErrCode(body))
	}
	var policy struct {
		Bindings []map[string]any `json:"bindings"`
	}
	if json.Unmarshal(body, &policy) != nil {
		return false, readBody(op, st)
	}
	for _, b := range policy.Bindings {
		if b["role"] == "roles/run.invoker" && hasMember(b, "allUsers") {
			return true, nil
		}
	}
	return false, nil
}

// createCloudFunctionFn: POST create (LRO) -> poll -> (if public) grant allUsers
// invoker on the backing Run service. The providerId is knowable BEFORE the response
// (deterministic name), so a lost/garbled outcome (D29) carries it.
func (d *Driver) createCloudFunctionFn(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	req, err := BuildCloudFunctionFnRequest(d.Project, environment, capability,
		attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	region, _ := attrs["location.region"].(string)
	name := FunctionName(d.Project, environment, capability, generation)
	public, _ := attrs["network.publicExposure"].(bool)
	pid := fnServerlessProviderID(d.Project, region, name)
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
		doc, rerr := d.getFnServerless(d.Project, region, name)
		switch {
		case rerr != nil:
			return provider.CreateResult{Status: "unknown",
				Reason: "name conflict, existing function gave no answer — reconcile: " + rerr.Error()}
		case doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
			doc.Labels["groundhold-environment"] != sanitizeLabel(environment):
			return provider.CreateResult{Status: "failed",
				Reason: "a function with this name exists but is not ours (labels do not match)"}
		case doc.ServiceConfig.IngressSettings != "" && doc.ServiceConfig.IngressSettings != wantIngress:
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf(
				"existing function ingress %q does not match desired %q and cloud functions "+
					"update is not wired", doc.ServiceConfig.IngressSettings, wantIngress)}
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
			// a timed-out/transient poll must carry the deterministic handle so a
			// function that may have landed is reconcilable (D29 — the bounded-poll gate).
			if res.Status == "unknown" && res.ProviderID == "" {
				res.ProviderID = pid
			}
			return res
		}
	}

	if public {
		// second gate: grant allUsers invoker on the BACKING Run service. A create
		// that cannot make the function public NEVER reports succeeded.
		doc, rerr := d.getFnServerless(d.Project, region, name)
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

// observeCloudFunctionFn reverse-maps a live function to capability.function.serverless.
func (d *Driver) observeCloudFunctionFn(capability, providerID string) ([]provider.Observation, []string, error) {
	project, region, name, err := splitFnServerlessProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, rerr := d.getFnServerless(project, region, name)
	if rerr != nil {
		return nil, nil, rerr
	}

	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "tls.enforced", Value: true, Derivation: "platform-invariant"},
	}
	obs = append(obs, provider.Observation{Path: "replicas.minimum",
		Value: float64(doc.ServiceConfig.MinInstanceCount), Derivation: "measured"})
	if doc.ServiceConfig.TimeoutSeconds > 0 {
		obs = append(obs, provider.Observation{Path: "timeout.maximum",
			Value: fmt.Sprintf("%ds", doc.ServiceConfig.TimeoutSeconds), Derivation: "measured"})
	}
	var diags []string
	// publicExposure: ingress ALLOW_ALL AND an allUsers invoker on the backing service.
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
			diags = append(diags, "network.publicExposure not observed: the backing "+
				"service path is unparseable or cross-project")
			break
		}
		disabled, svcErr := d.runFnInvokerState(sp, sr, sn)
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
		iamPublic, iamErr := d.readFnInvokerPolicy(sp, sr, sn)
		if iamErr != nil {
			diags = append(diags, "network.publicExposure not observed on the backing "+
				"service IAM policy: "+iamErr.Error())
		} else {
			obs = append(obs, provider.Observation{Path: "network.publicExposure",
				Value: iamPublic, Derivation: "measured"})
		}
	}
	return obs, diags, nil
}

// deleteCloudFunctionFn: ownership pre-read (labels), then DELETE (LRO), then poll.
// 404 is idempotent success; never delete a function that is not ours.
func (d *Driver) deleteCloudFunctionFn(capability, environment, providerID string) provider.CreateResult {
	project, region, name, err := splitFnServerlessProviderID(providerID)
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
	var doc fnServerlessDoc
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
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if status == http.StatusNotFound {
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

// discoverCloudFunctionFn enumerates Cloud Functions (Gen 2) in the region as
// capability.function.serverless — the SAME reverse map observe uses.
func (d *Driver) discoverCloudFunctionFn(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/locations/%s/functions", d.cfBase(), d.Project, region), nil)
	if err != nil {
		return nil, nil, err
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("functions.list: HTTP %d", status)
	}
	var resp struct {
		Functions []struct {
			Name string `json:"name"` // projects/P/locations/R/functions/N
		} `json:"functions"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil, nil, fmt.Errorf("functions.list: unparseable response")
	}
	var out []provider.Discovered
	var diags []string
	for _, f := range resp.Functions {
		parts := strings.Split(f.Name, "/")
		if len(parts) != 6 || parts[4] != "functions" {
			continue
		}
		name := parts[5]
		if !gcpName.MatchString(name) {
			continue
		}
		pid := fnServerlessProviderID(d.Project, region, name)
		obs, odiags, oerr := d.observeCloudFunctionFn("", pid)
		if oerr != nil {
			diags = append(diags, name+": observe: "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.function.serverless",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}
