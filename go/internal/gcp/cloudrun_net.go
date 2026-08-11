// Cloud Run network shell + security (D76 slice 3): the thin, httptest-covered
// half of the driver's second service. Everything semantic is in the pure
// cloudrun.go builder; this is auth/HTTP/operation-poll/IAM. Security posture
// mirrors Cloud SQL and adds the Cloud-Run-specific gates independent reviewers called
// out: a service-prefixed providerId with its own charset-validated parser,
// ownership labels checked before every mutate/delete, and public exposure
// that is TWO gates (ingress + an allUsers invoker binding) — a create that
// could not make the service public NEVER reports succeeded (it would lie
// about the exposure the contract exists to satisfy).
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func (d *Driver) runBase() string {
	if d.RunBaseURL != "" {
		return d.RunBaseURL
	}
	return runBaseURL
}

// sameProject refuses a providerId whose project component differs from the
// driver's pinned project (D76 review): a forged or stale binding must not
// redirect a read/mutate into another project while the D75 preflight was
// checked against the plan's pinned project. Applies to every service.
func (d *Driver) sameProject(project string) error {
	// The guard protects a PINNED project (apply/converge, where the D75
	// preflight was checked against it) from a forged binding redirecting the
	// mutation elsewhere. Read-only paths (observe/discover) run with no pinned
	// project — the providerId's own project is the authority there, and there
	// is no pinned identity to redirect away from — so an empty pin is a no-op,
	// never a refusal. (Found live: observe of any gcp resource failed here.)
	if d.Project == "" {
		return nil
	}
	if project != d.Project {
		return fmt.Errorf("providerId project %q does not match the pinned "+
			"project %q — refusing a cross-project operation", project, d.Project)
	}
	return nil
}

// runProviderID is service-PREFIXED (D76): the token qualifies the identity so
// a forged or stale binding cannot route a Cloud SQL id into run.googleapis
// paths (or vice-versa). Never the slash-form REST name — that embeds '/', the
// char class D73's boundary keeps out of stored identities.
func runProviderID(project, region, name string) string {
	return "cloudrun:" + project + ":" + region + ":" + name
}

// splitRunProviderID validates every component BEFORE it is interpolated into
// a REST path (D73 confused-deputy boundary, for the 4-part slash-free form).
// The service token is matched by exact string, never interpolated.
func splitRunProviderID(providerID string) (project, region, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "cloudrun" {
		return "", "", "", fmt.Errorf(
			"providerId %q is not cloudrun:project:region:name", providerID)
	}
	for i, p := range parts[1:] {
		if !gcpName.MatchString(p) {
			return "", "", "", fmt.Errorf(
				"providerId component %d (%q) is not a valid GCP identifier "+
					"— refusing to interpolate it into an API path", i+1, p)
		}
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) runServiceURL(project, region, name string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/services/%s",
		d.runBase(), project, region, name)
}

// createCloudRun: build -> POST -> poll -> (if public) grant allUsers invoker.
func (d *Driver) createCloudRun(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	req, err := BuildCloudRunCreateRequest(d.Project, environment, capability,
		attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	name := ServiceName(d.Project, environment, capability, generation)
	region, _ := attrs["location.region"].(string)
	public, _ := attrs["network.publicExposure"].(bool)
	// the service name is deterministic, so the providerId is knowable BEFORE the
	// create response — a lost/garbled outcome (D29) must carry it so a service
	// that may have landed is never orphaned (handle never lost).
	pid := runProviderID(d.Project, region, name)
	wantIngress := "INGRESS_TRAFFIC_INTERNAL_ONLY"
	if public {
		wantIngress = "INGRESS_TRAFFIC_ALL"
	}
	// tests override RunBaseURL; rebuild against it
	req.URL = fmt.Sprintf("%s/projects/%s/locations/%s/services?serviceId=%s",
		d.runBase(), d.Project, region, name)

	status, body, err := d.call(req.Method, req.URL, req.Body)
	if err != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown: %v", err)}
	}
	switch {
	case status == http.StatusConflict:
		// 409: continue ONLY if the existing service is ours AND its live
		// exposure already matches the desired contract — Cloud Run update is
		// not wired, so a mismatch cannot be repaired here and reporting
		// success would lie about exposure (ingress lived only in the
		// rejected POST body).
		ours, ingress, found, rerr := d.runGetService(d.Project, region, name, capability, environment)
		switch {
		case rerr != nil:
			return provider.CreateResult{Status: "unknown",
				Reason: "name conflict, existing service gave no answer — reconcile: " + rerr.Error()}
		case !found:
			return provider.CreateResult{Status: "unknown",
				Reason: "name conflict, but the conflicting service was gone on the follow-up read — reconcile"}
		case !ours:
			return provider.CreateResult{Status: "failed",
				Reason: "a service with this name exists but is not ours " +
					"(labels do not match)"}
		case ingress != wantIngress:
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf(
				"existing service ingress %q does not match desired exposure "+
					"(%q) and cloud run update is not wired", ingress, wantIngress)}
		}
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
			// a 2xx create MUST return an operation; an empty name means a
			// truncated/lost body — the mutation may have landed (D29).
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "create response carried no operation — reconcile"}
		}
		if res := d.pollRunOperation(op.Name); res.Status != "succeeded" {
			return res
		}
	}

	// Public exposure is the SECOND gate: without an allUsers invoker binding
	// the service 403s the world while the contract says public. A grant that
	// fails (e.g. Domain-Restricted-Sharing) makes the create a PARTIAL
	// mutation — report failed, never succeeded, and never observe public. A
	// LOST setIamPolicy response is unknown (D29), not failed.
	if public {
		if unknown, err := d.setPublicInvoker(d.Project, region, name); err != nil {
			st := "failed"
			if unknown {
				st = "unknown"
			}
			return provider.CreateResult{ProviderID: pid, Status: st, Reason: err.Error()}
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// pollRunOperation polls a Cloud Run v2 long-running operation. DONE with an
// error field is a failure; a lost response is UNKNOWN (D29).
func (d *Driver) pollRunOperation(opName string) provider.CreateResult {
	if opName == "" {
		return provider.CreateResult{Status: "succeeded"} // synchronous done
	}
	deadline := d.Now().Add(d.PollTimeout)
	for {
		status, body, err := d.call("GET", d.runBase()+"/"+opName, nil)
		if err == nil && status == http.StatusOK {
			var op struct {
				Done  bool `json:"done"`
				Error *struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &op) == nil && op.Done {
				if op.Error != nil {
					return provider.CreateResult{OperationID: opName,
						Status: "failed", Reason: "operation failed: " + op.Error.Message}
				}
				return provider.CreateResult{OperationID: opName, Status: "succeeded"}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{OperationID: opName, Status: "unknown",
				Reason: "operation still running at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

// setPublicInvoker grants allUsers roles/run.invoker via a read-modify-write on
// the IAM policy (etag preserved, append-only — a fresh policy would strip
// every existing binding, a destructive write hiding inside "make public"),
// then re-reads to CONFIRM the binding took. Domain-Restricted-Sharing is
// surfaced by name, distinct from a permission 403, so converge does not chase
// a grant that org policy forbids.
const iamPolicyVersion = 3

// getRunPolicyForWrite reads a policy at version 3 — REQUIRED to see and
// preserve conditional bindings; a v1 read silently strips conditions and
// writing that back is a destructive overwrite. An empty etag means no CAS,
// so a setIamPolicy would unconditionally replace the WHOLE policy — refuse
// rather than risk stripping every existing binding (review MED).
func (d *Driver) getRunPolicyForWrite(base string) ([]map[string]any, string, error) {
	// Cloud Run v2 getIamPolicy is a GET with the policy version as a query
	// param — a POST hits no route and returns an HTML 404 (found live: the
	// fake httptest server accepted any method, only a real apply caught it).
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s:getIamPolicy?options.requestedPolicyVersion=%d", base, iamPolicyVersion), nil)
	if err != nil {
		return nil, "", fmt.Errorf("getIamPolicy: %v", err)
	}
	if status != http.StatusOK {
		return nil, "", fmt.Errorf("getIamPolicy HTTP %d: %s", status, mutDetail(body))
	}
	var policy struct {
		Bindings []map[string]any `json:"bindings"`
		Etag     string           `json:"etag"`
	}
	if err := json.Unmarshal(body, &policy); err != nil {
		return nil, "", fmt.Errorf("getIamPolicy: unparseable policy")
	}
	if policy.Etag == "" {
		return nil, "", fmt.Errorf("getIamPolicy: no etag — refusing a " +
			"CAS-less write that would overwrite the whole policy")
	}
	return policy.Bindings, policy.Etag, nil
}

// setPublicInvoker grants allUsers roles/run.invoker via a version-3 read-
// modify-write (etag preserved, append-only). Returns unknown=true only when
// the MUTATING setIamPolicy call's response was lost (D29: never "failed").
func (d *Driver) setPublicInvoker(project, region, name string) (unknown bool, err error) {
	base := d.runServiceURL(project, region, name)
	bindings, etag, err := d.getRunPolicyForWrite(base)
	if err != nil {
		return false, fmt.Errorf("public exposure: %v", err) // reads are definitive
	}
	bindings = appendMember(bindings, "roles/run.invoker", "allUsers")

	status, body, cerr := d.call("POST", base+":setIamPolicy",
		map[string]any{"policy": map[string]any{
			"version": iamPolicyVersion, "bindings": bindings, "etag": etag}})
	if cerr != nil {
		return true, fmt.Errorf("public exposure: setIamPolicy outcome "+
			"unknown — reconcile via getIamPolicy: %v", cerr)
	}
	if status != http.StatusOK {
		if isDomainRestricted(body) {
			return false, fmt.Errorf("public exposure blocked by domain-"+
				"restricted-sharing (an org-policy decision, not a missing "+
				"permission): %s", mutDetail(body))
		}
		if status >= 500 {
			// a 5xx does NOT prove the grant did not land (D29) — the binding
			// may be live; unknown routes to reconcile, never a false failed.
			return true, fmt.Errorf("public exposure: setIamPolicy HTTP %d "+
				"(server error — the grant may have landed, reconcile): %s",
				status, mutDetail(body))
		}
		if provider.Classify(status, gcpErrCode(body), nil).Unknown() {
			// D237: a throttle (429) or live 403 does not prove the grant failed.
			return true, fmt.Errorf("public exposure: setIamPolicy HTTP %d "+
				"(transient/denied — the grant may have landed, reconcile): %s",
				status, mutDetail(body))
		}
		return false, fmt.Errorf("public exposure: setIamPolicy HTTP %d: %s",
			status, mutDetail(body))
	}
	pub, cerr := d.confirmPublic(project, region, name)
	switch {
	case pub:
		return false, nil
	case cerr != nil:
		// setIamPolicy returned 200 — the grant may well be live; a failed
		// CONFIRM read (transport, 429, stale replica) is not proof it did not
		// take. Unknown, not failed (D29): let reconcile settle it.
		return true, fmt.Errorf("public exposure: setIamPolicy returned 200 but "+
			"the binding could not be confirmed (%v) — reconcile", cerr)
	default:
		return false, fmt.Errorf("public exposure: allUsers invoker binding " +
			"did not take (org policy or a conditional binding may interfere)")
	}
}

// appendMember adds member ONLY to an UNCONDITIONAL binding for role — never
// to a conditional one (that would create condition-scoped access the receipt
// reports failed and observe reports absent, a silent residual grant), else
// appends a fresh unconditional binding. Shared by every service's public-
// exposure grant (Cloud Run run.invoker, GCS storage.objectViewer).
func appendMember(bindings []map[string]any, role, member string) []map[string]any {
	for _, b := range bindings {
		if _, cond := b["condition"]; cond {
			continue
		}
		if b["role"] == role {
			if hasMember(b, member) {
				return bindings // already granted, idempotent
			}
			members, _ := b["members"].([]any)
			b["members"] = append(members, member)
			return bindings
		}
	}
	return append(bindings, map[string]any{
		"role": role, "members": []any{member}})
}

// removeMember drops an UNCONDITIONAL member from a role's binding (the revoke twin
// of appendMember, for an in-place exposure update that turns a public resource
// private). Conditional bindings are left untouched — they never granted the member
// unconditionally (see hasMember). A binding left with no members is dropped so the
// policy does not carry an empty role.
func removeMember(bindings []map[string]any, role, member string) []map[string]any {
	out := bindings[:0]
	for _, b := range bindings {
		_, cond := b["condition"]
		if !cond && b["role"] == role {
			members, _ := b["members"].([]any)
			kept := make([]any, 0, len(members))
			for _, m := range members {
				if m != member {
					kept = append(kept, m)
				}
			}
			if len(kept) == 0 {
				continue // drop an emptied binding
			}
			b["members"] = kept
		}
		out = append(out, b)
	}
	return out
}

// hasMember: UNCONDITIONAL only — a binding carrying a condition does NOT grant
// the member unconditionally, so it is never treated as making a resource
// public. Shared confirm/observe helper across services.
func hasMember(b map[string]any, member string) bool {
	if _, hasCond := b["condition"]; hasCond {
		return false
	}
	members, _ := b["members"].([]any)
	for _, m := range members {
		if m == member {
			return true
		}
	}
	return false
}

// confirmPublic is THREE-valued: (public, why-not). A policy that gave no answer is
// NOT "not public" — collapsing them turns a 200 grant + a failed read into a
// false "failed" (adversarial review). Only a readable policy without the binding is
// a genuine "did not take".
func (d *Driver) confirmPublic(project, region, name string) (public bool, err error) {
	bindings, perr := d.readRunPolicy(d.runServiceURL(project, region, name))
	if perr != nil {
		return false, perr
	}
	for _, b := range bindings {
		if b["role"] == "roles/run.invoker" && hasMember(b, "allUsers") {
			return true, nil
		}
	}
	return false, nil
}

// readRunPolicy reads a policy at version 3 for confirmation/observation; a
// transport error, non-200, or UNPARSEABLE body returns an error — never a
// default-safe false.
func (d *Driver) readRunPolicy(base string) ([]map[string]any, error) {
	const op = "getIamPolicy"
	status, body, cerr := d.call("GET", fmt.Sprintf(
		"%s:getIamPolicy?options.requestedPolicyVersion=%d", base, iamPolicyVersion), nil)
	if cerr != nil {
		return nil, readTransport(op, cerr)
	}
	if status != http.StatusOK {
		return nil, readHTTP(op, status, gcpErrCode(body))
	}
	var policy struct {
		Bindings []map[string]any `json:"bindings"`
	}
	if json.Unmarshal(body, &policy) != nil {
		return nil, readBody(op, status)
	}
	return policy.Bindings, nil
}

func isDomainRestricted(body []byte) bool {
	s := strings.ToLower(string(body))
	return strings.Contains(s, "domain") &&
		(strings.Contains(s, "restrict") || strings.Contains(s, "allowedpolicymemberdomains"))
}

// runGetService GETs a service and returns ownership, ingress, existence, and
// why a read failed — so a transient failure or malformed body names itself
// rather than becoming a false "not ours" (which would record a definitive
// wrong ownership claim about our own resource). A 404 is an authoritative
// absence: found=false with a nil error.
func (d *Driver) runGetService(project, region, name, capability, environment string) (ours bool, ingress string, found bool, err error) {
	const op = "services.get"
	status, body, cerr := d.call("GET", d.runServiceURL(project, region, name), nil)
	if cerr != nil {
		return false, "", false, readTransport(op, cerr)
	}
	if status == http.StatusNotFound {
		return false, "", false, nil
	}
	if status != http.StatusOK {
		return false, "", false, readHTTP(op, status, gcpErrCode(body))
	}
	var svc struct {
		Ingress string            `json:"ingress"`
		Labels  map[string]string `json:"labels"`
	}
	if json.Unmarshal(body, &svc) != nil {
		return false, "", false, readBody(op, status)
	}
	ours = svc.Labels["groundhold-capability"] == sanitizeLabel(capability) &&
		svc.Labels["groundhold-environment"] == sanitizeLabel(environment)
	return ours, svc.Ingress, true, nil
}

// deleteCloudRun: ownership pre-read, then DELETE, then poll. 404 is idempotent
// success. Never delete a service that is not ours.
func (d *Driver) deleteCloudRun(capability, environment, providerID string) provider.CreateResult {
	project, region, name, err := splitRunProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	status, body, err := d.call("GET", d.runServiceURL(project, region, name), nil)
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
	var svc struct {
		Labels map[string]string `json:"labels"`
		Etag   string            `json:"etag"`
	}
	if err := json.Unmarshal(body, &svc); err != nil {
		// a truncated/garbled read could leave labels half-populated — refuse on
		// ambiguity rather than delete a resource we cannot prove is ours.
		return provider.CreateResult{Status: "unknown",
			Reason: "pre-delete read unparseable — refusing an ambiguous delete"}
	}
	if svc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
		svc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "service labels do not match — refusing to delete a " +
				"resource that is not ours"}
	}
	// ifMatch via the pre-read etag closes the TOCTOU between the ownership
	// check and the delete: a concurrent relabel/replace lands as a 409/412,
	// never a blind delete of a resource that just changed hands (Cloud Run v2
	// delete supports the etag query param — verified against the discovery doc).
	delURL := d.runServiceURL(project, region, name)
	if svc.Etag != "" {
		delURL += "?etag=" + url.QueryEscape(svc.Etag)
	}
	status, respBody, err := d.call("DELETE", delURL, nil)
	if err != nil {
		// a lost delete response (D29) — keep the pinned handle so reconcile can
		// conclude a delete that may have landed, never drop it.
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if status == http.StatusConflict || status == http.StatusPreconditionFailed {
		return provider.CreateResult{Status: "failed",
			Reason: "service changed between the pre-delete read and the delete " +
				"(etag conflict) — re-observe and re-seal"}
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
		// a 2xx delete MUST return an operation; an empty name is a truncated
		// body — the delete may have landed (D29), never a synchronous success.
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "delete response carried no operation — reconcile"}
	}
	res := d.pollRunOperation(op.Name)
	if res.Status == "succeeded" {
		res.ProviderID = providerID
	}
	return res
}

// observeCloudRun reverse-maps a live service. publicExposure is TRUE only
// when ingress is ALL and an unconditional allUsers invoker binding exists —
// both surfaces, never a default. An unreadable IAM policy emits a diagnostic
// and NOTHING for publicExposure (never default-to-safe).
func (d *Driver) observeCloudRun(capability, providerID string) ([]provider.Observation, []string, error) {
	project, region, name, err := splitRunProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	status, body, err := d.call("GET", d.runServiceURL(project, region, name), nil)
	if err != nil {
		return nil, nil, err
	}
	// F-LC3 (D519): a 404 here is a READABLE absence, not a failure to read.
	// Folded into the generic error it made the binding block forever on
	// unknown instead of re-creating; the contract reserves a marker for it.
	if status == http.StatusNotFound {
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"bound resource is gone (will re-create)"}, nil
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("services.get: HTTP %d", status)
	}
	var svc struct {
		Ingress             string `json:"ingress"`
		InvokerIamDisabled  bool   `json:"invokerIamDisabled"`
		BinaryAuthorization struct {
			UseDefault bool `json:"useDefault"`
		} `json:"binaryAuthorization"`
		Template struct {
			Scaling struct {
				MinInstanceCount int `json:"minInstanceCount"`
			} `json:"scaling"`
		} `json:"template"`
	}
	if err := json.Unmarshal(body, &svc); err != nil {
		return nil, nil, fmt.Errorf("services.get: unparseable service document")
	}

	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
	}
	var diags []string
	obs = append(obs, provider.Observation{Path: "location.region",
		Value: region, Derivation: "measured"})
	obs = append(obs, provider.Observation{Path: "service.managed",
		Value: true, Derivation: "measured"})
	obs = append(obs, provider.Observation{Path: "availability.class",
		Value: "regional", Derivation: "platform-invariant"})
	if svc.Template.Scaling.MinInstanceCount > 0 {
		obs = append(obs, provider.Observation{Path: "replicas.minimum",
			Value: float64(svc.Template.Scaling.MinInstanceCount), Derivation: "measured"})
	}
	// image.signedProvenance rides on binaryAuthorization.useDefault. This is
	// config-intent, NOT measured: it proves the service opts into the project's
	// default Binary Authorization policy, not that the policy actually enforces
	// signed provenance (that lives in org policy, invisible here). Without this
	// a contract requiring signedProvenance could never converge (write-only).
	obs = append(obs, provider.Observation{Path: "image.signedProvenance",
		Value: svc.BinaryAuthorization.UseDefault, Derivation: "config-intent"})
	// publicExposure has TWO reachability paths Cloud Run documents: an allUsers
	// invoker IAM binding, OR invokerIamDisabled=true (the invoker IAM check is
	// off, so anyone who can reach the ingress can invoke). Either, with ingress
	// ALL, is public. A KNOWN ingress is required; when the IAM binding is the
	// deciding factor a readable policy is required too — an unread surface emits
	// a diagnostic and NOTHING, never a default-safe "false".
	knownIngress := svc.Ingress == "INGRESS_TRAFFIC_ALL" ||
		svc.Ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY" ||
		svc.Ingress == "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
	ingressAll := svc.Ingress == "INGRESS_TRAFFIC_ALL"
	switch {
	case !knownIngress:
		diags = append(diags, "network.publicExposure not observed: the "+
			"service ingress value is absent or unknown")
	case svc.InvokerIamDisabled:
		// the invoker IAM check is disabled — a public mode independent of any
		// allUsers binding; ingress alone decides reachability.
		obs = append(obs, provider.Observation{Path: "network.publicExposure",
			Value: ingressAll, Derivation: "measured"})
	default:
		iamPublic, iamErr := d.readInvoker(project, region, name)
		if iamErr != nil {
			diags = append(diags, "network.publicExposure not observed: "+iamErr.Error())
		} else {
			obs = append(obs, provider.Observation{Path: "network.publicExposure",
				Value: ingressAll && iamPublic, Derivation: "measured"})
		}
	}
	return obs, diags, nil
}

// runServiceURI reads the service's server-assigned public *.run.app uri via one
// services.get (D330 output derivation). A transport error, non-200, unparseable
// body, or an empty uri is an ERROR (reconcile) — never a default-safe empty,
// mirroring AWS cloudfront's domainName derivation.
func (d *Driver) runServiceURI(project, region, name string) (string, error) {
	const op = "services.get"
	status, body, cerr := d.call("GET", d.runServiceURL(project, region, name), nil)
	if cerr != nil {
		return "", readTransport(op, cerr)
	}
	if status != http.StatusOK {
		return "", readHTTP(op, status, gcpErrCode(body))
	}
	var svc struct {
		URI string `json:"uri"`
	}
	if json.Unmarshal(body, &svc) != nil {
		return "", readBody(op, status)
	}
	if svc.URI == "" {
		return "", fmt.Errorf("services.get returned no uri yet — reconcile")
	}
	return svc.URI, nil
}

func (d *Driver) readInvoker(project, region, name string) (public bool, err error) {
	bindings, perr := d.readRunPolicy(d.runServiceURL(project, region, name))
	if perr != nil {
		return false, perr
	}
	for _, b := range bindings {
		if b["role"] == "roles/run.invoker" && hasMember(b, "allUsers") {
			return true, nil
		}
	}
	return false, nil
}

// sanitizeLabel bounds a value to lowercase alnum + '-' (nameOK replaces every
// other char, including '.' and '_'), <=63 — applied IDENTICALLY on the write
// and ownership-check sides so the driver never locks itself out of its own
// resources. It is intentionally lossy; ownership is a coarse check, and the
// service name's stable hash suffix (not sanitized here) carries uniqueness.
func sanitizeLabel(s string) string {
	s = strings.ToLower(s)
	s = nameOK.ReplaceAllString(s, "-")
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}
