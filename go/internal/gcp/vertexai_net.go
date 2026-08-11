// GCP Vertex AI inference network shell (D76): the thin, httptest-covered half of
// the GCP capability.ai.inference vocab — the parity twin of aws/bedrock_net.go.
// OBSERVE-FIRST — the D1 verifier rule needs the OBSERVED destination region(s),
// so the load-bearing path is endpoints.get -> the authoritative location parsed
// from the SERVER-RETURNED resource name (the "global" endpoint reduces to the
// ["global"] sentinel, catching the trap). CREATE of an endpoint is wired
// four-valued + ownership labels, but model.access is a MANUAL-GATE (Model Garden
// terms accepted in the console, never an API create): a create that requires
// model.access=true HONEST-REFUSES rather than faking it. DELETE is ownership-gated
// (labels) with an etag pre-read. Vertex AI speaks REST-JSON at a REGIONAL host
// (<region>-aiplatform.googleapis.com/v1); the "global" location uses the
// unprefixed aiplatform.googleapis.com/v1 host.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"groundhold/internal/provider"
)

// vertexAIBaseURLOverride lets tests point the driver at an httptest server
// WITHOUT editing the shared Driver struct (this slice is isolated to new files,
// D76 discipline). The production wiring adds a Driver.VertexAIBaseURL field and
// prefers it here (see the reported driver.go snippet); this package var is the
// isolated-slice equivalent — set it in a test, clear it in a defer.
var vertexAIBaseURLOverride string

// vertexAIBase is the REGIONAL Vertex host. The "global" location has no region
// prefix; every other location gets <location>-aiplatform.googleapis.com. Tests
// override the whole host via vertexAIBaseURLOverride.
func (d *Driver) vertexAIBase(location string) string {
	if vertexAIBaseURLOverride != "" {
		return vertexAIBaseURLOverride
	}
	if location == "global" {
		return "https://aiplatform.googleapis.com/v1"
	}
	return "https://" + location + "-aiplatform.googleapis.com/v1"
}

func (d *Driver) vertexEndpointsURL(project, location string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/endpoints",
		d.vertexAIBase(location), project, location)
}

func (d *Driver) vertexEndpointURL(project, location, id string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/endpoints/%s",
		d.vertexAIBase(location), project, location, id)
}

// vertexEndpoint is the projection of endpoints.get the driver reads. Name is the
// AUTHORITATIVE resource name (its /locations/<LOC>/ segment is the measured
// destination-region surface); DeployedModels feed model.provider (parsed from the
// publisher path) + the model.access proxy; Labels drive the ownership gate; Etag
// closes the delete TOCTOU.
type vertexEndpoint struct {
	Name           string `json:"name"`
	DisplayName    string `json:"displayName"`
	DeployedModels []struct {
		ID    string `json:"id"`
		Model string `json:"model"`
	} `json:"deployedModels"`
	Labels map[string]string `json:"labels"`
	Etag   string            `json:"etag"`
}

func (e vertexEndpoint) deployedModelRefs() []string {
	out := make([]string, 0, len(e.DeployedModels))
	for _, m := range e.DeployedModels {
		out = append(out, m.Model)
	}
	return out
}

func (e vertexEndpoint) ownedBy(capability, environment string) bool {
	return e.Labels["groundhold-capability"] == sanitizeLabel(capability) &&
		e.Labels["groundhold-environment"] == sanitizeLabel(environment)
}

// getVertexEndpoint resolves the endpoint our id names. (found, readable): a 404
// is found=false+readable (an absent endpoint, not an error); a transport error or
// any other non-200 is readable=false (unknown — never a fabricated absence).
func (d *Driver) getVertexEndpoint(project, location, id string) (vertexEndpoint, bool, error) {
	const op = "vertexEndpoint.get"
	st, body, err := d.call("GET", d.vertexEndpointURL(project, location, id), nil)
	if err != nil {
		return vertexEndpoint{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return vertexEndpoint{}, false, nil
	}
	if st != http.StatusOK {
		return vertexEndpoint{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var e vertexEndpoint
	if json.Unmarshal(body, &e) != nil {
		return vertexEndpoint{}, false, readBody(op, st)
	}
	return e, true, nil
}

// createVertexAI provisions a Vertex AI endpoint (endpoints.create), four-valued +
// ownership labels. The MANUAL-GATE crux (parity with Bedrock C2): if the contract
// requires model.access=true, the create must NOT fake it — Model Garden access is
// granted by accepting terms in the console, never an API create, so the create
// HONEST-REFUSES before any mutation. Vertex assigns the endpoint id, so the pid is
// knowable only from the operation response; a transport/5xx before the id lands is
// unknown (reconcile by displayName), never a silent success.
func (d *Driver) createVertexAI(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildVertexAI(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// MANUAL-GATE: model.access cannot be provisioned nor honestly verified through
	// these APIs — refuse rather than fabricate a grant (the honest posture the
	// vocab demands: the driver OBSERVES access, it does not create it).
	if plan.NeedsAccess {
		return provider.CreateResult{Status: "failed",
			Reason: "model access is a manual gate — grant it by accepting terms in the Vertex Model Garden console; " +
				"groundhold observes model.access, it does not provision it (refusing to fake model.access=true)"}
	}

	// create-adoption (D253, extended by D424): an endpoint id is SERVER-assigned and
	// endpoints.create takes no idempotency token, so a blind create on a lost ledger
	// mints a SECOND model-serving endpoint — billed, live, and absent from the ledger.
	// Every recovery path below already names this lookup ("reconcile by displayName via
	// endpoints.list"); doing it FIRST is what makes those messages unnecessary. Exactly
	// one endpoint of ours at our displayName -> BIND it; a foreign one at that name is
	// left alone and a fresh create proceeds; an unreadable list falls through so a
	// genuine first deploy is never blocked.
	if id, loc, found, lerr := d.findVertexEndpointByDisplayName(plan.Region, plan.DisplayName,
		capability, environment); lerr == nil && found {
		return provider.CreateResult{ProviderID: vertexProviderID(d.Project, loc, id), Status: "succeeded"}
	}

	body := map[string]any{
		"displayName": plan.DisplayName,
		"labels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
	}
	st, resp, err := d.call("POST", d.vertexEndpointsURL(d.Project, plan.Region), body)
	switch {
	case err != nil:
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("endpoints.create outcome unknown (may have landed) — reconcile by displayName %q via endpoints.list: %v", plan.DisplayName, err)}
	case st == http.StatusConflict:
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("endpoints.create conflict on displayName %q — reconcile ownership via endpoints.list", plan.DisplayName)}
	case st >= 500:
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("endpoints.create HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	case st >= 400:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("endpoints.create HTTP %d: %s", st, mutDetail(resp))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(resp, &op) != nil || op.Name == "" {
		// a 2xx create MUST return an operation; an empty name is a truncated body —
		// the endpoint may have landed (D29), reconcile by displayName.
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("endpoints.create returned no operation — reconcile by displayName %q via endpoints.list", plan.DisplayName)}
	}
	res, epName := d.pollVertexOperation(plan.Region, op.Name)
	if res.Status != "succeeded" {
		return res
	}
	id := endpointIDFromName(epName)
	if id == "" || !vertexEndpointIDOK.MatchString(id) {
		return provider.CreateResult{OperationID: op.Name, Status: "unknown",
			Reason: fmt.Sprintf("endpoints.create operation done but returned no usable endpoint id — reconcile by displayName %q via endpoints.list", plan.DisplayName)}
	}
	// bind using the SERVER-RETURNED location, never a fabricated one.
	loc := locationFromEndpointName(epName)
	if loc == "" {
		loc = plan.Region
	}
	return provider.CreateResult{ProviderID: vertexProviderID(d.Project, loc, id), Status: "succeeded"}
}

// pollVertexOperation polls a Vertex AI long-running operation. DONE with an error
// field is a failure; a lost response is UNKNOWN (D29). Returns the created/target
// resource name from the operation's response so the caller can recover the
// server-assigned endpoint id + location.
func (d *Driver) pollVertexOperation(location, opName string) (provider.CreateResult, string) {
	if opName == "" {
		return provider.CreateResult{Status: "succeeded"}, ""
	}
	deadline := d.Now().Add(d.PollTimeout)
	for {
		status, body, err := d.call("GET", d.vertexAIBase(location)+"/"+opName, nil)
		if err == nil && status == http.StatusOK {
			var op struct {
				Done  bool `json:"done"`
				Error *struct {
					Message string `json:"message"`
				} `json:"error"`
				Response struct {
					Name string `json:"name"`
				} `json:"response"`
			}
			if json.Unmarshal(body, &op) == nil && op.Done {
				if op.Error != nil {
					return provider.CreateResult{OperationID: opName,
						Status: "failed", Reason: "operation failed: " + op.Error.Message}, ""
				}
				return provider.CreateResult{OperationID: opName, Status: "succeeded"}, op.Response.Name
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{OperationID: opName, Status: "unknown",
				Reason: "operation still running at poll timeout — reconcile"}, ""
		}
		time.Sleep(d.PollInterval)
	}
}

// observeVertexAI reverse-maps a live Vertex endpoint to capability.ai.inference.
// The load-bearing observation is inference.destinationRegions — the region parsed
// from the SERVER-RETURNED resource name (the authoritative surface the subset-of
// contract asserts against; a "global" endpoint reduces to ["global"], NOT an EU
// region, so the trap becomes a `violated` verdict DETERMINISTICALLY).
// model.provider is parsed from the deployed publisher model. model.access is a
// MANUAL-GATE: OBSERVED from a gated model actually being DEPLOYED (you cannot
// deploy a gated family without the grant), never a fabricated constant, with a
// diagnostic that it lives behind the Model Garden console. An unreadable endpoint
// is unknown (an error); a not-found endpoint is nothing-to-observe.
func (d *Driver) observeVertexAI(capability, providerID string) ([]provider.Observation, []string, error) {
	project, location, id, err := splitVertexProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	e, found, rerr := d.getVertexEndpoint(project, location, id)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"endpoint not found — bound resource is gone (will re-create)"}, nil
	}

	// the destination region is MEASURED from the server-returned resource name,
	// never the providerId's claimed location — a stale binding cannot pass off a
	// wrong region as observed truth.
	measuredLoc := locationFromEndpointName(e.Name)
	if measuredLoc == "" {
		measuredLoc = location
	}
	destRegions := destinationRegionsFromLocation(measuredLoc)

	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: measuredLoc, Derivation: "measured"},
		{Path: "inference.destinationRegions", Value: destRegions, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	if measuredLoc == "global" {
		diags = append(diags, "inference.destinationRegions is [global] — the Vertex global endpoint routes to ANY available region; "+
			"it is NOT a bounded EU set, so a residency subset-of an EU allowlist will be violated (the trap, caught deterministically)")
	}
	refs := e.deployedModelRefs()
	if prov := providerFromDeployedModels(refs); prov != "" {
		obs = append(obs, provider.Observation{Path: "model.provider", Value: prov, Derivation: "measured"})
	} else {
		diags = append(diags, "model.provider not derivable from the deployed models (no publisher model, or none deployed) — omitted rather than fabricated")
	}
	// model.access — a MANUAL-GATE. A gated model actually DEPLOYED on the endpoint
	// is the strongest signal these read-only APIs expose (you cannot deploy a gated
	// family without the grant); it is OBSERVED (reflects real endpoint state, never
	// a blind constant). The diagnostic keeps it honest: the grant lives behind the
	// Model Garden console, groundhold observes it, never provisions.
	obs = append(obs, provider.Observation{
		Path: "model.access", Value: len(refs) > 0, Derivation: "measured"})
	diags = append(diags,
		"model.access is a manual-gate — Vertex Model Garden access is granted by accepting terms in the console, never an API create; "+
			"groundhold OBSERVES it (from a model being deployed on the endpoint), it does NOT provision it")
	return obs, diags, nil
}

// deleteVertexAI removes a Vertex endpoint groundhold created, ownership-gated by
// labels with an etag pre-read that closes the TOCTOU between the ownership check
// and the delete. Idempotent on already-gone (404); a transport/5xx is unknown WITH
// the pid (reconcile), never a claimed success.
func (d *Driver) deleteVertexAI(capability, environment, providerID string) provider.CreateResult {
	project, location, id, err := splitVertexProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	e, found, rerr := d.getVertexEndpoint(project, location, id)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	if !e.ownedBy(capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "endpoint labels do not match — refusing to delete a resource that is not ours"}
	}
	// D995: Vertex endpoints.delete has NO etag parameter — it 400s any `?etag=`
	// ("Unknown name 'etag': Cannot bind query parameter"), so the old ifMatch made
	// EVERY delete of a present endpoint fail (an endpoint always carries an etag).
	// The ownership pre-read above (labels via ownedBy) is the guard the API gives us;
	// there is no server-side If-Match for this resource, so we delete without one.
	delURL := d.vertexEndpointURL(project, location, id)
	st, body, err := d.call("DELETE", delURL, nil)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("endpoints.delete outcome unknown: %v", err)}
	case st == http.StatusConflict || st == http.StatusPreconditionFailed:
		return provider.CreateResult{Status: "failed",
			Reason: "endpoint changed between the pre-delete read and the delete (etag conflict) — re-observe and re-seal"}
	case st == http.StatusNotFound:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("endpoints.delete HTTP %d (server error) — reconcile", st)}
	case st >= 400:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("endpoints.delete HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		// a 2xx delete returning no operation is a truncated body — the delete may
		// have landed (D29), never a synchronous success.
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "endpoints.delete returned no operation — reconcile"}
	}
	res, _ := d.pollVertexOperation(location, op.Name)
	if res.Status == "succeeded" {
		res.ProviderID = providerID
	}
	return res
}

// discoverVertexAI enumerates a region's endpoints as capability.ai.inference — so
// `discover --provider gcp` surfaces the endpoints whose destination region must be
// checked against the residency allowlist (including a "global" endpoint). Reuses
// observeVertexAI (two-step: endpoints.list -> per-endpoint reverse map).
func (d *Driver) discoverVertexAI(region string) ([]provider.Discovered, []string, error) {
	loc := region
	if loc == "" {
		// endpoints are listed per-location; with no region scope, sweep the
		// aggregated location "-" (Vertex supports the wildcard list).
		loc = "-"
	}
	listURL := fmt.Sprintf("%s/projects/%s/locations/%s/endpoints",
		d.vertexAIBase(regionForHost(region)), d.Project, loc)
	st, body, err := d.call("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("vertex endpoints.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("vertex endpoints.list: HTTP %d", st)
	}
	var out struct {
		Endpoints []struct {
			Name string `json:"name"`
		} `json:"endpoints"`
	}
	if json.Unmarshal(body, &out) != nil {
		return nil, nil, readBody("endpoints.list", st)
	}
	var found []provider.Discovered
	var diags []string
	for _, ep := range out.Endpoints {
		epLoc := locationFromEndpointName(ep.Name)
		epID := endpointIDFromName(ep.Name)
		if epLoc == "" || epID == "" {
			continue
		}
		if region != "" && epLoc != region {
			continue // another location — not this sweep
		}
		pid := vertexProviderID(d.Project, epLoc, epID)
		obs, od, oerr := d.observeVertexAI("", pid)
		if oerr != nil {
			diags = append(diags, epID+": "+oerr.Error())
			continue
		}
		for _, dg := range od {
			diags = append(diags, epID+": "+dg)
		}
		found = append(found, provider.Discovered{
			ProviderID: pid, ResourceType: "capability.ai.inference", Observations: provider.WithoutAbsence(obs)})
	}
	return found, diags, nil
}

// regionForHost picks the host region for a list call: an explicit region uses its
// regional host; an unscoped sweep uses "global" (the unprefixed aiplatform host,
// which accepts the locations/- wildcard).
func regionForHost(region string) string {
	if region == "" {
		return "global"
	}
	return region
}

// findVertexEndpointByDisplayName lists the region's endpoints and returns the one whose
// displayName matches ours AND whose labels prove it is ours. It VERIFIES the labels on
// what comes back rather than trusting the name alone — a foreign endpoint may carry any
// displayName. Any transport/HTTP/parse failure returns an error and the caller falls
// through to a normal create. Mirrors findVpcByTags (D253) and apigwByName (D410).
func (d *Driver) findVertexEndpointByDisplayName(region, displayName, capability, environment string) (id, loc string, found bool, err error) {
	// D870: EVERY page. This is the read-before-write guard (D700/D804), and the comment
	// at its caller says what a miss costs: "a blind create on a lost ledger mints a
	// SECOND model-serving endpoint — billed, live, and absent from the ledger". Vertex
	// pages this listing, so past the first page the guard was not weak, it was absent —
	// and unlike a false claim, this one MUTATES.
	type vertexEndpoint struct {
		Name        string            `json:"name"`
		DisplayName string            `json:"displayName"`
		Labels      map[string]string `json:"labels"`
	}
	var endpoints []vertexEndpoint
	if perr := d.listAllPages("endpoints.list", d.vertexEndpointsURL(d.Project, region),
		func(body []byte) error {
			var page struct {
				Endpoints []vertexEndpoint `json:"endpoints"`
			}
			if json.Unmarshal(body, &page) != nil {
				return readBody("endpoints.list", http.StatusOK)
			}
			endpoints = append(endpoints, page.Endpoints...)
			return nil
		}); perr != nil {
		return "", "", false, perr
	}
	for _, ep := range endpoints {
		if ep.DisplayName != displayName {
			continue
		}
		if ep.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
			ep.Labels["groundhold-environment"] != sanitizeLabel(environment) {
			continue // at our name but not ours — never adopt it
		}
		epID := endpointIDFromName(ep.Name)
		if epID == "" || !vertexEndpointIDOK.MatchString(epID) {
			continue
		}
		l := locationFromEndpointName(ep.Name)
		if l == "" {
			l = region
		}
		return epID, l, true, nil
	}
	return "", "", false, nil
}
