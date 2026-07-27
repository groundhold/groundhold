// AWS Bedrock inference network shell (D150): the SigV4-signed, REST-JSON half of
// the AWS capability.ai.inference vocab. OBSERVE-FIRST — the D1 verifier rule needs
// the OBSERVED destination regions, so the load-bearing path is GetInferenceProfile
// -> the authoritative routing set parsed from models[].modelArn. CREATE of an
// APPLICATION inference profile is wired four-valued + ownership tags, but
// model.access is a MANUAL-GATE (granted by a Bedrock console use-case form, never an
// API create): a create that requires model.access=true HONEST-REFUSES rather than
// faking it. DELETE is ownership-gated and honest-refuses SYSTEM (AWS-managed)
// profiles. Bedrock control-plane speaks REST-JSON at bedrock.<region>.amazonaws.com;
// SigV4 service "bedrock". The runtime endpoint (bedrock-runtime.*) is SEPARATE — we
// do NOT call it.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"groundhold/internal/provider"
)

const bedrockProfilesPath = "/inference-profiles"

func (d *Driver) bedrockBase(region string) string {
	if d.BedrockBaseURL != "" {
		return d.BedrockBaseURL
	}
	return "https://bedrock." + region + ".amazonaws.com"
}

// bedrockDo is the REST-JSON caller for the Bedrock control plane (SigV4 service
// "bedrock"). Tests override the endpoint via BedrockBaseURL.
func (d *Driver) bedrockDo(method, region, path string, body []byte) (int, []byte, error) {
	return d.doSigned(method, d.bedrockBase(region)+path, "bedrock", region,
		map[string]string{"Content-Type": "application/json"}, body)
}

// bedrockErr pulls a human string out of a Bedrock JSON error body.
func bedrockErr(body []byte) string {
	var e struct {
		Message string `json:"message"`
		Msg     string `json:"Message"`
	}
	_ = json.Unmarshal(body, &e)
	if e.Message != "" {
		return e.Message
	}
	if e.Msg != "" {
		return e.Msg
	}
	return mutDetail(body)
}

func bedrockIsNotFound(status int, body []byte) bool {
	return status == http.StatusNotFound || strings.Contains(bedrockErr(body), "NotFound")
}

func bedrockIsAlreadyExists(status int, body []byte) bool {
	return status == http.StatusConflict || strings.Contains(bedrockErr(body), "Conflict")
}

// bedrockProfile is the projection of GetInferenceProfile the driver reads. The
// models[].modelArn set is the AUTHORITATIVE routing surface (destination regions +
// model provider); Status feeds model.access (the manual-gate proxy) + the create
// poll; Type distinguishes SYSTEM_DEFINED (AWS-managed) from APPLICATION; Tags drive
// the ownership gate for a delete.
type bedrockProfile struct {
	InferenceProfileArn  string `json:"inferenceProfileArn"`
	InferenceProfileID   string `json:"inferenceProfileId"`
	InferenceProfileName string `json:"inferenceProfileName"`
	Status               string `json:"status"`
	Type                 string `json:"type"`
	Models               []struct {
		ModelArn string `json:"modelArn"`
	} `json:"models"`
	Tags []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"tags"`
}

func (p bedrockProfile) modelArns() []string {
	out := make([]string, 0, len(p.Models))
	for _, m := range p.Models {
		out = append(out, m.ModelArn)
	}
	return out
}

func (p bedrockProfile) tagMap() map[string]string {
	m := map[string]string{}
	for _, t := range p.Tags {
		m[t.Key] = t.Value
	}
	return m
}

// getInferenceProfile resolves the profile our id names. (found, readable): a 404 /
// NotFound is found=false+readable (an absent profile, not an error); a transport
// error or any other non-200 is readable=false (unknown — never a fabricated absence).
func (d *Driver) getInferenceProfile(region, profileID string) (bedrockProfile, bool, error) {
	const op = "GetInferenceProfile"
	st, resp, err := d.bedrockDo("GET", region, bedrockProfilesPath+"/"+profileID, nil)
	if err != nil {
		return bedrockProfile{}, false, readTransport(op, err)
	}
	if bedrockIsNotFound(st, resp) {
		return bedrockProfile{}, false, nil
	}
	if st != http.StatusOK {
		return bedrockProfile{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var p bedrockProfile
	if json.Unmarshal(resp, &p) != nil {
		return bedrockProfile{}, false, readBody(op, st)
	}
	return p, true, nil
}

// listInferenceProfiles lists a region's inference-profile summaries (type filters
// SYSTEM_DEFINED vs APPLICATION). readable=false on any transport/HTTP/parse failure
// (never a fabricated empty set).
func (d *Driver) listInferenceProfiles(region, typ string) ([]string, error) {
	// PAGINATE (nextToken): a complete list is what lets reconcileBedrock honestly
	// conclude a pending create "failed" when no owned profile is present, instead
	// of false-failing one that sits on a later page (which would double-create).
	var ids []string
	token := ""
	for {
		path := bedrockProfilesPath + "?maxResults=100"
		if typ != "" {
			path += "&typeEquals=" + typ
		}
		if token != "" {
			path += "&nextToken=" + url.QueryEscape(token)
		}
		const op = "ListInferenceProfiles"
		st, resp, cerr := d.bedrockDo("GET", region, path, nil)
		if cerr != nil {
			return nil, readTransport(op, cerr)
		}
		if st != http.StatusOK {
			return nil, readHTTP(op, st, awsErrCodeOf(resp))
		}
		var out struct {
			InferenceProfileSummaries []struct {
				InferenceProfileID string `json:"inferenceProfileId"`
			} `json:"inferenceProfileSummaries"`
			NextToken string `json:"nextToken"`
		}
		if json.Unmarshal(resp, &out) != nil {
			return nil, readBody(op, st)
		}
		for _, s := range out.InferenceProfileSummaries {
			ids = append(ids, s.InferenceProfileID)
		}
		if out.NextToken == "" {
			return ids, nil
		}
		token = out.NextToken
	}
}

// observeBedrock reverse-maps a live inference profile to capability.ai.inference.
// The load-bearing observation is inference.destinationRegions — the SORTED, UNIQUE
// set of regions parsed from models[].modelArn (the authoritative routing surface the
// subset-of contract asserts against, catching the eu-south-2 trap DETERMINISTICALLY).
// model.provider is parsed from the same ARNs. model.access is a MANUAL-GATE: it is
// OBSERVED from the profile being resolvable + ACTIVE (never a fabricated constant),
// and a diagnostic states plainly that it is granted via the console use-case form,
// not provisioned by groundhold. An unreadable profile is unknown (an error); a
// not-found profile is nothing-to-observe.
func (d *Driver) observeBedrock(capability, providerID string) ([]provider.Observation, []string, error) {
	region, profileID, err := splitBedrockProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	p, found, rerr := d.getInferenceProfile(region, profileID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"profile not found — nothing to observe"}, nil
	}

	arns := p.modelArns()
	destRegions := destinationRegionsFromModels(arns)
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "inference.destinationRegions", Value: destRegions, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	if len(destRegions) == 0 {
		diags = append(diags, "inference.destinationRegions is empty (no readable model ARNs) — the residency surface could not be measured")
	}
	if prov := providerFromModels(arns); prov != "" {
		obs = append(obs, provider.Observation{Path: "model.provider", Value: prov, Derivation: "measured"})
	} else {
		diags = append(diags, "model.provider not derivable from the model ARNs — omitted rather than fabricated")
	}
	// model.access — a MANUAL-GATE. The profile being resolvable + ACTIVE is the
	// strongest signal these read-only APIs expose; it is OBSERVED (reflects the real
	// profile state, never a blind constant). The diagnostic keeps it honest: the grant
	// lives behind the Bedrock console use-case form, groundhold observes it, never provisions.
	obs = append(obs, provider.Observation{
		Path: "model.access", Value: p.Status == "ACTIVE", Derivation: "measured"})
	diags = append(diags,
		"model.access is a manual-gate — Bedrock model access is granted via the console use-case form, never an API create; "+
			"groundhold OBSERVES it (from the profile being resolvable + ACTIVE), it does NOT provision it")
	return obs, diags, nil
}

// discoverBedrock enumerates a region's inference profiles as capability.ai.inference
// — so `discover --provider aws` surfaces the EU cross-region profiles (eu.anthropic.*)
// whose routing must be checked against the residency allowlist. Reuses observeBedrock
// (two-step: ListInferenceProfiles ids -> per-profile reverse map).
func (d *Driver) discoverBedrock(region string) ([]provider.Discovered, []string, error) {
	// List BOTH types explicitly. A bare list DEFAULTS to SYSTEM_DEFINED on real AWS
	// (F20's sibling), so an unfiltered discover silently misses every APPLICATION
	// profile — exactly the ones groundhold creates and a brownfield adopt takes over.
	// SYSTEM_DEFINED profiles stay in the sweep too: their reverse-mapped
	// destinationRegions are the residency-audit surface. listInferenceProfiles
	// paginates, so neither set is truncated at the first page.
	var ids []string
	for _, typ := range []string{"SYSTEM_DEFINED", "APPLICATION"} {
		got, lerr := d.listInferenceProfiles(region, typ)
		if lerr != nil {
			return nil, nil, fmt.Errorf("bedrock %s profiles: %w", typ, lerr)
		}
		ids = append(ids, got...)
	}
	var found []provider.Discovered
	var diags []string
	for _, id := range ids {
		pid := bedrockProviderID(region, id)
		obs, od, oerr := d.observeBedrock("", pid)
		if oerr != nil {
			diags = append(diags, id+": "+oerr.Error())
			continue
		}
		diags = append(diags, od...)
		found = append(found, provider.Discovered{
			ProviderID: pid, ResourceType: "capability.ai.inference", Observations: obs})
	}
	return found, diags, nil
}

// createBedrock provisions an APPLICATION inference profile (CreateInferenceProfile),
// four-valued + ownership tags. The MANUAL-GATE crux (C2): if the contract requires
// model.access=true, the create must NOT fake it — model access is granted by a
// Bedrock console use-case form, never an API create, so the create HONEST-REFUSES
// before any mutation. An application profile's id is AWS-assigned, so the pid is
// knowable only from the response; a transport/5xx before the id lands is unknown
// (reconcile by name via ListInferenceProfiles), never a silent success.
func (d *Driver) createBedrock(region, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildBedrock(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// The MANUAL-GATE refusal used to live here and now lives in BuildBedrock
	// (D378): it is a pure function of the candidate, so raising it in the pure
	// core makes apply's up-front Validate refuse the whole run before the first
	// mutation, instead of discovering it mid-DAG with siblings already applied.
	// `plan.NeedsAccess` therefore cannot be true by the time this line runs —
	// BuildBedrock returned an error above.

	body := jsonBody(map[string]any{
		"inferenceProfileName": plan.ProfileName,
		"modelSource":          map[string]any{"copyFrom": plan.ModelSource},
		"tags": []any{
			map[string]any{"key": "groundhold-capability", "value": sanitizeTag(capability)},
			map[string]any{"key": "groundhold-environment", "value": sanitizeTag(environment)},
		},
	})
	st, resp, err := d.bedrockDo("POST", region, bedrockProfilesPath, []byte(body))
	switch {
	case err != nil:
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("CreateInferenceProfile outcome unknown (may have landed) — reconcile by name %q via ListInferenceProfiles: %v", plan.ProfileName, err)}
	case st == http.StatusOK || st == http.StatusCreated:
		// created — recover the AWS-assigned id below
	case bedrockIsAlreadyExists(st, resp):
		// create-adoption (D252): the name already exists — if it is OURS, BIND it
		// (measured reality) instead of stranding an unknown, so a lost-ledger
		// converge re-adopts existing infrastructure rather than duplicating it.
		// Ownership is the deterministic name + our tags; attribute drift (if any)
		// is carried by the next reconcile, never checked here.
		if ids, lerr := d.listInferenceProfiles(region, "APPLICATION"); lerr == nil {
			for _, id := range ids {
				if p, found, rerr := d.getInferenceProfile(region, id); rerr == nil && found &&
					p.InferenceProfileName == plan.ProfileName &&
					groundholdTagsMatch(p.tagMap(), capability, environment) {
					return provider.CreateResult{ProviderID: bedrockProviderID(region, id), Status: "succeeded"}
				}
			}
		}
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("CreateInferenceProfile says the name %q now exists but it is not resolvably ours — reconcile ownership", plan.ProfileName)}
	case st >= 500:
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("CreateInferenceProfile HTTP %d (server error — may have landed): %s", st, bedrockErr(resp))}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateInferenceProfile HTTP %d: %s", st, bedrockErr(resp))}
	}
	var out struct {
		InferenceProfileArn string `json:"inferenceProfileArn"`
		InferenceProfileID  string `json:"inferenceProfileId"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("CreateInferenceProfile response unparseable — reconcile by name %q via ListInferenceProfiles", plan.ProfileName)}
	}
	// AWS CreateInferenceProfile returns the ARN, not a bare inferenceProfileId, so
	// derive the id from the ARN's last path segment. Requiring inferenceProfileId
	// here false-negatived a SUCCESSFUL create (profile ACTIVE) as "unknown" and
	// aborted the apply into a partial (F18).
	profileID := out.InferenceProfileID
	if profileID == "" {
		profileID = bedrockIDFromArn(out.InferenceProfileArn)
	}
	if profileID == "" {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("CreateInferenceProfile returned neither id nor arn — reconcile by name %q via ListInferenceProfiles", plan.ProfileName)}
	}
	return provider.CreateResult{ProviderID: bedrockProviderID(region, profileID), Status: "succeeded"}
}

// deleteBedrock removes an APPLICATION inference profile groundhold created,
// ownership-gated. A SYSTEM_DEFINED profile (eu.anthropic.* and the other geo-prefixed
// cross-region profiles) is AWS-managed — groundhold never owns it, so the delete
// HONEST-REFUSES before touching it. Idempotent on already-gone (404); a transport/5xx
// is unknown WITH the pid (reconcile), never a claimed success.
func (d *Driver) deleteBedrock(capability, environment, providerID string) provider.CreateResult {
	region, profileID, err := splitBedrockProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// system (AWS-managed) profiles are refused up front — they carry no ownership tags
	// and are not groundhold's to delete.
	if isSystemProfileID(profileID) {
		return provider.CreateResult{Status: "failed",
			Reason: "a system inference profile is AWS-managed, not groundhold-owned — refusing to delete it"}
	}
	p, found, rerr := d.getInferenceProfile(region, profileID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	if p.Type == "SYSTEM_DEFINED" {
		return provider.CreateResult{Status: "failed",
			Reason: "a system inference profile is AWS-managed, not groundhold-owned — refusing to delete it"}
	}
	// ownership guard: refuse a foreign application profile at our id.
	if !groundholdTagsMatch(p.tagMap(), capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "profile tags do not match — refusing to delete a resource that is not ours"}
	}
	st, body, err := d.bedrockDo("DELETE", region, bedrockProfilesPath+"/"+profileID, nil)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("DeleteInferenceProfile outcome unknown: %v", err)}
	case st == http.StatusOK || st == http.StatusNoContent || st == http.StatusAccepted || bedrockIsNotFound(st, body):
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("DeleteInferenceProfile HTTP %d (server error) — reconcile", st)}
	default:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("DeleteInferenceProfile HTTP %d: %s", st, bedrockErr(body))}
	}
}
