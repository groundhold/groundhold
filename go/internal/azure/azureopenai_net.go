// Azure OpenAI inference network shell (parity with D150/D76): the ARM half of the
// Azure capability.ai.inference vocab — the parity twin of aws/bedrock_net.go and
// gcp/vertexai_net.go. OBSERVE-FIRST: the D1 verifier rule needs the OBSERVED
// destination regions, so the load-bearing path is accounts.get + deployments.list ->
// the destination-region set MEASURED from the real deployment skus (a Global sku
// reduces to ["global"], a DataZone sku to ["datazone-<zone>"], catching the trap).
// CREATE stands up the account (Microsoft.CognitiveServices/accounts, kind=OpenAI) and,
// if a model is named, one deployment — four-valued + ownership tags. model.access is a
// MANUAL-GATE (Azure OpenAI access is an application/approval, never an API create): a
// create that requires model.access=true HONEST-REFUSES rather than faking it. DELETE is
// ownership-gated by tags. ARM is a single PUT polled to provisioningState=Succeeded.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

// aoiAccountPath / aoiDeploymentsPath / aoiDeploymentPath build the ARM provider paths.
func (d *Driver) aoiAccountPath(account string) string {
	return "Microsoft.CognitiveServices/accounts/" + account
}
func (d *Driver) aoiDeploymentPath(account, deployment string) string {
	return "Microsoft.CognitiveServices/accounts/" + account + "/deployments/" + deployment
}

// createAzureOpenAI provisions an Azure OpenAI account (+ an optional model deployment),
// four-valued + ownership tags. The MANUAL-GATE crux (parity with Bedrock/Vertex): if
// the contract requires model.access=true, the create must NOT fake it — access is
// granted by an application/approval, never an API create, so the create HONEST-REFUSES
// before any mutation.
func (d *Driver) createAzureOpenAI(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAzureOpenAI(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed", Reason: "azure openai requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	// MANUAL-GATE: model.access cannot be provisioned nor honestly verified through
	// these APIs — refuse rather than fabricate a grant (the honest posture the vocab
	// demands: the driver OBSERVES access, it does not create it).
	if plan.NeedsAccess {
		return provider.CreateResult{Status: "failed",
			Reason: "model access is a manual gate — grant it by applying for Azure OpenAI model access; " +
				"groundhold observes model.access, it does not provision it (refusing to fake model.access=true)"}
	}

	pid := aoiProviderID(d.Subscription, rg, plan.Account)
	acctURL, err := d.armURL(rg, d.aoiAccountPath(plan.Account), cognitiveAPIVersion)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	acctBody, _ := json.Marshal(map[string]any{
		"location": plan.Region,
		"kind":     "OpenAI",
		"sku":      map[string]any{"name": "S0"},
		"tags":     d.tags(capability, environment),
		"properties": map[string]any{
			"customSubDomainName": plan.Account,
			"publicNetworkAccess": "Enabled",
		},
	})
	if r := d.putAndPoll(acctURL, acctBody, pid, "azure openai account"); r != nil {
		return *r
	}

	// optional model deployment — the sku (scale type) determines the routing observe
	// measures. Standard = regional (the residency-safe default).
	if plan.DeploymentModel != "" {
		depURL, err := d.armURL(rg, d.aoiDeploymentPath(plan.Account, plan.DeploymentName), cognitiveAPIVersion)
		if err != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: err.Error()}
		}
		model := map[string]any{"format": "OpenAI", "name": plan.DeploymentModel}
		if plan.DeploymentVersion != "" {
			model["version"] = plan.DeploymentVersion
		}
		depBody, _ := json.Marshal(map[string]any{
			"sku":        map[string]any{"name": plan.DeploymentSku, "capacity": 1},
			"properties": map[string]any{"model": model},
		})
		if r := d.putAndPoll(depURL, depBody, pid, "azure openai deployment"); r != nil {
			return *r
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// aoiAccountDoc is the projection of accounts.get the driver reads.
type aoiAccountDoc struct {
	Location   string            `json:"location"`
	Kind       string            `json:"kind"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
	} `json:"properties"`
}

// aoiDeploymentDoc is the projection of one deployments.list entry: the sku name is the
// scale type (the routing surface), the model format/name feed model.provider.
type aoiDeploymentDoc struct {
	Name string `json:"name"`
	Sku  struct {
		Name string `json:"name"`
	} `json:"sku"`
	Properties struct {
		Model struct {
			Format string `json:"format"`
			Name   string `json:"name"`
		} `json:"model"`
	} `json:"properties"`
}

// listAOIDeployments lists an account's model deployments. (deployments, readable): any
// transport/HTTP/parse failure is readable=false (never a fabricated empty set that
// would understate the residency surface).
func (d *Driver) listAOIDeployments(rg, account string) ([]aoiDeploymentDoc, error) {
	const op = "deployments.list"
	depsURL, err := d.armURL(rg, d.aoiAccountPath(account)+"/deployments", cognitiveAPIVersion)
	if err != nil {
		return nil, &armReadError{Op: op, Cause: "scope", Detail: err.Error()}
	}
	// D869: EVERY page. `Deployments_List` is pageable (ARM's own spec), and this list
	// reduces to `inference.destinationRegions` — the attribute that turns a Global sku
	// into a deterministic residency violation. A deployment on page two is a destination
	// that silently leaves the surface, which is the failure this read exists to prevent.
	var out []aoiDeploymentDoc
	if err := d.listAllARMPages(op, depsURL, func(body []byte) error {
		var page struct {
			Value []aoiDeploymentDoc `json:"value"`
		}
		if json.Unmarshal(body, &page) != nil {
			return armBody(op, http.StatusOK)
		}
		out = append(out, page.Value...)
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// observeAzureOpenAI reverse-maps a live Azure OpenAI account to
// capability.ai.inference. The load-bearing observation is inference.destinationRegions
// — MEASURED from the account's region + the real deployment skus (a Global sku reduces
// to ["global"], a DataZone sku to ["datazone-<zone>"], NOT bounded EU regions, so the
// trap becomes a `violated` verdict DETERMINISTICALLY). model.provider is parsed from
// the deployed model's format. model.access is a MANUAL-GATE: OBSERVED from a model
// actually being DEPLOYED (you cannot deploy a model without the grant), never a
// fabricated constant, with a diagnostic that it lives behind an application/approval.
func (d *Driver) observeAzureOpenAI(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, account, err := splitAzureOpenAIProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	acctURL, err := d.armURL(rg, d.aoiAccountPath(account), cognitiveAPIVersion)
	if err != nil {
		return nil, nil, err
	}
	st, resp, e := d.doARM("GET", acctURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("accounts.get: %v", e)
	}
	if st == http.StatusNotFound {
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"account not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("accounts.get: HTTP %d", st)
	}
	var doc aoiAccountDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "accounts.get", Cause: "body", Status: st}
	}
	region := azRegion(doc.Location)
	if region == "" {
		region = "unknown"
	}

	// the destination regions are MEASURED from the account's deployment skus. An
	// unreadable deployment list is an ERROR (never a fabricated absence that would
	// understate the residency surface and let the trap slip through).
	deps, lerr := d.listAOIDeployments(rg, account)
	if lerr != nil {
		return nil, nil, fmt.Errorf("the residency surface could not be measured: %w", lerr)
	}
	scaleTypes := make([]string, 0, len(deps))
	formats := make([]string, 0, len(deps))
	for _, dep := range deps {
		scaleTypes = append(scaleTypes, dep.Sku.Name)
		if dep.Properties.Model.Format != "" {
			formats = append(formats, dep.Properties.Model.Format)
		}
	}
	destRegions := destinationRegionsFromDeployments(scaleTypes, region)

	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "inference.destinationRegions", Value: destRegions, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	for _, r := range destRegions {
		if r == "global" {
			diags = append(diags, "inference.destinationRegions includes [global] — a global-sku deployment routes to ANY region worldwide; "+
				"it is NOT a bounded EU set, so a residency subset-of an EU allowlist will be violated (the trap, caught deterministically)")
		} else if len(r) > 9 && r[:9] == "datazone-" {
			diags = append(diags, "inference.destinationRegions includes ["+r+"] — a data-zone-sku deployment routes across a multi-region data zone (broader than a single region); "+
				"a strict single-region residency subset-of will be violated")
		}
	}
	if prov := firstProvider(formats); prov != "" {
		obs = append(obs, provider.Observation{Path: "model.provider", Value: prov, Derivation: "measured"})
	} else {
		diags = append(diags, "model.provider not derivable from the deployed models (none deployed, or no readable format) — omitted rather than fabricated")
	}
	// model.access — a MANUAL-GATE. A model actually DEPLOYED is the strongest signal
	// these read-only APIs expose (you cannot deploy without the grant); it is OBSERVED
	// (reflects real account state, never a blind constant). The diagnostic keeps it
	// honest: the grant lives behind an application/approval, groundhold observes it, never
	// provisions it.
	obs = append(obs, provider.Observation{
		Path: "model.access", Value: len(deps) > 0, Derivation: "measured"})
	diags = append(diags,
		"model.access is a manual-gate — Azure OpenAI model access is granted by an application/approval, never an API create; "+
			"groundhold OBSERVES it (from a model being deployed on the account), it does NOT provision it")
	return obs, diags, nil
}

// firstProvider maps the first readable deployment model format to model.provider.
func firstProvider(formats []string) string {
	for _, f := range formats {
		if p := providerFromModelFormat(f); p != "" {
			return p
		}
	}
	return ""
}

// deleteAzureOpenAI removes an Azure OpenAI account groundhold created, ownership-gated by
// tags with a pre-read (deleting the account removes its deployments). Idempotent on
// already-gone (404); a transport/5xx is unknown WITH the pid (reconcile), never a
// claimed success.
func (d *Driver) deleteAzureOpenAI(capability, environment, providerID string) provider.CreateResult {
	_, rg, account, err := splitAzureOpenAIProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	acctURL, err := d.armURL(rg, d.aoiAccountPath(account), cognitiveAPIVersion)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	st, resp, e := d.doARM("GET", acctURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc aoiAccountDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed", Reason: "account tags do not match — refusing to delete a resource that is not ours"}
	}
	// D984: route the delete through deleteAndConfirm (D971) — a Cognitive Services
	// account DELETE returns 202 Accepted (async); concluding succeeded here tombstoned
	// an account (with its deployments) still live. The helper polls to a confirmed
	// 404, unknown on timeout.
	return *d.deleteAndConfirm(acctURL, providerID, "azure openai account")
}

// discoverAzureOpenAI enumerates the region's Azure OpenAI accounts as
// capability.ai.inference — so `discover --provider azure` surfaces the accounts whose
// destination regions must be checked against the residency allowlist (including a
// global/data-zone deployment). Reuses observeAzureOpenAI (two-step:
// accounts.list -> per-account reverse map). kind=OpenAI filters non-OpenAI Cognitive
// Services accounts.
func (d *Driver) discoverAzureOpenAI(region string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.CognitiveServices/accounts?api-version=%s",
		d.BaseURL, d.Subscription, cognitiveAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("accounts.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("accounts.list: HTTP %d", st)
	}
	var accts struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Kind     string `json:"kind"`
			Location string `json:"location"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &accts) != nil {
		return nil, nil, &armReadError{Op: "accounts.list", Cause: "body", Status: st}
	}
	want := azRegion(region)
	var out []provider.Discovered
	var diags []string
	for _, a := range accts.Value {
		if a.Kind != "OpenAI" {
			continue // another Cognitive Services kind — not this capability
		}
		if azRegion(a.Location) != want {
			continue // lives in another region — not this sweep
		}
		rg := resourceGroupOf(a.ID)
		if rg == "" {
			diags = append(diags, a.Name+": resource group unparseable from id")
			continue
		}
		pid := aoiProviderID(d.Subscription, rg, a.Name)
		obs, odiags, oerr := d.observeAzureOpenAI("", pid)
		if oerr != nil {
			diags = append(diags, a.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, a.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.ai.inference",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}
