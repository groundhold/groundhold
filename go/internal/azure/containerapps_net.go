// Azure Container Apps network shell (D99): the ARM half of the workload.container
// driver. Constitutive composite under ONE binding, fixed sequence: managed
// environment (async) -> container app (async, referencing the env). The
// providerId is the app, carried from the environment PUT (the first durable
// resource) so a partial is unknown WITH the pid. Ownership is tags; delete is
// reverse (app then env).
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func acaProviderID(sub, rg, app string) string {
	return "aca:" + sub + ":" + rg + ":" + app
}

func splitACAProviderID(providerID string) (sub, rg, app string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "aca" {
		return "", "", "", fmt.Errorf("providerId %q is not aca:sub:rg:app", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || !azNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) envID(sub, rg, env string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/managedEnvironments/%s", sub, rg, env)
}

func (d *Driver) createContainerApp(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildContainerApp(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed", Reason: "azure container app requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := acaProviderID(d.Subscription, rg, plan.App)

	// ---- 1. the constitutive managed environment ----
	envURL, _ := d.armURL(rg, "Microsoft.App/managedEnvironments/"+plan.Env, appAPIVersion)
	envProps := map[string]any{"zoneRedundant": plan.ZoneRedundant}
	if plan.ZoneRedundant {
		envProps["vnetConfiguration"] = map[string]any{"infrastructureSubnetId": plan.Subnet}
	}
	envBody, _ := json.Marshal(map[string]any{
		"location": plan.Region, "tags": d.tags(capability, environment),
		"properties": envProps})
	if r := d.putAndPoll(envURL, envBody, pid, "managed environment"); r != nil {
		return *r
	}

	// ---- 2. the container app ----
	appURL, _ := d.armURL(rg, "Microsoft.App/containerApps/"+plan.App, appAPIVersion)
	appBody, _ := json.Marshal(map[string]any{
		"location": plan.Region, "tags": d.tags(capability, environment),
		"properties": map[string]any{
			"managedEnvironmentId": d.envID(d.Subscription, rg, plan.Env),
			"configuration": map[string]any{"ingress": map[string]any{
				"external": plan.Public, "allowInsecure": plan.AllowInsecure, "targetPort": 8080}},
			"template": map[string]any{
				"containers": []any{map[string]any{"name": "app", "image": plan.Image}},
				"scale":      map[string]any{"minReplicas": plan.MinReplicas}},
		}})
	if r := d.putAndPoll(appURL, appBody, pid, "container app"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type acaDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
		Configuration     struct {
			Ingress *struct {
				External      bool   `json:"external"`
				AllowInsecure bool   `json:"allowInsecure"`
				FQDN          string `json:"fqdn"`
			} `json:"ingress"`
		} `json:"configuration"`
		Template struct {
			Scale struct {
				MinReplicas *int `json:"minReplicas"`
			} `json:"scale"`
		} `json:"template"`
	} `json:"properties"`
}

func (d *Driver) observeContainerApp(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, app, err := splitACAProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	appURL, _ := d.armURL(rg, "Microsoft.App/containerApps/"+app, appAPIVersion)
	st, resp, e := d.doARM("GET", appURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("containerApps.get: %v", e)
	}
	if st == http.StatusNotFound {
		return nil, []string{"container app not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("containerApps.get: HTTP %d", st)
	}
	var doc acaDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "containerApps.get", Cause: "body", Status: st}
	}
	var obs []provider.Observation
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: strings.ToLower(doc.Location), Derivation: "measured"})
	}
	obs = append(obs,
		provider.Observation{Path: "service.managed", Value: true, Derivation: "measured"},
		provider.Observation{Path: "availability.class", Value: "zonal", Derivation: "config-intent"},
	)
	if ing := doc.Properties.Configuration.Ingress; ing != nil {
		obs = append(obs,
			provider.Observation{Path: "network.publicExposure", Value: ing.External, Derivation: "measured"},
			provider.Observation{Path: "tls.enforced", Value: !ing.AllowInsecure, Derivation: "measured"},
		)
	} else {
		// no ingress = not publicly exposed.
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: false, Derivation: "measured"})
	}
	if m := doc.Properties.Template.Scale.MinReplicas; m != nil {
		obs = append(obs, provider.Observation{Path: "replicas.minimum", Value: float64(*m), Derivation: "measured"})
	}
	return obs, nil, nil
}

// acaIngressFQDN reads the container app's server-assigned ingress fqdn via one
// containerApps.get (D330 output derivation, the GCP cloudrun uri twin). A
// transport error, non-200 or unparseable body is an ERROR (reconcile) — never a
// fabricated absence. An app with ingress DISABLED has no fqdn: "" is returned
// (the caller omits the output), not an error, since — unlike Cloud Run, which
// always has a uri — Container Apps ingress is optional.
func (d *Driver) acaIngressFQDN(rg, app string) (string, error) {
	appURL, err := d.armURL(rg, "Microsoft.App/containerApps/"+app, appAPIVersion)
	if err != nil {
		return "", err
	}
	st, resp, e := d.doARM("GET", appURL, nil)
	if e != nil {
		return "", fmt.Errorf("containerApps.get: %v", e)
	}
	if st != http.StatusOK {
		return "", fmt.Errorf("containerApps.get: HTTP %d", st)
	}
	var doc acaDoc
	if json.Unmarshal(resp, &doc) != nil {
		return "", &armReadError{Op: "containerApps.get", Cause: "body", Status: st}
	}
	if ing := doc.Properties.Configuration.Ingress; ing != nil {
		return ing.FQDN, nil
	}
	return "", nil
}

func (d *Driver) deleteContainerApp(capability, environment, providerID string) provider.CreateResult {
	sub, rg, app, err := splitACAProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	_ = sub
	appURL, _ := d.armURL(rg, "Microsoft.App/containerApps/"+app, appAPIVersion)
	st, resp, e := d.doARM("GET", appURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc acaDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "container app tags do not match — refusing to delete a resource that is not ours"}
	}
	// delete the app, then the constitutive environment (reverse).
	if r := d.deleteAndConfirm(appURL, providerID, "container app"); r != nil {
		return *r
	}
	envURL, _ := d.armURL(rg, "Microsoft.App/managedEnvironments/"+app+"-env", appAPIVersion)
	if r := d.deleteAndConfirm(envURL, providerID, "managed environment"); r != nil && r.Status != "succeeded" {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded",
			Reason: "app retired; environment cleanup inconclusive — reconcile"}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
