// Azure Application Insights availability test network shell (D108): the ARM half of the
// capability.monitoring.uptime driver. A single PUT of a webtest, ownership by tags.
// observe reverse-maps target/protocol/path/period from the test's Request URL +
// Frequency. A lost PUT is unknown (D29). NOT live-validated (no Azure creds here).
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"groundhold/internal/provider"
)

func azureWebtestProviderID(sub, rg, name string) string {
	return "azwebtest:" + sub + ":" + rg + ":" + name
}

func splitAzureWebtestProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "azwebtest" {
		return "", "", "", fmt.Errorf("providerId %q is not azwebtest:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid sub/rg", providerID)
	}
	if parts[3] == "" {
		return "", "", "", fmt.Errorf("providerId %q has an empty name", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) createAzureWebtest(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAzureWebtest(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed", Reason: "azure availability test requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := azureWebtestProviderID(d.Subscription, rg, plan.Name)
	iURL, _ := d.armURL(rg, "Microsoft.Insights/webtests/"+plan.Name, webtestAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	if r := d.refuseForeignUpsert(iURL, body); r != nil { // D254
		return *r
	}
	st, resp, e := d.doARM("PUT", iURL, body)
	if e != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", e)}
	}
	switch {
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, azErrCode(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetailAz(resp))}
	}
}

type azureWebtestDoc struct {
	Tags       map[string]string `json:"tags"`
	Properties struct {
		Frequency int `json:"Frequency"`
		// D902b: Azure returns Request as null on GET and carries the request URL only
		// inside the WebTest XML — the reverse map reads it from there, not from a
		// structured Request field the platform never populates.
		Configuration struct {
			WebTest string `json:"WebTest"`
		} `json:"Configuration"`
	} `json:"properties"`
}

// webtestURLFromXML pulls the request URL out of the WebTest XML blob (D902b).
var webtestURLFromXML = regexp.MustCompile(`\bUrl="([^"]+)"`)

func (d *Driver) observeAzureWebtest(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitAzureWebtestProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	iURL, _ := d.armURL(rg, "Microsoft.Insights/webtests/"+name, webtestAPIVersion)
	st, resp, e := d.doARM("GET", iURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("webtests.get: %v", e)
	}
	if st == http.StatusNotFound {
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"availability test not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("webtests.get: HTTP %d", st)
	}
	var doc azureWebtestDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "webtests.get", Cause: "body", Status: st}
	}
	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "check.period", Value: fmt.Sprintf("%ds", doc.Properties.Frequency), Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	rawURL := ""
	if m := webtestURLFromXML.FindStringSubmatch(doc.Properties.Configuration.WebTest); len(m) == 2 {
		rawURL = xmlUnescaper.Replace(m[1])
	}
	if u, perr := url.Parse(rawURL); perr == nil && u.Host != "" {
		obs = append(obs,
			provider.Observation{Path: "check.target", Value: u.Host, Derivation: "measured"},
			provider.Observation{Path: "check.protocol", Value: u.Scheme, Derivation: "measured"})
		if u.Path != "" {
			obs = append(obs, provider.Observation{Path: "check.path", Value: u.Path, Derivation: "measured"})
		}
	}
	return obs, nil, nil
}

func (d *Driver) deleteAzureWebtest(capability, environment, providerID string) provider.CreateResult {
	_, rg, name, err := splitAzureWebtestProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	iURL, _ := d.armURL(rg, "Microsoft.Insights/webtests/"+name, webtestAPIVersion)
	st, resp, e := d.doARM("GET", iURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc azureWebtestDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed", Reason: "availability test tags do not match — refusing to delete a resource that is not ours"}
	}
	dst, dresp, de := d.doARM("DELETE", iURL, nil)
	if de != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", de)}
	}
	if dst == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if dst >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", dst)}
	}
	if dst < 200 || dst >= 300 {
		if r := provider.MutationResult(dst, azErrCode(dresp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", dst, mutDetailAz(dresp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
