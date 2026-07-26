// Route 53 health check network shell (D108): the REST-XML (global, us-east-1) half of
// the AWS capability.monitoring.uptime driver. Reuses the hosted-zone signing plumbing
// (r53Do). The health-check Id is server-assigned, so it is parsed from the response (a
// lost create is unknown). Ownership is tags (ResourceType=healthcheck). observe
// reverse-maps the single health check config.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"groundhold/internal/provider"
)

var r53hcIDOK = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

func r53hcProviderID(id string) string { return "r53hc:" + id }

func splitR53HCProviderID(providerID string) (id string, err error) {
	parts := strings.SplitN(providerID, ":", 2)
	if len(parts) != 2 || parts[0] != "r53hc" {
		return "", fmt.Errorf("providerId %q is not r53hc:id", providerID)
	}
	if !r53hcIDOK.MatchString(parts[1]) {
		return "", fmt.Errorf("providerId health check id %q is invalid", parts[1])
	}
	return parts[1], nil
}

func (d *Driver) createRoute53HealthCheck(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildRoute53HealthCheck(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	st, resp, e := d.r53Do("POST", "/2013-04-01/healthcheck", plan.createXML())
	if e != nil {
		return provider.CreateResult{Status: "unknown", Reason: fmt.Sprintf("create outcome unknown: %v", e)}
	}
	if st != http.StatusCreated && st != http.StatusOK {
		if st >= 500 {
			return provider.CreateResult{Status: "unknown", Reason: fmt.Sprintf("create HTTP %d (server error) — reconcile", st)}
		}
		if r := provider.MutationResult(st, "", nil, "", "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(resp))}
	}
	var r struct {
		ID string `xml:"HealthCheck>Id"`
	}
	if xml.Unmarshal(resp, &r) != nil || r.ID == "" {
		return provider.CreateResult{Status: "unknown", Reason: "create response carried no health check id — reconcile"}
	}
	pid := r53hcProviderID(r.ID)
	// tag for ownership (ResourceType=healthcheck).
	tst, tresp, te := d.r53Do("POST", "/2013-04-01/tags/healthcheck/"+r.ID, r53TagsXML(capability, environment))
	if te != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "health check created; tagging outcome unknown — reconcile"}
	}
	if tst < 200 || tst >= 300 {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("health check created but tagging HTTP %d: %s — reconcile", tst, mutDetail(tresp))}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

func (d *Driver) r53hcTags(id string) (map[string]string, error) {
	const op = "ListTagsForResource"
	st, resp, err := d.r53Do("GET", "/2013-04-01/tags/healthcheck/"+id, "")
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, ecsErr(resp))
	}
	var r struct {
		Tags []struct {
			Key   string `xml:"Key"`
			Value string `xml:"Value"`
		} `xml:"ResourceTagSet>Tags>Tag"`
	}
	if xml.Unmarshal(resp, &r) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range r.Tags {
		m[t.Key] = t.Value
	}
	return m, nil
}

func (d *Driver) observeRoute53HealthCheck(capability, providerID string) ([]provider.Observation, []string, error) {
	id, err := splitR53HCProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	st, resp, e := d.r53Do("GET", "/2013-04-01/healthcheck/"+id, "")
	if e != nil {
		return nil, nil, fmt.Errorf("GetHealthCheck: %v", e)
	}
	if st == http.StatusNotFound {
		return nil, []string{"health check not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("GetHealthCheck: HTTP %d", st)
	}
	var r struct {
		Type         string `xml:"HealthCheck>HealthCheckConfig>Type"`
		FQDN         string `xml:"HealthCheck>HealthCheckConfig>FullyQualifiedDomainName"`
		ResourcePath string `xml:"HealthCheck>HealthCheckConfig>ResourcePath"`
		Interval     int    `xml:"HealthCheck>HealthCheckConfig>RequestInterval"`
	}
	if xml.Unmarshal(resp, &r) != nil {
		return nil, nil, fmt.Errorf("GetHealthCheck: unparseable")
	}
	obs := []provider.Observation{
		{Path: "check.target", Value: r.FQDN, Derivation: "measured"},
		{Path: "check.period", Value: fmt.Sprintf("%ds", r.Interval), Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	switch r.Type {
	case "HTTP":
		obs = append(obs, provider.Observation{Path: "check.protocol", Value: "http", Derivation: "measured"})
	case "HTTPS":
		obs = append(obs, provider.Observation{Path: "check.protocol", Value: "https", Derivation: "measured"})
	case "TCP":
		obs = append(obs, provider.Observation{Path: "check.protocol", Value: "tcp", Derivation: "measured"})
	}
	if r.ResourcePath != "" {
		obs = append(obs, provider.Observation{Path: "check.path", Value: r.ResourcePath, Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteRoute53HealthCheck(capability, environment, providerID string) provider.CreateResult {
	id, err := splitR53HCProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	tags, terr := d.r53hcTags(id)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed", Reason: "health check tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, e := d.r53Do("DELETE", "/2013-04-01/healthcheck/"+id, "")
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, "", nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
