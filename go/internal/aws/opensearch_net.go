// OpenSearch network shell (D113): the SigV4-signed, REST-JSON half of the AWS
// capability.search.index driver. CreateDomain is polled to Processing=false; the
// domain name is deterministic, so the providerId is knowable before the response
// (D29). Ownership is TAGS (ListTags on the domain ARN). D29/D87 honesty throughout.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

const openSearchPath = "/2021-01-01/opensearch"

func (d *Driver) openSearchBase(region string) string {
	if d.OpenSearchBaseURL != "" {
		return d.OpenSearchBaseURL
	}
	return "https://es." + region + ".amazonaws.com"
}

func openSearchProviderID(region, account, domain string) string {
	return "opensearch:" + region + ":" + account + ":" + domain
}

func splitOpenSearchProviderID(providerID string) (region, account, domain string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "opensearch" {
		return "", "", "", fmt.Errorf("providerId %q is not opensearch:region:account:domain", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !account12.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId account %q is invalid", parts[2])
	}
	if !osNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId domain %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func openSearchARN(region, account, domain string) string {
	return "arn:aws:es:" + region + ":" + account + ":domain/" + domain
}

func (d *Driver) openSearchDo(method, region, path string, body []byte) (int, []byte, error) {
	return d.doSigned(method, d.openSearchBase(region)+path, "es", region,
		map[string]string{"Content-Type": "application/json"}, body)
}

// osErr pulls a message out of an OpenSearch JSON error body.
func osErr(body []byte) string {
	var e struct {
		Message string `json:"message"`
		Msg     string `json:"Message"`
	}
	_ = json.Unmarshal(body, &e)
	if e.Message != "" {
		return boundMsg(e.Message)
	}
	if e.Msg != "" {
		return boundMsg(e.Msg)
	}
	return "" // D309: never the raw body — this string reaches a persisted receipt
}

type openSearchDomain struct {
	DomainName              string `json:"DomainName"`
	ARN                     string `json:"ARN"`
	Created                 bool   `json:"Created"`
	Deleted                 bool   `json:"Deleted"`
	Processing              bool   `json:"Processing"`
	EncryptionAtRestOptions struct {
		Enabled  bool   `json:"Enabled"`
		KmsKeyId string `json:"KmsKeyId"`
	} `json:"EncryptionAtRestOptions"`
	DomainEndpointOptions struct {
		EnforceHTTPS bool `json:"EnforceHTTPS"`
	} `json:"DomainEndpointOptions"`
	ClusterConfig struct {
		ZoneAwarenessEnabled bool `json:"ZoneAwarenessEnabled"`
	} `json:"ClusterConfig"`
	VPCOptions *struct {
		SubnetIds []string `json:"SubnetIds"`
	} `json:"VPCOptions"`
}

// describeDomain reads a domain. found=false + readable=true is authoritative
// "does not exist"; readable=false is a transport/HTTP/parse failure.
func (d *Driver) describeDomain(region, domain string) (openSearchDomain, bool, error) {
	const op = "DescribeDomain"
	st, resp, err := d.openSearchDo("GET", region, openSearchPath+"/domain/"+domain, nil)
	if err != nil {
		return openSearchDomain{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound || strings.Contains(osErr(resp), "ResourceNotFound") {
		return openSearchDomain{}, false, nil
	}
	if st != http.StatusOK {
		return openSearchDomain{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var out struct {
		DomainStatus openSearchDomain `json:"DomainStatus"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return openSearchDomain{}, false, readBody(op, st)
	}
	return out.DomainStatus, true, nil
}

// openSearchTags reads the domain's ownership tags. readable=false on any failure.
func (d *Driver) openSearchTags(region, account, domain string) (map[string]string, error) {
	const op = "ListTags"
	st, resp, err := d.openSearchDo("GET", region, openSearchPath+"/tags/?arn="+openSearchARN(region, account, domain), nil)
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, ecsErr(resp))
	}
	var out struct {
		TagList []struct {
			Key   string `json:"Key"`
			Value string `json:"Value"`
		} `json:"TagList"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range out.TagList {
		m[t.Key] = t.Value
	}
	return m, nil
}

func (d *Driver) createOpenSearch(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildOpenSearch(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := openSearchProviderID(region, account, plan.Domain)
	body, _ := json.Marshal(plan.createBody(region, account, capability, environment))
	st, resp, err := d.openSearchDo("POST", region, openSearchPath+"/domain", body)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK || st == http.StatusCreated:
		// creating — poll below
	case strings.Contains(osErr(resp), "ResourceAlreadyExists"):
		tags, terr := d.openSearchTags(region, account, plan.Domain)
		if terr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing domain tags gave no answer — reconcile: " + terr.Error()}
		}
		if !groundholdTagsMatch(tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a domain with this name exists and is not ours (tags do not match)"}
		}
		// ours — fall through to poll
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	default:
		if r := provider.MutationResult(st, osErr(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d (%s)", st, osErr(resp))}
	}

	deadline := d.Now().Add(d.PollTimeout)
	for {
		dom, found, rerr := d.describeDomain(region, plan.Domain)
		if rerr == nil && found && !dom.Processing {
			return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "domain still processing at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

func (d *Driver) observeOpenSearch(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, domain, err := splitOpenSearchProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	dom, found, rerr := d.describeDomain(region, domain)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"domain not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "encryption.atRest", Value: dom.EncryptionAtRestOptions.Enabled, Derivation: "measured"},
		{Path: "encryption.inTransit", Value: dom.DomainEndpointOptions.EnforceHTTPS, Derivation: "measured"},
		// a domain with VPCOptions is private; a public endpoint has none.
		{Path: "network.publicExposure", Value: dom.VPCOptions == nil, Derivation: "measured"},
	}
	if dom.ClusterConfig.ZoneAwarenessEnabled {
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "regional", Derivation: "measured"})
	} else {
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "zonal", Derivation: "measured"})
	}
	if dom.EncryptionAtRestOptions.KmsKeyId != "" {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: true, Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteOpenSearch(capability, environment, providerID string) provider.CreateResult {
	region, account, domain, err := splitOpenSearchProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	_, found, rerr := d.describeDomain(region, domain)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	tags, terr := d.openSearchTags(region, account, domain)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "domain tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, e := d.openSearchDo("DELETE", region, openSearchPath+"/domain/"+domain, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound || strings.Contains(osErr(resp), "ResourceNotFound") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		if r := provider.MutationResult(st, osErr(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d (%s)", st, osErr(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
