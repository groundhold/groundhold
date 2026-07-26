// GCP Cloud Monitoring uptime check network shell (D108): the bearer-signed half of
// the capability.monitoring.uptime driver. The config id is SERVER-ASSIGNED (parse
// from the response; a lost create is unknown). Ownership is userLabels. observe
// reverse-maps target/protocol/path/period from the config.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"groundhold/internal/provider"
)

var guptimeIDOK = regexp.MustCompile(`^[0-9A-Za-z_-]+$`)

func (d *Driver) uptimeBase() string {
	if d.UptimeBaseURL != "" {
		return d.UptimeBaseURL
	}
	return uptimeBaseURL
}

func guptimeProviderID(project, id string) string { return "guptime:" + project + ":" + id }

func splitGUptimeProviderID(providerID string) (project, id string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "guptime" {
		return "", "", fmt.Errorf("providerId %q is not guptime:project:id", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !guptimeIDOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId check id %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

func (d *Driver) createUptimeCheck(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildUptimeCheck(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	url := fmt.Sprintf("%s/projects/%s/uptimeCheckConfigs", d.uptimeBase(), d.Project)
	// create-adoption (D255): server-assigned id — bind an existing check with our
	// displayName instead of minting a duplicate.
	if id, found, ok := d.findByDisplayName(url, "uptimeCheckConfigs", plan.DisplayName); ok && found {
		return provider.CreateResult{ProviderID: guptimeProviderID(d.Project, id), Status: "succeeded"}
	}
	st, body, e := d.call("POST", url, plan.createBody(d.Project, capability, environment))
	if e != nil {
		if id, found, ok := d.findByDisplayName(url, "uptimeCheckConfigs", plan.DisplayName); ok && found {
			return provider.CreateResult{ProviderID: guptimeProviderID(d.Project, id), Status: "succeeded"}
		}
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed; reconcile by displayName %q): %v", plan.DisplayName, e)}
	}
	if st == http.StatusOK || st == http.StatusCreated {
		var doc struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(body, &doc) != nil || doc.Name == "" {
			return provider.CreateResult{Status: "unknown", Reason: "create response carried no config name — reconcile"}
		}
		id := doc.Name[strings.LastIndex(doc.Name, "/")+1:]
		return provider.CreateResult{ProviderID: guptimeProviderID(d.Project, id), Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed; reconcile by displayName) — %s", st, mutDetail(body))}
	}
	if r := provider.MutationResult(st, gcpErrCode(body), nil, "", "create"); r != nil {
		return *r
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
}

type uptimeDoc struct {
	UserLabels        map[string]string `json:"userLabels"`
	Period            string            `json:"period"`
	MonitoredResource struct {
		Labels map[string]string `json:"labels"`
	} `json:"monitoredResource"`
	HTTPCheck *struct {
		Path   string `json:"path"`
		UseSsl bool   `json:"useSsl"`
	} `json:"httpCheck"`
	TCPCheck *struct {
		Port int `json:"port"`
	} `json:"tcpCheck"`
}

func (d *Driver) getUptimeCheck(project, id string) (uptimeDoc, bool, error) {
	const op = "uptimeCheck.get"
	url := fmt.Sprintf("%s/projects/%s/uptimeCheckConfigs/%s", d.uptimeBase(), project, id)
	st, body, err := d.call("GET", url, nil)
	if err != nil {
		return uptimeDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return uptimeDoc{}, false, nil
	}
	if st != http.StatusOK {
		return uptimeDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc uptimeDoc
	if json.Unmarshal(body, &doc) != nil {
		return uptimeDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) observeUptimeCheck(capability, providerID string) ([]provider.Observation, []string, error) {
	project, id, err := splitGUptimeProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getUptimeCheck(project, id)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"uptime check not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "check.target", Value: doc.MonitoredResource.Labels["host"], Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if sec := strings.TrimSuffix(doc.Period, "s"); sec != "" {
		if n, e := strconv.Atoi(sec); e == nil {
			obs = append(obs, provider.Observation{Path: "check.period", Value: fmt.Sprintf("%ds", n), Derivation: "measured"})
		}
	}
	switch {
	case doc.TCPCheck != nil:
		obs = append(obs, provider.Observation{Path: "check.protocol", Value: "tcp", Derivation: "measured"})
	case doc.HTTPCheck != nil:
		proto := "http"
		if doc.HTTPCheck.UseSsl {
			proto = "https"
		}
		obs = append(obs, provider.Observation{Path: "check.protocol", Value: proto, Derivation: "measured"})
		if doc.HTTPCheck.Path != "" {
			obs = append(obs, provider.Observation{Path: "check.path", Value: doc.HTTPCheck.Path, Derivation: "measured"})
		}
	}
	return obs, nil, nil
}

func (d *Driver) deleteUptimeCheck(capability, environment, providerID string) provider.CreateResult {
	project, id, err := splitGUptimeProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getUptimeCheck(project, id)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.UserLabels["groundhold-capability"] != sanitizeLabel(capability) ||
		doc.UserLabels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed", Reason: "uptime check labels do not match — refusing to delete a resource that is not ours"}
	}
	url := fmt.Sprintf("%s/projects/%s/uptimeCheckConfigs/%s", d.uptimeBase(), project, id)
	st, body, e := d.call("DELETE", url, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, gcpErrCode(body), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
