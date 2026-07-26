// API Gateway v2 network shell (D119): the SigV4-signed, REST-JSON half of the AWS
// capability.apigateway.http driver. The ApiId is SERVER-ASSIGNED, so the providerId
// is parsed from the create response (DeterministicID=false). Ownership is TAGS
// (returned inline by GetApi). D29/D87 honesty throughout.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"groundhold/internal/provider"
)

const apigwPath = "/v2/apis"

// apigwIDOK bounds a server-assigned API id (10 lowercase alnum).
var apigwIDOK = regexp.MustCompile(`^[a-z0-9]{6,20}$`)

func (d *Driver) apigwBase(region string) string {
	if d.APIGatewayBaseURL != "" {
		return d.APIGatewayBaseURL
	}
	return "https://apigateway." + region + ".amazonaws.com"
}

func apigwProviderID(region, account, apiID string) string {
	return "apigw:" + region + ":" + account + ":" + apiID
}

func splitApiGWProviderID(providerID string) (region, account, apiID string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "apigw" {
		return "", "", "", fmt.Errorf("providerId %q is not apigw:region:account:apiId", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !account12.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId account %q is invalid", parts[2])
	}
	if !apigwIDOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId api %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) apigwDo(method, region, path string, body []byte) (int, []byte, error) {
	return d.doSigned(method, d.apigwBase(region)+path, "apigateway", region,
		map[string]string{"Content-Type": "application/json"}, body)
}

func apigwErr(body []byte) string {
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

type apigwAPI struct {
	ApiId        string            `json:"ApiId"`
	Name         string            `json:"Name"`
	ProtocolType string            `json:"ProtocolType"`
	ApiEndpoint  string            `json:"ApiEndpoint"`
	Tags         map[string]string `json:"Tags"`
}

func (d *Driver) getAPI(region, apiID string) (apigwAPI, bool, error) {
	const op = "GetApi"
	st, resp, err := d.apigwDo("GET", region, apigwPath+"/"+apiID, nil)
	if err != nil {
		return apigwAPI{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound || strings.Contains(apigwErr(resp), "NotFound") {
		return apigwAPI{}, false, nil
	}
	if st != http.StatusOK {
		return apigwAPI{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var api apigwAPI
	if json.Unmarshal(resp, &api) != nil {
		return apigwAPI{}, false, readBody(op, st)
	}
	return api, true, nil
}

func (d *Driver) createApiGWv2(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildApiGWv2(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	body, _ := json.Marshal(plan.createBody(capability, environment))
	st, resp, err := d.apigwDo("POST", region, apigwPath, body)
	switch {
	case err != nil:
		// server-assigned id and no idempotency token — a lost create genuinely loses
		// the handle, so unknown WITHOUT a pid is honest until the id-yielding response.
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed) — reconcile by name via GetApis: %v", err)}
	case st == http.StatusCreated || st == http.StatusOK:
		var api apigwAPI
		if json.Unmarshal(resp, &api) != nil || !apigwIDOK.MatchString(api.ApiId) {
			return provider.CreateResult{Status: "unknown", Reason: "create returned no api id — reconcile by name"}
		}
		return provider.CreateResult{ProviderID: apigwProviderID(region, account, api.ApiId), Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile by name", st)}
	default:
		if r := provider.MutationResult(st, apigwErr(resp), nil, "", "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d (%s)", st, apigwErr(resp))}
	}
}

func (d *Driver) observeApiGWv2(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, apiID, err := splitApiGWProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	api, found, rerr := d.getAPI(region, apiID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"api not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	switch api.ProtocolType {
	case "HTTP":
		obs = append(obs, provider.Observation{Path: "protocol", Value: "http", Derivation: "measured"})
	case "WEBSOCKET":
		obs = append(obs, provider.Observation{Path: "protocol", Value: "websocket", Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteApiGWv2(capability, environment, providerID string) provider.CreateResult {
	region, _, apiID, err := splitApiGWProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	api, found, rerr := d.getAPI(region, apiID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !groundholdTagsMatch(api.Tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "api tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, e := d.apigwDo("DELETE", region, apigwPath+"/"+apiID, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound || strings.Contains(apigwErr(resp), "NotFound") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, apigwErr(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d (%s)", st, apigwErr(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
