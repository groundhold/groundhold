// GCP service account network shell (D121): the bearer-signed REST half of the
// capability.identity.serviceaccount driver. serviceAccounts.create is SYNCHRONOUS
// (no LRO). The accountId is deterministic, so the providerId is knowable before the
// create response (D29). Ownership is a DESCRIPTION MARKER (service accounts carry no
// labels). D29/D87 honesty throughout.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// iamBase is the shared IAM endpoint resolver, defined once in customrole_net.go
// (D105) and reused here (D121 dedup on rebase); both default to iam.googleapis.com/v1.

func gsaProviderID(project, accountID string) string {
	return "gsa:" + project + ":" + accountID
}

func splitGSAProviderID(providerID string) (project, accountID string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "gsa" {
		return "", "", fmt.Errorf("providerId %q is not gsa:project:accountId", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !gsaAccountIDOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId accountId %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

func gsaEmail(accountID, project string) string {
	return accountID + "@" + project + ".iam.gserviceaccount.com"
}

func (d *Driver) gsaURL(project, accountID string) string {
	return fmt.Sprintf("%s/projects/%s/serviceAccounts/%s", d.iamBase(), project, gsaEmail(accountID, project))
}

type gsaDoc struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
}

func (d *Driver) getGSA(project, accountID string) (gsaDoc, bool, error) {
	const op = "gSA.get"
	st, body, err := d.call("GET", d.gsaURL(project, accountID), nil)
	if err != nil {
		return gsaDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return gsaDoc{}, false, nil
	}
	if st != http.StatusOK {
		return gsaDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc gsaDoc
	if json.Unmarshal(body, &doc) != nil {
		return gsaDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createGServiceAccount(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildGServiceAccount(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := gsaProviderID(d.Project, plan.AccountID)
	url := fmt.Sprintf("%s/projects/%s/serviceAccounts", d.iamBase(), d.Project)
	st, body, err := d.call("POST", url, plan.createBody(capability, environment))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // synchronous
	case st == http.StatusConflict:
		// content-addressed: an existing account with our id + marker is ours.
		doc, found, rerr := d.getGSA(d.Project, plan.AccountID)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing account gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || !markerOurs(doc.Description, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a service account with this id exists and is not ours (marker does not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
	}
}

func (d *Driver) observeGServiceAccount(capability, providerID string) ([]provider.Observation, []string, error) {
	project, accountID, err := splitGSAProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getGSA(project, accountID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"service account not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// a service account has no downloadable key (keyless / workload identity).
		{Path: "key.exportable", Value: false, Derivation: "config-intent"},
	}
	if doc.DisplayName != "" {
		obs = append(obs, provider.Observation{Path: "display.name", Value: doc.DisplayName, Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteGServiceAccount(capability, environment, providerID string) provider.CreateResult {
	project, accountID, err := splitGSAProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getGSA(project, accountID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !markerOurs(doc.Description, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "service account marker does not match — refusing to delete a resource that is not ours"}
	}
	st, body, e := d.call("DELETE", d.gsaURL(project, accountID), nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		if r := provider.MutationResult(st, gcpErrCode(body), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
