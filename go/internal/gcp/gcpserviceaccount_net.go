// GCP service account network shell (D121): the bearer-signed REST half of the
// capability.identity.serviceaccount driver. serviceAccounts.create is SYNCHRONOUS
// (no LRO). The accountId is deterministic, so the providerId is knowable before the
// create response (D29). Ownership is a DESCRIPTION MARKER (service accounts carry no
// labels). D29/D87 honesty throughout.
package gcp

import (
	"encoding/json"
	"fmt"
	"groundhold/internal/provider"
	"net/http"
	"sort"
	"strings"
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

// observeGServiceAccount reads the identity. The trust read is a SECOND call, so it is
// made here and not by the discovery sweep: a sweep touches every account in the project
// and doubling its calls would spend the crawl's budget on a question discovery does not
// ask (D141's gentle pace). The sweep passes withTrust=false and says so ONCE for the
// whole sweep — per account it would be one line per account, and a diagnostic nobody can
// read is not a disclosure. What it must not do is stay silent: an ABSENT trust.principals
// is not an empty one (D847), and the sweep is where that confusion would start.
func (d *Driver) observeGServiceAccount(capability, providerID string) ([]provider.Observation, []string, error) {
	return d.observeGServiceAccountTrust(capability, providerID, true)
}

func (d *Driver) observeGServiceAccountTrust(capability, providerID string, withTrust bool) ([]provider.Observation, []string, error) {
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
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"service account not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// a service account has no downloadable key (keyless / workload identity).
		{Path: "key.exportable", Value: false, Derivation: "config-intent"},
	}
	var diags []string

	// D868: WHO may assume this identity, from the account's OWN IAM policy. A second
	// read, and worth it: an identity's permissions say what it can do, and this says who
	// can pick it up — the half that changed silently until there was an attribute for it.
	if withTrust {
		if tp, ok := d.gsaTrustPrincipals(project, accountID); ok {
			obs = append(obs, provider.Observation{
				Path: "trust.principals", Value: tp, Derivation: "measured"})
		} else {
			diags = append(diags, "trust.principals not observed: the service account's IAM "+
				"policy gave no answer, so who may assume this identity was not established")
		}
	}
	if doc.DisplayName != "" {
		obs = append(obs, provider.Observation{Path: "display.name", Value: doc.DisplayName, Derivation: "measured"})
	}
	return obs, diags, nil
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

// assumeRoles are the GCP roles that let a principal PICK UP this identity (D868). Three,
// and the third is the one an audit forgets: `serviceAccountUser` does not mint a token
// directly, it lets a principal ATTACH the account to a resource they create — and the
// resource then runs AS the account. Leaving it out would under-report who can end up
// acting as this identity, and for a trust attribute the safe direction is to over-report.
var assumeRoles = map[string]bool{
	"roles/iam.serviceAccountTokenCreator": true,
	"roles/iam.workloadIdentityUser":       true,
	"roles/iam.serviceAccountUser":         true,
}

// trustPrincipals renders WHO may assume this service account, from its OWN IAM policy.
//
// The role rides with the member, because on GCP the three roles above grant different
// powers over one identity — minting a token is not the same as attaching the account to a
// VM — and a set of bare members would compare them equal. That is the same equality D776
// warned about on AWS, where the condition rather than the role is what a bare set loses.
// The binding's CONDITION rides too, for the same reason.
//
// ok=false means the policy did not answer — never an empty set, which is the
// safest-looking possible answer about who can act as an identity (D847).
func (d *Driver) gsaTrustPrincipals(project, accountID string) (principals []string, ok bool) {
	st, body, err := d.call("POST", d.gsaURL(project, accountID)+":getIamPolicy", map[string]any{})
	if err != nil || st != http.StatusOK {
		return nil, false
	}
	var doc struct {
		Bindings []struct {
			Role      string   `json:"role"`
			Members   []string `json:"members"`
			Condition struct {
				// `expression` only: the title is a label, and a name this decoder does not
				// use is a name nothing confirms against Google's own models.
				Expression string `json:"expression"`
			} `json:"condition"`
		} `json:"bindings"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil, false
	}
	seen := map[string]bool{}
	for _, b := range doc.Bindings {
		if !assumeRoles[b.Role] {
			continue
		}
		suffix := " via " + b.Role
		if e := strings.TrimSpace(b.Condition.Expression); e != "" {
			suffix += " if " + e
		}
		for _, m := range b.Members {
			seen[m+suffix] = true
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, true
}
