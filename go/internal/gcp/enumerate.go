// Scope enumeration for the gentle crawl (D141): the GCP driver's answer to
// "which scopes can this credential see?" A GCP crawl scope is a PROJECT, so
// Enumerate lists the projects the acting identity can reach via Cloud Resource
// Manager projects.list and returns the ACTIVE ones. Strictly read-only.
//
// Endpoint (cloudresourcemanager.googleapis.com/v1):
//
//	ListProjects  GET  /projects   -> {projects:[{projectId, lifecycleState}], nextPageToken}
//
// Honesty: a partial enumeration is a fact, never a silently short list. If the
// list call is forbidden but a project is already pinned, we degrade to that one
// project and SAY SO in a diagnostic (the crawl still records the scope it can
// prove reachable). Any other failure — no pinned project to fall back to, a
// transport error, a server error — is a real error: the crawl records the
// enumeration as incomplete rather than fabricating an empty scope list.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// crmProjectsListPageCap bounds pagination so a misbehaving or hostile
// nextPageToken loop cannot spin forever (gentleness, D141).
const crmProjectsListPageCap = 100

// Enumerate lists the accessible GCP project IDs (the crawlable scopes). It
// follows pagination and filters to lifecycleState==ACTIVE. See the package doc
// for the fall-back-vs-error contract.
func (d *Driver) Enumerate() (scopes []string, diags []string, err error) {
	base := d.crmBase() + "/projects"
	var out []string
	pageToken := ""
	for page := 0; page < crmProjectsListPageCap; page++ {
		u := base
		if pageToken != "" {
			u = base + "?" + url.Values{"pageToken": {pageToken}}.Encode()
		}
		status, body, cerr := d.call("GET", u, nil)
		if cerr != nil {
			// Transport-level failure: we cannot know what is reachable. This is
			// never a permission denial we can reason about — report it.
			return nil, nil, fmt.Errorf("projects.list: %v", cerr)
		}
		if status == http.StatusForbidden || status == http.StatusUnauthorized {
			// The credential cannot enumerate projects. If a project is already
			// pinned, the crawl can still proceed against that single proven scope
			// — degrade with a diagnostic rather than fail the whole fan-out.
			if d.Project != "" {
				return []string{d.Project}, []string{fmt.Sprintf(
					"projects.list denied (HTTP %d); enumeration limited to the "+
						"pinned project %q", status, d.Project)}, nil
			}
			return nil, nil, fmt.Errorf(
				"projects.list: HTTP %d and no project pinned to fall back to", status)
		}
		if status != http.StatusOK {
			return nil, nil, fmt.Errorf("projects.list: HTTP %d: %s", status, mutDetail(body))
		}
		var resp struct {
			Projects []struct {
				ProjectID      string `json:"projectId"`
				LifecycleState string `json:"lifecycleState"`
			} `json:"projects"`
			NextPageToken string `json:"nextPageToken"`
		}
		if e := json.Unmarshal(body, &resp); e != nil {
			return nil, nil, fmt.Errorf("projects.list: bad response: %v", e)
		}
		for _, p := range resp.Projects {
			if p.ProjectID == "" || p.LifecycleState != "ACTIVE" {
				continue // non-ACTIVE (DELETE_REQUESTED, etc.) is not a crawlable scope
			}
			out = append(out, p.ProjectID)
		}
		if resp.NextPageToken == "" {
			return out, nil, nil
		}
		pageToken = resp.NextPageToken
	}
	// Ran out of page budget with a token still pending: an honest partial.
	return out, []string{fmt.Sprintf(
		"projects.list stopped after %d pages (more remain) — enumeration is partial",
		crmProjectsListPageCap)}, nil
}
