// D255 — create-time adoption for the three server-assigned-id Cloud Monitoring
// resources (dashboard, alert policy, uptime check). Their id is minted by GCP on
// create, so a blind POST on a lost ledger mints a DUPLICATE (there is no
// deterministic name to collide on, unlike Cloud SQL / GCS / Cloud DNS which get a
// 409 and adopt). The deterministic ownership marker is the displayName; this
// paginated lookup finds ours and lets the create BIND it instead of duplicating —
// exactly the guard billingbudget already carries (findBillingBudgetByDisplayName).
package gcp

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// findByDisplayName scans a monitoring list (arrayKey is the JSON array field:
// "dashboards" | "alertPolicies" | "uptimeCheckConfigs") for a resource whose
// displayName matches ours — the deterministic per-(capability,environment,
// generation) marker. Paginates (a match on a later page missed would defeat the
// guard). readable=false on any transport/HTTP/parse failure (the caller then
// proceeds to the create rather than blocking a genuine first deploy).
func (d *Driver) findByDisplayName(listURL, arrayKey, displayName string) (id string, found, readable bool) {
	pageToken := ""
	for {
		u := listURL
		if pageToken != "" {
			u += "?pageToken=" + url.QueryEscape(pageToken)
		}
		st, body, err := d.call("GET", u, nil)
		if err != nil || st != http.StatusOK {
			return "", false, false
		}
		var raw map[string]json.RawMessage
		if json.Unmarshal(body, &raw) != nil {
			return "", false, false
		}
		var items []struct {
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
		}
		if arr, ok := raw[arrayKey]; ok {
			_ = json.Unmarshal(arr, &items)
		}
		for _, it := range items {
			if it.DisplayName == displayName {
				return leafName(it.Name), true, true
			}
		}
		var tok struct {
			NextPageToken string `json:"nextPageToken"`
		}
		_ = json.Unmarshal(body, &tok)
		if tok.NextPageToken == "" {
			return "", false, true
		}
		pageToken = tok.NextPageToken
	}
}
