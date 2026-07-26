// Azure scope enumeration (D141/parity): the crawl scope for Azure is a
// SUBSCRIPTION, so a scopeless `groundhold pair azure` must fan out across every
// subscription the credential can see instead of silently crawling one.
// Enumerate lists them via the tenant-scoped ARM `GET /subscriptions` (bearer,
// the same signed control-plane plumbing the discoverers use), follows the
// nextLink pagination, and keeps only Enabled subscriptions. A subscription that
// is disabled/warned/deleted is not a crawlable scope. A failure to LIST is an
// error — never a fabricated empty list — except that when the tenant refuses the
// list but the driver already carries a configured subscription, that one is
// returned with a diagnostic (an honest partial enumeration, not a silent short
// list).
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

// compile-time proof the Azure driver satisfies the scope-enumeration contract.
var _ provider.Enumerator = (*Driver)(nil)

// subscriptionsAPIVersion is the tenant-scoped subscriptions-list contract.
const subscriptionsAPIVersion = "2020-01-01"

// Enumerate returns the subscription IDs the credential can see (state ==
// Enabled), the crawlable scopes the gentle crawl fans out to. Pagination is
// followed via nextLink; the loop is bounded so a misbehaving endpoint cannot
// spin forever.
func (d *Driver) Enumerate() (scopes []string, diags []string, err error) {
	url := fmt.Sprintf("%s/subscriptions?api-version=%s", d.BaseURL, subscriptionsAPIVersion)
	const maxPages = 100 // a hard bound: no tenant has this many subscription pages
	for page := 0; url != "" && page < maxPages; page++ {
		st, body, derr := d.doARM("GET", url, nil)
		if derr != nil {
			return nil, nil, fmt.Errorf("subscriptions.list: %v", derr)
		}
		if st == http.StatusForbidden || st == http.StatusUnauthorized {
			// The tenant refuses the list. Falling back to a fabricated empty
			// list would silently crawl nothing; instead surface the configured
			// subscription (if any) as an honest partial, else fail loudly.
			if subOK.MatchString(d.Subscription) {
				return []string{d.Subscription}, []string{fmt.Sprintf(
					"subscriptions.list refused (HTTP %d); enumerated only the configured subscription %s",
					st, d.Subscription)}, nil
			}
			return nil, nil, fmt.Errorf("subscriptions.list: HTTP %d and no configured subscription to fall back to", st)
		}
		if st != http.StatusOK {
			return nil, nil, fmt.Errorf("subscriptions.list: HTTP %d", st)
		}
		var listing struct {
			Value []struct {
				SubscriptionID string `json:"subscriptionId"`
				State          string `json:"state"`
			} `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if json.Unmarshal(body, &listing) != nil {
			return nil, nil, armBody("subscriptions.list", st)
		}
		for _, s := range listing.Value {
			if s.State != "Enabled" {
				continue // disabled/warned/past-due/deleted is not a crawlable scope
			}
			if s.SubscriptionID == "" {
				continue
			}
			scopes = append(scopes, s.SubscriptionID)
		}
		url = listing.NextLink
	}
	return scopes, diags, nil
}
