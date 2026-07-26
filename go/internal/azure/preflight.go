// Permission preflight (D75), the Azure half. The deterministic permission TABLE
// lives in provider.PermissionsFor ("azure" case); this is only the LIVE check, via
// the ARM Microsoft.Authorization/permissions list — the caller's EFFECTIVE RBAC
// actions at a scope.
//
// Evidence, not proof: the permissions list reflects role ASSIGNMENTS visible at the
// queried scope; it does not surface DENY assignments, ABAC conditions, or
// management-group policy evaluated at write time. A pass can still fail mid-apply;
// write-ahead receipts remain the recovery story.
//
// Honesty (D78 applied to Azure). At the SUBSCRIPTION scope, a required action no
// assignment grants is UNATTESTED, not denied — a role assigned at a narrower
// (resource-group/resource) scope would not appear here, so absence is not
// authoritative. At the RESOURCE scope (CheckResourcePermissions) the effective
// permissions include every inherited assignment, so an ungranted action IS a real
// denial. groundhold must never refuse an authorized user.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"groundhold/internal/provider"
)

// compile-time proof the Azure driver satisfies both preflight interfaces.
var (
	_ provider.Preflighter         = (*Driver)(nil)
	_ provider.ResourcePreflighter = (*Driver)(nil)
)

const azAuthAPIVersion = "2022-04-01"

type azPermEntry struct {
	Actions    []string `json:"actions"`
	NotActions []string `json:"notActions"`
}

// effectivePermissions GETs the caller's effective RBAC permission entries at an ARM
// scope (a subscription path or a full resource id). A non-nil error is inconclusive
// (never a denial): transport, a non-200 (e.g. the caller lacks
// Microsoft.Authorization/permissions/read), or a bad body.
func (d *Driver) effectivePermissions(scope string) ([]azPermEntry, error) {
	url := d.BaseURL + scope + "/providers/Microsoft.Authorization/permissions?api-version=" + azAuthAPIVersion
	st, body, err := d.doARM("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("Authorization/permissions: %w", err)
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("Authorization/permissions HTTP %d at %s "+
			"(the acting identity needs Microsoft.Authorization/permissions/read): %s",
			st, scope, mutDetailAz(body))
	}
	var out struct {
		Value []azPermEntry `json:"value"`
	}
	if json.Unmarshal(body, &out) != nil {
		return nil, fmt.Errorf("Authorization/permissions: bad response")
	}
	return out.Value, nil
}

// azActionAllowed: RBAC grants an action when some entry's Actions match it and that
// SAME entry's NotActions do not (notActions subtract within a role; allows union
// across roles).
func azActionAllowed(perms []azPermEntry, action string) bool {
	for _, e := range perms {
		if azMatchAny(e.Actions, action) && !azMatchAny(e.NotActions, action) {
			return true
		}
	}
	return false
}

func azMatchAny(patterns []string, action string) bool {
	for _, p := range patterns {
		if azGlob(p, action) {
			return true
		}
	}
	return false
}

// azGlob matches an RBAC action pattern where '*' globs any run of characters
// (including '/'), case-insensitively — e.g. "Microsoft.Cache/*" matches
// "Microsoft.Cache/Redis/write".
func azGlob(pattern, action string) bool {
	segs := strings.Split(pattern, "*")
	for i := range segs {
		segs[i] = regexp.QuoteMeta(segs[i])
	}
	m, _ := regexp.MatchString("(?i)^"+strings.Join(segs, ".*")+"$", action)
	return m
}

// CheckPermissions implements provider.Preflighter — the subscription-scope check.
// A granted action passes; an ungranted one is UNATTESTED (a narrower-scope
// assignment may grant it), never denied. The subscription surface carries no
// authoritative-denial signal (deny assignments are not returned here), so `denied`
// is always empty at this scope — the resource check is where a negative is trusted.
func (d *Driver) CheckPermissions(subscription string, permissions []string) (denied, unattested []string, err error) {
	if len(permissions) == 0 {
		return nil, nil, nil
	}
	sub := subscription
	if sub == "" {
		sub = d.Subscription
	}
	if !subOK.MatchString(sub) {
		return nil, nil, fmt.Errorf("no valid subscription to preflight against")
	}
	perms, err := d.effectivePermissions("/subscriptions/" + sub)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range permissions {
		if !azActionAllowed(perms, p) {
			unattested = append(unattested, p)
		}
	}
	sort.Strings(unattested)
	return nil, unattested, nil
}

// CheckResourcePermissions implements provider.ResourcePreflighter — the
// AUTHORITATIVE check for an EXISTING resource. The permissions list at the
// resource's own scope includes every inherited (subscription/RG/resource)
// assignment, so an ungranted action IS a real denial. Services whose resource id
// cannot be reconstructed from the providerID return ErrNoResourceSurface → the
// caller falls back to the subscription check (unattested, safe). Any error is
// inconclusive, never a denial.
func (d *Driver) CheckResourcePermissions(service, providerID string, permissions []string) ([]string, error) {
	if len(permissions) == 0 {
		return nil, nil
	}
	resID, ok := azResourceID(service, providerID)
	if !ok {
		return nil, provider.ErrNoResourceSurface
	}
	perms, err := d.effectivePermissions(resID)
	if err != nil {
		return nil, err
	}
	var denied []string
	for _, p := range permissions {
		if !azActionAllowed(perms, p) {
			denied = append(denied, p)
		}
	}
	sort.Strings(denied)
	return denied, nil
}

// azResourceID reconstructs an ARM resource id from a providerID for services whose
// id is a pure function of it. Conservative: an unmapped service returns ok=false →
// the subscription "*" fallback (unattested, never a false denial). More services
// join as their type path is confirmed.
func azResourceID(service, providerID string) (string, bool) {
	sub, rg, name, err := "", "", "", error(nil)
	var typePath string
	switch service {
	case "flexpostgres":
		sub, rg, name, err = splitFlexProviderID(providerID)
		typePath = "Microsoft.DBforPostgreSQL/flexibleServers"
	case "aks":
		sub, rg, name, err = splitAKSProviderID(providerID)
		typePath = "Microsoft.ContainerService/managedClusters"
	case "rediscache":
		sub, rg, name, err = splitRedisAzureProviderID(providerID)
		typePath = "Microsoft.Cache/Redis"
	case "cosmos":
		sub, rg, name, err = splitCosmosProviderID(providerID)
		typePath = "Microsoft.DocumentDB/databaseAccounts"
	default:
		return "", false
	}
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/%s/%s", sub, rg, typePath, name), true
}
