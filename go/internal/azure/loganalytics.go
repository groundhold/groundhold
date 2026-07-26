// Azure Log Analytics workspace request building (D76 parity): the Azure half of the
// capability.monitoring.logs driver — the SAME vocabulary AWS CloudWatch Logs (a log
// group, cwlogs) and GCP Cloud Logging (a log bucket, logbucket) fulfil. A Log
// Analytics workspace (Microsoft.OperationalInsights/workspaces) is the durable
// container Azure Monitor stores log events in; what an organization governs about it
// is WHERE the logs live (location.region), HOW LONG they are kept (retention.days ->
// properties.retentionInDays) and whether they use a CUSTOMER-managed key.
//
// STATEFUL: a workspace HOLDS logs, so destroying it loses history (D47 friction on
// delete, conservative-honest retirement). It is a SINGLE ARM resource carrying
// location, sku and retention in one create body — a cleaner map than the CloudWatch
// composite (CreateLogGroup + PutRetentionPolicy).
//
// Two honest asymmetries versus CloudWatch:
//  1. retention.days is a RANGE, not a fixed set. Azure accepts ANY whole-day value in
//     [30, 730] interactively; the builder validates that range and REFUSES a value
//     outside it (never silently clamps). Unlike CloudWatch, a workspace ALWAYS has a
//     retention (the service default is 30 days, never "keeps forever"), so retention.days
//     is OPTIONAL — absent, the workspace uses that bounded default (no unbounded-cost
//     trap to guard against, so no create-time requirement).
//  2. encryption.customerManagedKeys is REFUSED, not honored. A customer key over Log
//     Analytics is a DEDICATED-CLUSTER feature (Microsoft.OperationalInsights/clusters
//     with a committed-capacity tier + a cluster-level Key Vault key), NOT a property of
//     a standalone workspace — an honest one-cloud gap (refused, never silently
//     downgraded), the same stance as CMK on Azure Cache for Redis (D100).
package azure

import (
	"fmt"
	"regexp"
	"sort"

	"groundhold/internal/scalars"
)

const laAPIVersion = "2022-10-01"

// Azure Log Analytics interactive retention bounds (days). A duration outside this
// range is refused rather than clamped (over- or under-delivering on a guarantee).
const (
	laRetentionMinDays = 30
	laRetentionMaxDays = 730
)

// laSkuOK bounds the workspace pricing-tier operand (a conservative alnum charset).
var laSkuOK = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)

// LogAnalyticsPlan is the attribute-derived shape a create assembles into an ARM body.
type LogAnalyticsPlan struct {
	Name          string
	Region        string
	RetentionDays int    // one of [30,730]; 0 = unset (workspace uses the service default)
	Sku           string // pricing tier operand; default PerGB2018
}

// BuildLogAnalytics maps capability.monitoring.logs attributes + impl to a workspace
// plan. Every error is a preflight refusal apply surfaces, never a silent drop.
func BuildLogAnalytics(environment, capability string,
	attrs, impl map[string]any, generation int) (LogAnalyticsPlan, error) {
	p := LogAnalyticsPlan{
		Name: azResourceName("pv-la", environment, capability, generation),
		Sku:  "PerGB2018",
	}

	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "retention.days":
			days, err := laDurationToDays(raw)
			if err != nil {
				return LogAnalyticsPlan{}, fmt.Errorf("retention.days: %v", err)
			}
			if days < laRetentionMinDays || days > laRetentionMaxDays {
				return LogAnalyticsPlan{}, fmt.Errorf(
					"retention.days maps to %d day(s), which Azure Log Analytics does not accept — "+
						"it takes a whole-day value in [%d, %d] (refusing to silently clamp to the "+
						"nearest bound, which would over- or under-deliver on a retention guarantee)",
					days, laRetentionMinDays, laRetentionMaxDays)
			}
			p.RetentionDays = days
		case "encryption.customerManagedKeys":
			if raw == true {
				return LogAnalyticsPlan{}, fmt.Errorf(
					"encryption.customerManagedKeys is not honored on a Log Analytics workspace: a " +
						"customer key over Log Analytics is a DEDICATED-CLUSTER feature (a " +
						"Microsoft.OperationalInsights/clusters resource with a committed-capacity tier " +
						"and a cluster-level Key Vault key), not a property of a standalone workspace — " +
						"refusing rather than silently downgrading (honest one-cloud gap)")
			}
			// false -> the provider's default key, honored implicitly (nothing to set).
		case "service.managed":
			if raw != true {
				return LogAnalyticsPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored by Azure Log Analytics")
			}
		default:
			return LogAnalyticsPlan{}, fmt.Errorf(
				"attribute %s has no Azure Log Analytics mapping — refusing rather than silently "+
					"dropping it", path)
		}
	}

	if p.Region == "" {
		return LogAnalyticsPlan{}, fmt.Errorf("capability.monitoring.logs requires location.region")
	}

	// sku is an operand (D26): a pinned pricing tier overrides the default.
	if s, _ := impl["sku"].(string); s != "" {
		if !laSkuOK.MatchString(s) {
			return LogAnalyticsPlan{}, fmt.Errorf("implementation.sku %q is not a valid Log Analytics pricing tier", s)
		}
		p.Sku = s
	}
	if !azNameOK.MatchString(p.Name) {
		return LogAnalyticsPlan{}, fmt.Errorf("workspace name %q is not a valid Log Analytics workspace name", p.Name)
	}
	return p, nil
}

// laDurationToDays converts a retention.days duration scalar to whole days through the
// same scalar grammar the verifier uses (so "90d" and "2160h" are both accepted, unlike
// time.ParseDuration which rejects the day unit). A non-positive or fractional-day value
// is refused rather than truncated.
func laDurationToDays(raw any) (int, error) {
	s, err := scalars.Parse(raw)
	if err != nil || s.Kind != scalars.Duration {
		return 0, fmt.Errorf("must be a duration (e.g. \"90d\" or \"2160h\"), got %v", raw)
	}
	ms, ok := s.Value.(float64)
	if !ok || ms <= 0 {
		return 0, fmt.Errorf("must be a positive duration, got %v", raw)
	}
	const msPerDay = 86_400_000.0
	days := ms / msPerDay
	if days != float64(int(days)) {
		return 0, fmt.Errorf("must be a whole number of days, got %v", raw)
	}
	return int(days), nil
}

// createBody is the workspace PUT body (tags stamped at birth = ownership). sku +
// retention ride in properties; retentionInDays is omitted when unset so the workspace
// keeps the bounded service default.
func (p LogAnalyticsPlan) createBody(tags map[string]any) map[string]any {
	props := map[string]any{
		"sku": map[string]any{"name": p.Sku},
	}
	if p.RetentionDays > 0 {
		props["retentionInDays"] = p.RetentionDays
	}
	return map[string]any{
		"location":   p.Region,
		"tags":       tags,
		"properties": props,
	}
}

// classifyLogAnalyticsChange answers, per attribute, whether a workspace can honor the
// transition IN PLACE (D46) — PURE provider knowledge, no network. retention.days is a
// PATCH of properties.retentionInDays (mutable — an updater is wired, so this is never a
// mutable-without-updater lie); the region is the workspace's fixed home (a change is a
// replacement); CMK is a dedicated-cluster feature this driver does not offer.
func classifyLogAnalyticsChange(path string) (string, string) {
	switch path {
	case "retention.days":
		return "mutable", "" // PATCH properties.retentionInDays in place
	case "location.region":
		return "immutable", "a Log Analytics workspace lives in one region — moving it is a replacement"
	case "encryption.customerManagedKeys":
		return "unsupported", "CMK on Log Analytics is a dedicated-cluster feature, not a workspace property — not honored"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Log Analytics in-place mapping for " + path
	}
}
