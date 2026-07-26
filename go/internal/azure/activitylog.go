// Azure Activity Log export request building (D76 parity, capability.audit.trail):
// the Azure half of the SAME vocabulary AWS CloudTrail and GCP Cloud Audit Logs
// fulfil — but Azure is a THIRD animal, and this file maps it HONESTLY rather than
// pretending a symmetry that does not exist.
//
// The model (the TWIN of the GCP log sink, NOT of a CloudTrail trail): the Azure
// Activity Log is ALWAYS on and subscription-global — there is no "trail" object to
// create. What an operator GOVERNS is the durable EXPORT of that log: a diagnostic
// setting (Microsoft.Insights/diagnosticSettings) on the SUBSCRIPTION scope, whose
// log categories select the Activity Log and whose destination is a durable ujście
// (a Log Analytics workspace / a Storage account / an Event Hub — each a SEPARATE
// capability the operator owns, D26). The diagnostic setting is the resource this
// driver stands up; the destination is an operand. This is exactly the GCP sink
// shape, so delivery.assured is measured, scope.multiRegion is honored/refused, and
// integrity.logValidation is refused — never faked.
//
// HONEST vocab mapping — several CloudTrail attributes have NO Azure analog on the
// diagnostic setting:
//   - location.region: a subscription diagnostic setting is a GLOBAL proxy resource;
//     the Activity Log is subscription-global. Residency lives in the DESTINATION
//     (workspace/account/hub), a separate capability. We accept location.region as a
//     declared residency assertion about that operand (validated), but it does NOT
//     enter the setting body and is NOT observable from the setting — observe OMITS it
//     with a diagnostic (never fabricated).
//   - scope.multiRegion: the Activity Log is subscription-global by construction, so a
//     subscription diagnostic setting captures every region. We honor true and REFUSE
//     false (a single-region audit scope is not expressible on Azure) — observe
//     reports true. This is the GCP auditlogs stance, verbatim.
//   - integrity.logValidation: Azure has NO CloudTrail log-file-validation equivalent
//     (no signed-digest tamper evidence for the Activity Log). We REFUSE true and
//     observe OMITS it with an unsupported diagnostic. This is the load-bearing honesty
//     of the whole driver: it is NEVER faked true.
//   - encryption.customerManagedKeys: CMK lives on the DESTINATION resource (the
//     storage account / workspace), not the diagnostic setting. true requires the
//     operand implementation.kms_key_name (a REFERENCE to a separate
//     capability.key.encryption); it does not enter the setting body and is OMITTED on
//     observe (the destination capability governs it).
//   - delivery.assured: the setting EXISTS and its Activity Log categories are ENABLED
//     and forwarding — the true Azure analog of StartLogging/IsLogging and of the GCP
//     sink's disabled flag. Measured from the live category enabled flags, mutable in
//     place via a diagnosticSettings PUT (the category enabled flags).
//   - service.managed: a managed export vs a self-operated pipeline.
//
// This file is PURE: it validates the shape and REFUSES before any mutation (an
// unmapped attribute, a missing/invalid operand, or an unsupportable guarantee is a
// preflight refusal, never a silent drop); activitylog_net.go drives the plan over the
// wire. Azure has NO credentials in this environment, so the driver is code + golden
// httptest certified, NOT live-validated — flagged honestly, never claimed proven.
package azure

import (
	"fmt"
	"regexp"
	"sort"
)

// activityLogAPIVersion is the Monitor diagnostic-settings control-plane version that
// supports subscription-scope settings.
const activityLogAPIVersion = "2021-05-01-preview"

// activityLogCategories is the canonical, ordered set of Activity Log categories a
// subscription diagnostic setting exports (the Azure equivalent of "all four audit
// log types" the GCP sink filter captures). The order is fixed so the request body is
// deterministic; a contract may restrict the set via the log_categories operand.
var activityLogCategories = []string{
	"Administrative", "Security", "ServiceHealth", "Alert",
	"Recommendation", "Policy", "Autoscale", "ResourceHealth",
}

func isActivityLogCategory(c string) bool {
	for _, k := range activityLogCategories {
		if k == c {
			return true
		}
	}
	return false
}

// diagSettingNameOK bounds a diagnostic-setting name before it is interpolated into a
// providerId or an ARM path (the D73 injection boundary). Diagnostic setting names
// forbid <>*%&:?+/\ and control chars; this is a conservative safe subset that
// azResourceName GENERATES (lowercase alnum+hyphen) while accepting the fuller set a
// hand-adopted setting might carry (letters/digits/._-), letter/digit-led, <=259.
var diagSettingNameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,258}$`)

// The three destination operand shapes the diagnostic-settings API accepts — each a
// REFERENCE to a SEPARATE capability the operator owns (never stood up here). The
// destination rides in the request BODY under a field determined by its type; a
// malformed destination is a malformed contract, refused in preflight.
var (
	logAnalyticsDestOK = regexp.MustCompile(
		`^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9._()-]{1,90}/providers/Microsoft\.OperationalInsights/workspaces/[A-Za-z0-9][A-Za-z0-9-]{2,62}$`)
	storageDestOK = regexp.MustCompile(
		`^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9._()-]{1,90}/providers/Microsoft\.Storage/storageAccounts/[a-z0-9]{3,24}$`)
	eventHubDestOK = regexp.MustCompile(
		`^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9._()-]{1,90}/providers/Microsoft\.EventHub/namespaces/[A-Za-z0-9-]{6,50}/authorizationRules/[A-Za-z0-9._-]{1,256}$`)
)

// activityLogDestField routes a destination operand to the diagnostic-setting body
// field it belongs in ("" + false when it is not one of the three durable ujścia).
func activityLogDestField(dest string) (string, bool) {
	switch {
	case logAnalyticsDestOK.MatchString(dest):
		return "workspaceId", true
	case storageDestOK.MatchString(dest):
		return "storageAccountId", true
	case eventHubDestOK.MatchString(dest):
		return "eventHubAuthorizationRuleId", true
	}
	return "", false
}

// activityLogRegionOK bounds a declared residency assertion (the destination's region,
// not the setting's — the setting has none). Accepts both "westeurope" and "West Europe".
var activityLogRegionOK = regexp.MustCompile(`^[A-Za-z0-9 ]{2,40}$`)

// azKmsKeyOK bounds the CMK operand: an Azure Key Vault key REFERENCE (a Key Vault key
// ARM resource id OR a key vault URI), never key material (D53). It names a key on the
// destination, a separate capability.key.encryption.
var azKmsKeyOK = regexp.MustCompile(
	`^(/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9._()-]{1,90}/providers/Microsoft\.KeyVault/vaults/[A-Za-z0-9-]{3,24}/keys/[A-Za-z0-9-]{1,127}` +
		`|https://[a-z0-9-]{3,24}\.vault\.azure\.net/keys/[A-Za-z0-9-]{1,127}(/[0-9a-f]{32})?)$`)

// activityLogName is the deterministic diagnostic-setting name — BOTH the idempotency
// handle (a PUT is create-or-update by name) AND the recovery handle (the providerId is
// knowable BEFORE the create response, D29). Diagnostic settings carry NO tags, so this
// content-addressed name IS the ownership marker (the changefeed/azcustomrole discipline):
// groundhold only ever mutates a setting at its own deterministic name. g>=2 (D48
// replacements) coexist via the generation salt.
func activityLogName(environment, capability string, generation int) string {
	return azResourceName("pv-al", environment, capability, generation)
}

// ActivityLogPlan is the attribute+operand-derived shape a create assembles. The
// setting SHAPE (whether it is delivering, which categories) is driven by capability
// attributes + operands; the destination, the setting name and the CMK reference are
// OPERATOR operands (implementation: block, D26).
type ActivityLogPlan struct {
	Subscription string
	Name         string
	Destination  string   // operand, required — the durable ujście
	DestField    string   // the body field the destination rides in
	Categories   []string // the Activity Log categories exported (ordered subset)
	Deliver      bool     // delivery.assured -> category enabled flags
	Region       string   // location.region: declared residency of the destination (NOT on the setting)
	CMK          bool     // encryption.customerManagedKeys — a destination property, declared here
	KmsKeyName   string   // operand, required IFF CMK (a reference to capability.key.encryption)
}

// BuildActivityLog maps capability.audit.trail attributes + implementation operands to
// a plan, or REFUSES. Every error is a preflight refusal (never a half-build): an
// unmapped attribute, an unsupportable guarantee (integrity.logValidation on Azure), a
// single-region audit scope, or a missing/invalid operand is refused here, before the
// first setting mutation (invariant #4, D26). delivery.assured defaults to true — a
// configured-but-disabled export is a silent audit gap, so the setting delivers by
// default unless the contract explicitly asks otherwise.
func BuildActivityLog(subscription, environment, capability string,
	attrs, impl map[string]any, generation int) (ActivityLogPlan, error) {
	if generation < 1 {
		generation = 1
	}
	if !subOK.MatchString(subscription) {
		return ActivityLogPlan{}, fmt.Errorf("azure subscription %q is not a valid GUID", subscription)
	}
	p := ActivityLogPlan{
		Subscription: subscription,
		Deliver:      true, // a setting that does not deliver is a dead export
		Categories:   activityLogCategories,
	}

	// --- CAPABILITY attributes drive the SHAPE (refuse any unmapped attribute) ---
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
			// residency of the DESTINATION operand; validated below. A subscription
			// diagnostic setting is global — it has no region, so this is a declared
			// assertion, not a setting field.
		case "scope.multiRegion":
			b, ok := raw.(bool)
			if !ok {
				return ActivityLogPlan{}, fmt.Errorf("scope.multiRegion must be a bool")
			}
			if !b {
				return ActivityLogPlan{}, fmt.Errorf(
					"scope.multiRegion=false cannot be honored — the Azure Activity Log is " +
						"subscription-global; a single-region audit scope is not expressible, and " +
						"groundhold refuses to pretend a subscription diagnostic setting is region-scoped")
			}
		case "integrity.logValidation":
			b, ok := raw.(bool)
			if !ok {
				return ActivityLogPlan{}, fmt.Errorf("integrity.logValidation must be a bool")
			}
			if b {
				return ActivityLogPlan{}, fmt.Errorf(
					"integrity.logValidation=true has NO Azure equivalent — Azure has no CloudTrail " +
						"log-file-validation (signed-digest tamper evidence) for the Activity Log; groundhold " +
						"refuses to claim a guarantee Azure does not provide (set it false or omit it)")
			}
		case "encryption.customerManagedKeys":
			b, ok := raw.(bool)
			if !ok {
				return ActivityLogPlan{}, fmt.Errorf("encryption.customerManagedKeys must be a bool")
			}
			p.CMK = b
		case "delivery.assured":
			b, ok := raw.(bool)
			if !ok {
				return ActivityLogPlan{}, fmt.Errorf("delivery.assured must be a bool")
			}
			p.Deliver = b
		case "service.managed":
			if raw != true {
				return ActivityLogPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored — groundhold manages the diagnostic setting it stands up")
			}
		default:
			return ActivityLogPlan{}, fmt.Errorf(
				"attribute %s has no Azure activity-log-export mapping — refusing rather than silently "+
					"dropping it (the audit.trail vocab governs scope.multiRegion, "+
					"integrity.logValidation, encryption.customerManagedKeys, delivery.assured and "+
					"location.region)", path)
		}
	}

	// location.region, when declared, must be a valid region string (the destination's
	// residency assertion). It is not enforced through the setting API — the destination
	// (a separate capability) owns residency — so we validate the shape and carry it.
	if p.Region != "" && !activityLogRegionOK.MatchString(p.Region) {
		return ActivityLogPlan{}, fmt.Errorf(
			"location.region %q is not a valid Azure region (it declares the residency of the "+
				"destination operand, a separate capability the operator owns)", p.Region)
	}

	// --- OPERATOR operands supply the placement (implementation: block, D26) ---
	// the destination is REQUIRED — a setting with no ujście exports to the void and is
	// not the durable audit record the contract asked for.
	p.Destination, _ = impl["destination"].(string)
	if p.Destination == "" {
		return ActivityLogPlan{}, fmt.Errorf(
			"implementation.destination is required (the durable ujście the diagnostic setting exports " +
				"the Activity Log to: a Microsoft.OperationalInsights/workspaces, a Microsoft.Storage/" +
				"storageAccounts, or a Microsoft.EventHub/.../authorizationRules resource id — a separate " +
				"capability the operator owns)")
	}
	field, ok := activityLogDestField(p.Destination)
	if !ok {
		return ActivityLogPlan{}, fmt.Errorf(
			"implementation.destination %q is not a recognized diagnostic-setting destination "+
				"(Log Analytics workspace / Storage account / Event Hub authorization rule)", p.Destination)
	}
	p.DestField = field

	// optional log_categories operand restricts the exported set (else the full Activity
	// Log set). Each must be a known Activity Log category — an unknown category is a
	// refusal, never a silently dropped selector.
	if rawCats, present := impl["log_categories"]; present {
		list, ok := rawCats.([]any)
		if !ok {
			return ActivityLogPlan{}, fmt.Errorf("implementation.log_categories must be a list of Activity Log category names")
		}
		if len(list) == 0 {
			return ActivityLogPlan{}, fmt.Errorf("implementation.log_categories must not be empty (omit it for the full Activity Log set)")
		}
		selected := make(map[string]bool, len(list))
		for _, item := range list {
			c, ok := item.(string)
			if !ok || !isActivityLogCategory(c) {
				return ActivityLogPlan{}, fmt.Errorf(
					"implementation.log_categories %v is not a known Activity Log category "+
						"(Administrative, Security, ServiceHealth, Alert, Recommendation, Policy, Autoscale, ResourceHealth)", item)
			}
			selected[c] = true
		}
		// preserve the canonical order (deterministic body), filtered by the selection.
		chosen := make([]string, 0, len(selected))
		for _, c := range activityLogCategories {
			if selected[c] {
				chosen = append(chosen, c)
			}
		}
		p.Categories = chosen
	}

	// the CMK is REQUIRED iff customer-managed encryption is asked for. The key name is
	// a REFERENCE (names a key on the destination), never key material (D53). Given but
	// not asked -> ambiguous. It lives on the DESTINATION, not the setting, so it is not
	// sent to the setting API — it is validated and carried as a declared assertion.
	p.KmsKeyName, _ = impl["kms_key_name"].(string)
	if p.CMK {
		if p.KmsKeyName == "" {
			return ActivityLogPlan{}, fmt.Errorf(
				"encryption.customerManagedKeys=true requires implementation.kms_key_name (a Key Vault " +
					"key on the destination, a separate capability.key.encryption) — refusing to claim CMK with no key")
		}
		if !azKmsKeyOK.MatchString(p.KmsKeyName) {
			return ActivityLogPlan{}, fmt.Errorf(
				"implementation.kms_key_name %q is not a valid Key Vault key reference", p.KmsKeyName)
		}
	} else if p.KmsKeyName != "" {
		return ActivityLogPlan{}, fmt.Errorf(
			"implementation.kms_key_name was given but encryption.customerManagedKeys is not true — " +
				"a customer key only attaches to CMK encryption; refusing an ambiguous shape")
	}

	// an optional setting-name operand (else the deterministic name), recoverable at
	// observe so a partial create repairs to the SAME setting.
	if given, _ := impl["diagnosticSettingName"].(string); given != "" {
		if !diagSettingNameOK.MatchString(given) {
			return ActivityLogPlan{}, fmt.Errorf(
				"implementation.diagnosticSettingName %q is invalid (letter/digit-led, alnum/._- , <=259)", given)
		}
		p.Name = given
	} else {
		p.Name = activityLogName(environment, capability, generation)
	}
	if !diagSettingNameOK.MatchString(p.Name) {
		return ActivityLogPlan{}, fmt.Errorf("derived diagnostic setting name %q is invalid", p.Name)
	}
	return p, nil
}

// createBody is the diagnosticSettings create/replace request body. The destination +
// enabled Activity Log categories make it an audit-log export; delivery.assured encodes
// the per-category enabled flag. The CMK/residency assertions do NOT appear — they are
// properties of the destination operand, not the setting.
func (p ActivityLogPlan) createBody() map[string]any {
	logs := make([]any, 0, len(p.Categories))
	for _, c := range p.Categories {
		logs = append(logs, map[string]any{"category": c, "enabled": p.Deliver})
	}
	props := map[string]any{"logs": logs}
	props[p.DestField] = p.Destination
	return map[string]any{"properties": props}
}

// classifyActivityLogChange (D46): PURE — can a capability.audit.trail transition be
// honored in place on an Azure diagnostic setting? delivery.assured is a single
// diagnosticSettings PUT (the category enabled flags). Everything else is either
// structural (scope), a property of the destination operand (residency, CMK — a
// destination replacement), or has no Azure analog at all (integrity) — each an HONEST
// unsupported/immutable, never a silent claim.
func classifyActivityLogChange(path string) (string, string) {
	switch path {
	case "delivery.assured":
		return "mutable", "in-place via diagnosticSettings PUT (Activity Log category enabled flags)"
	case "location.region", "encryption.customerManagedKeys":
		return "immutable", "residency/CMK live on the destination operand (a separate capability); a change is a replacement of the destination, not an in-place setting PUT"
	case "scope.multiRegion":
		return "unsupported", "the Azure Activity Log is subscription-global — scope is structural, nothing to patch"
	case "integrity.logValidation":
		return "unsupported", "Azure has no CloudTrail log-file-validation equivalent for the Activity Log — nothing to patch"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Azure activity-log-export in-place mapping for " + path
	}
}
