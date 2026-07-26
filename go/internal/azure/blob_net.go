// Azure Blob network shell (D99): the ARM half of the storage.object driver. The
// constitutive composite is created in a fixed sequence under ONE binding: storage
// account (async, poll provisioningState) -> blobServices/default settings ->
// container -> optional immutability policy (+one-way lock) -> optional lifecycle.
// The providerId is the container, carried from the account PUT (the first durable
// resource) so a partial is unknown/failed WITH the pid. Ownership is account tags;
// delete removes the account (which removes the whole composite). A WORM-locked
// container blocks deletion until expiry — surfaced, never forced.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func blobProviderID(sub, rg, account, container string) string {
	return "blob:" + sub + ":" + rg + ":" + account + ":" + container
}

func splitBlobProviderID(providerID string) (sub, rg, account, container string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 5 || parts[0] != "blob" {
		return "", "", "", "", fmt.Errorf("providerId %q is not blob:sub:rg:account:container", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) ||
		!storageNameOK.MatchString(parts[3]) || !azNameOK.MatchString(parts[4]) {
		return "", "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], parts[4], nil
}

func (d *Driver) acctPath(account string) string {
	return "Microsoft.Storage/storageAccounts/" + account
}

// createBlob runs the constitutive-composite create sequence.
func (d *Driver) createBlob(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildBlob(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure blob requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := blobProviderID(d.Subscription, rg, plan.Account, plan.Container)

	// ---- 1. storage account (the constitutive substrate; async) ----
	acctURL, _ := d.armURL(rg, d.acctPath(plan.Account), storageAPIVersion)
	acctProps := map[string]any{
		"allowBlobPublicAccess": plan.Public,
		"minimumTlsVersion":     "TLS1_2",
	}
	if plan.KmsKeyVaultURI != "" {
		acctProps["encryption"] = map[string]any{
			"keySource":                       "Microsoft.Keyvault",
			"keyvaultproperties":              map[string]any{"keyvaulturi": plan.KmsKeyVaultURI},
			"identity":                        map[string]any{"userAssignedIdentity": plan.KmsIdentity},
			"requireInfrastructureEncryption": false,
		}
	}
	acctBody, _ := json.Marshal(map[string]any{
		"location":   plan.Region,
		"kind":       "StorageV2",
		"sku":        map[string]any{"name": plan.SKU},
		"tags":       d.tags(capability, environment),
		"properties": acctProps,
	})
	if r := d.putAndPoll(acctURL, acctBody, pid, "storage account"); r != nil {
		return *r
	}

	// ---- 2. blobServices/default (versioning + change feed) ----
	bsURL, _ := d.armURL(rg, d.acctPath(plan.Account)+"/blobServices/default", storageAPIVersion)
	bsProps := map[string]any{"isVersioningEnabled": plan.Versioning}
	if plan.Replication {
		// object replication is driven by the source account's change feed; enable
		// it alongside versioning (both are source-side presuppositions we control).
		bsProps["changeFeed"] = map[string]any{"enabled": true}
	}
	bsBody, _ := json.Marshal(map[string]any{"properties": bsProps})
	if r := d.putSetting(bsURL, bsBody, pid, "blob-services"); r != nil {
		return *r
	}

	// ---- 3. container ----
	pubAccess := "None"
	if plan.Public {
		pubAccess = "Blob"
	}
	cURL, _ := d.armURL(rg, d.acctPath(plan.Account)+"/blobServices/default/containers/"+plan.Container, storageAPIVersion)
	cBody, _ := json.Marshal(map[string]any{
		"properties": map[string]any{"publicAccess": pubAccess}})
	if r := d.putSetting(cURL, cBody, pid, "container"); r != nil {
		return *r
	}

	// ---- 4. immutability policy (retention.minimum) + optional WORM lock ----
	if plan.RetentionMinDays > 0 {
		ipURL, _ := d.armURL(rg, d.acctPath(plan.Account)+"/blobServices/default/containers/"+plan.Container+"/immutabilityPolicies/default", storageAPIVersion)
		ipBody, _ := json.Marshal(map[string]any{
			"properties": map[string]any{"immutabilityPeriodSinceCreationInDays": plan.RetentionMinDays}})
		st, resp, e := d.doARM("PUT", ipURL, ipBody)
		if r := terminalOr(st, resp, e, pid, "immutability-policy"); r != nil {
			return *r
		}
		if plan.RetentionLocked {
			etag := jsonEtag(resp)
			if etag == "" {
				return provider.CreateResult{ProviderID: pid, Status: "unknown",
					Reason: "immutability policy created but no etag to lock it — reconcile"}
			}
			lockURL, _ := d.armURL(rg, d.acctPath(plan.Account)+"/blobServices/default/containers/"+plan.Container+"/immutabilityPolicies/default/lock", storageAPIVersion)
			// the lock is a POST with the policy etag as If-Match; one-way (WORM).
			lst, lresp, le := d.doARMIfMatch("POST", lockURL, nil, etag)
			if r := terminalOr(lst, lresp, le, pid, "immutability-lock"); r != nil {
				return *r
			}
		}
	}

	// ---- 5. lifecycle (retention.maximum) ----
	if plan.RetentionMaxDays > 0 {
		mpURL, _ := d.armURL(rg, d.acctPath(plan.Account)+"/managementPolicies/default", storageAPIVersion)
		mpBody, _ := json.Marshal(managementPolicyBody(plan.Container, plan.RetentionMaxDays))
		if r := d.putSetting(mpURL, mpBody, pid, "lifecycle-policy"); r != nil {
			return *r
		}
	}

	// ---- 6. object replication policy (replication.enabled) ----
	// Directional, source -> a destination account in another region (the S3 CRR
	// shape, not GCS dual-region). The policy must exist on BOTH accounts with a
	// matching policyId/ruleId: create on the DESTINATION first (Azure mints the
	// ids), then mirror onto the SOURCE. The destination account is an operand (a
	// separate capability.storage.object) — this driver points at it, never creates it.
	if plan.Replication {
		if r := d.createObjectReplication(rg, plan, pid); r != nil {
			return *r
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// createObjectReplication runs the two-account object-replication dance. Any
// non-2xx is mapped to a terminal result WITH the pid (a 5xx/transport error may
// have landed -> unknown; a 4xx -> failed), never a silent success.
func (d *Driver) createObjectReplication(rg string, plan BlobPlan, pid string) *provider.CreateResult {
	srcAcctID := fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s",
		d.Subscription, rg, plan.Account)
	rule := map[string]any{
		"sourceContainer":      plan.Container,
		"destinationContainer": plan.ReplicationDestContainer,
	}
	// step a: create on the DESTINATION account (policyId "default" -> Azure mints
	// the policyId + per-rule ruleId we must mirror onto the source).
	destBody, _ := json.Marshal(map[string]any{"properties": map[string]any{
		"sourceAccount":      srcAcctID,
		"destinationAccount": plan.ReplicationDestAccountID,
		"rules":              []any{rule},
	}})
	destURL := d.BaseURL + plan.ReplicationDestAccountID +
		"/objectReplicationPolicies/default?api-version=" + storageAPIVersion
	dst, dresp, de := d.doARM("PUT", destURL, destBody)
	if r := terminalOr(dst, dresp, de, pid, "object-replication (destination)"); r != nil {
		return r
	}
	policyID, ruleIDs := parseORPolicy(dresp)
	if !subOK.MatchString(policyID) {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "object replication policy created on the destination but no usable " +
				"policyId returned to mirror onto the source — reconcile"}
	}
	// step b: mirror the policy onto the SOURCE account with the minted ids.
	srcRule := map[string]any{
		"sourceContainer":      plan.Container,
		"destinationContainer": plan.ReplicationDestContainer,
	}
	if len(ruleIDs) > 0 && ruleIDs[0] != "" {
		srcRule["ruleId"] = ruleIDs[0]
	}
	srcBody, _ := json.Marshal(map[string]any{"properties": map[string]any{
		"policyId":           policyID,
		"sourceAccount":      srcAcctID,
		"destinationAccount": plan.ReplicationDestAccountID,
		"rules":              []any{srcRule},
	}})
	srcURL, err := d.armURL(rg, d.acctPath(plan.Account)+"/objectReplicationPolicies/"+policyID, storageAPIVersion)
	if err != nil {
		return &provider.CreateResult{ProviderID: pid, Status: "failed", Reason: err.Error()}
	}
	sst, sresp, se := d.doARM("PUT", srcURL, srcBody)
	return terminalOr(sst, sresp, se, pid, "object-replication (source)")
}

// parseORPolicy pulls the minted policyId + per-rule ruleIds out of an object
// replication policy response.
func parseORPolicy(resp []byte) (policyID string, ruleIDs []string) {
	var doc struct {
		Properties struct {
			PolicyID string `json:"policyId"`
			Rules    []struct {
				RuleID string `json:"ruleId"`
			} `json:"rules"`
		} `json:"properties"`
	}
	_ = json.Unmarshal(resp, &doc)
	for _, r := range doc.Properties.Rules {
		ruleIDs = append(ruleIDs, r.RuleID)
	}
	return doc.Properties.PolicyID, ruleIDs
}

func managementPolicyBody(container string, days int64) map[string]any {
	return map[string]any{"properties": map[string]any{"policy": map[string]any{
		"rules": []any{map[string]any{
			"enabled": true, "name": "groundhold-retention-maximum", "type": "Lifecycle",
			"definition": map[string]any{
				"filters": map[string]any{"blobTypes": []any{"blockBlob"},
					"prefixMatch": []any{container + "/"}},
				"actions": map[string]any{"baseBlob": map[string]any{
					"delete": map[string]any{"daysAfterModificationGreaterThan": days}}},
			},
		}},
	}}}
}

// putSetting is a settings PUT (no LRO): a 2xx is success; a 5xx/lost is
// unknown-with-pid; a 4xx/3xx is failed. Mirrors the S3 config-step honesty.
func (d *Driver) putSetting(url string, body []byte, pid, what string) *provider.CreateResult {
	// D254: a settings body is usually tagless (a child of our own resource) so this
	// is a no-op there, but if one ever PUTs a tag-owned body it must not overwrite a
	// foreign resource either.
	if r := d.refuseForeignUpsert(url, body); r != nil {
		return r
	}
	st, resp, err := d.doARM("PUT", url, body)
	return terminalOr(st, resp, err, pid, what)
}

// azErrCode extracts the normalized error code from an Azure JSON error body:
// {"error":{"code":"TooManyRequests","message":"..."}}. Empty when unparseable.
func azErrCode(body []byte) string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	return e.Error.Code
}

// terminalOr maps a mutation response to a terminal result (or nil on 2xx). D237:
// it routes through the shared classifier, so a throttle (429), server error, or
// live permission denial (403) is unknown with the providerId preserved (the
// mutation may have landed / a retry may land it), and only a clean 4xx refusal
// is a terminal failed.
func terminalOr(st int, resp []byte, err error, pid, what string) *provider.CreateResult {
	if r := provider.MutationResult(st, azErrCode(resp), err, pid, what); r != nil {
		return r
	}
	if st < 200 || st >= 300 {
		return &provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("%s HTTP %d: %s", what, st, mutDetailAz(resp))}
	}
	return nil
}

func jsonEtag(resp []byte) string {
	var d struct {
		Etag string `json:"etag"`
	}
	_ = json.Unmarshal(resp, &d)
	return d.Etag
}

// doARMIfMatch is doARM with an If-Match header (CAS for the WORM lock).
func (d *Driver) doARMIfMatch(method, url string, body []byte, etag string) (int, []byte, error) {
	// reuse doARM's auth path by temporarily... simplest: inline a request here.
	return d.doARMHeader(method, url, body, map[string]string{"If-Match": etag})
}

type blobAccountDoc struct {
	Location   string                `json:"location"`
	Tags       map[string]string     `json:"tags"`
	Sku        struct{ Name string } `json:"sku"`
	Properties struct {
		ProvisioningState     string `json:"provisioningState"`
		AllowBlobPublicAccess *bool  `json:"allowBlobPublicAccess"`
		Encryption            struct {
			KeySource string `json:"keySource"`
		} `json:"encryption"`
	} `json:"properties"`
}

func (d *Driver) observeBlob(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, account, container := "", "", "", ""
	var err error
	sub, rg, account, container, err = splitBlobProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	var doc blobAccountDoc
	found, rerr := d.armGetInto("storageAccounts.get", rg, d.acctPath(account),
		storageAPIVersion, &doc)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"storage account not found — nothing to observe"}, nil
	}
	var obs []provider.Observation
	var diags []string
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: strings.ToLower(doc.Location), Derivation: "measured"})
	}
	obs = append(obs,
		provider.Observation{Path: "service.managed", Value: true, Derivation: "measured"},
		provider.Observation{Path: "encryption.atRest", Value: true, Derivation: "config-intent"},
	)
	switch doc.Sku.Name {
	case "Standard_LRS":
		obs = append(obs, provider.Observation{Path: "durability.class", Value: "single-zone", Derivation: "measured"})
	case "Standard_ZRS":
		obs = append(obs, provider.Observation{Path: "durability.class", Value: "regional", Derivation: "measured"})
	case "Standard_GZRS":
		obs = append(obs, provider.Observation{Path: "durability.class", Value: "multi-regional", Derivation: "measured"})
	}
	if doc.Properties.AllowBlobPublicAccess != nil {
		obs = append(obs, provider.Observation{Path: "network.publicExposure",
			Value: *doc.Properties.AllowBlobPublicAccess, Derivation: "measured"})
	}
	if doc.Properties.Encryption.KeySource == "Microsoft.Keyvault" {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: true, Derivation: "measured"})
	}
	// retention.minimum / retention.locked: the container's immutability policy
	// (WORM). Absent (404) means no immutability protection — the paths are simply
	// absent, not an error.
	retObs, retDiags := d.observeBlobImmutability(rg, account, container)
	obs = append(obs, retObs...)
	diags = append(diags, retDiags...)
	// replication.enabled / replication.destinationRegion: object replication
	// policies on THIS (source) account. destinationRegion is the SUBSTANCE of DR
	// residency and is MEASURED from the destination account's location, never read
	// off the policy (parity with S3's GetBucketLocation-on-the-replica).
	repObs, repDiags := d.observeBlobReplication(rg, account)
	obs = append(obs, repObs...)
	diags = append(diags, repDiags...)
	diags = append(diags, "versioning observed on the account/blobServices child — reconcile for full detail")
	return obs, diags, nil
}

// observeBlobImmutability MEASURES the container's immutability policy: the
// period reverse-maps to retention.minimum (a day-granular duration floor), and
// the policy state (Locked vs Unlocked) reverse-maps to retention.locked (the
// WORM guarantee vs a soft, shortenable floor).
func (d *Driver) observeBlobImmutability(rg, account, container string) ([]provider.Observation, []string) {
	ipURL, err := d.armURL(rg,
		d.acctPath(account)+"/blobServices/default/containers/"+container+"/immutabilityPolicies/default",
		storageAPIVersion)
	if err != nil {
		return nil, []string{"retention.minimum not observed: " + err.Error()}
	}
	st, resp, e := d.doARM("GET", ipURL, nil)
	if e != nil {
		return nil, []string{"retention.minimum not observed: " +
			azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return nil, nil // not immutability-protected — absent, not an error
	}
	if st != http.StatusOK {
		return nil, []string{fmt.Sprintf("retention.minimum not observed: immutabilityPolicies.get HTTP %d", st)}
	}
	var doc struct {
		Properties struct {
			Days  *int   `json:"immutabilityPeriodSinceCreationInDays"`
			State string `json:"state"`
		} `json:"properties"`
	}
	if json.Unmarshal(resp, &doc) != nil {
		return nil, []string{"retention.minimum not observed: immutabilityPolicies.get unparseable"}
	}
	if doc.Properties.Days == nil || *doc.Properties.Days <= 0 {
		return nil, nil // no active floor
	}
	return []provider.Observation{
		{Path: "retention.minimum", Value: fmt.Sprintf("%dd", *doc.Properties.Days), Derivation: "measured"},
		{Path: "retention.locked", Value: doc.Properties.State == "Locked", Derivation: "measured"},
	}, nil
}

// observeBlobReplication MEASURES object replication on THIS (source) account. A
// policy whose sourceAccount is us marks this capability as replicating; the
// destination region is measured from the destination account's own location.
func (d *Driver) observeBlobReplication(rg, account string) ([]provider.Observation, []string) {
	orpURL, err := d.armURL(rg, d.acctPath(account)+"/objectReplicationPolicies", storageAPIVersion)
	if err != nil {
		return nil, []string{"replication.enabled not observed: " + err.Error()}
	}
	st, resp, e := d.doARM("GET", orpURL, nil)
	if e != nil {
		return nil, []string{"replication.enabled not observed: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return []provider.Observation{{Path: "replication.enabled", Value: false, Derivation: "measured"}}, nil
	}
	if st != http.StatusOK {
		return nil, []string{fmt.Sprintf("replication.enabled not observed: objectReplicationPolicies.list HTTP %d", st)}
	}
	var doc struct {
		Value []struct {
			Properties struct {
				SourceAccount      string `json:"sourceAccount"`
				DestinationAccount string `json:"destinationAccount"`
			} `json:"properties"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &doc) != nil {
		return nil, []string{"replication.enabled not observed: objectReplicationPolicies.list unparseable"}
	}
	destAccount := ""
	for _, p := range doc.Value {
		// a policy where WE are the source (not merely a replica target) marks this
		// capability as replicating. The account field is a resource id or bare name.
		if accountNameOf(p.Properties.SourceAccount) == account {
			destAccount = p.Properties.DestinationAccount
			break
		}
	}
	obs := []provider.Observation{{Path: "replication.enabled", Value: destAccount != "", Derivation: "measured"}}
	if destAccount == "" {
		return obs, nil
	}
	reg, ok, diag := d.blobDestinationRegion(destAccount)
	var diags []string
	if diag != "" {
		diags = append(diags, diag)
	}
	if ok {
		obs = append(obs, provider.Observation{Path: "replication.destinationRegion", Value: reg, Derivation: "measured"})
	}
	return obs, diags
}

// blobDestinationRegion MEASURES the destination account's region — the region
// lives on the account, not in the replication policy, so residency is measured
// (mierzona) not read off the rule. A bare-name destination carries no region.
func (d *Driver) blobDestinationRegion(destAccount string) (region string, ok bool, diag string) {
	if !storageAccountIDOK.MatchString(destAccount) {
		return "", false, fmt.Sprintf(
			"replication.destinationRegion not observed: destination account %q is not a full "+
				"resource id to read a location from", destAccount)
	}
	url := d.BaseURL + destAccount + "?api-version=" + storageAPIVersion
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil || st != http.StatusOK {
		return "", false, "replication.destinationRegion not observed: " +
			azReadWhy(st, resp, e)
	}
	var doc struct {
		Location string `json:"location"`
	}
	if json.Unmarshal(resp, &doc) != nil || doc.Location == "" {
		return "", false, "replication.destinationRegion not observed: the destination " +
			"account answered HTTP 200 without a usable location"
	}
	return azRegion(doc.Location), true, ""
}

// accountNameOf extracts the account name from a resource id or bare-name field.
func accountNameOf(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// classifyBlobChange (D46): PURE — can this capability.storage.object transition
// be honored in place? The blob binding is a CONSTITUTIVE COMPOSITE anchored on
// the storage account and has NO in-place updater wired, so a change to a
// honored attribute is a replacement of the stateful account (consented via
// allow_replace_stateful, D48), never a silent "mutable" the driver cannot then
// apply. Two attributes are called out explicitly for parity with S3:
//   - retention.minimum/locked: WORM. A LOCKED immutability policy is
//     irreversible and its floor can only be EXTENDED; enablement is effectively
//     a foundation. Treated as immutable (replacement), the S3 Object Lock choice.
//   - replication.enabled/destinationRegion: Azure object replication IS
//     reconfigurable in place, but the blob driver has no updater — so rather
//     than a mutable-without-a-safe-updater gap, a change is a replacement.
//
// Everything else stays "unsupported" (the prior default) — nothing silently
// widens.
func classifyBlobChange(path string) (string, string) {
	switch path {
	case "location.region":
		return "immutable", "a storage account's region is fixed at creation — a change is a replacement"
	case "durability.class":
		return "immutable", "the storage account SKU/redundancy is fixed at creation — a change is a replacement"
	case "retention.minimum", "retention.locked":
		return "immutable", "an immutability policy (WORM) is a create-time foundation — a " +
			"locked floor is irreversible and can only be extended; a change is a replacement"
	case "replication.enabled", "replication.destinationRegion":
		return "immutable", "object replication is not wired for in-place update on the blob " +
			"driver — a change is a replacement of the stateful account (never a mutable-without-updater gap)"
	default:
		return "unsupported", "no azure blob in-place mapping for " + path
	}
}

func (d *Driver) deleteBlob(capability, environment, providerID string) provider.CreateResult {
	_, rg, account, _, err := splitBlobProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	acctURL, _ := d.armURL(rg, d.acctPath(account), storageAPIVersion)
	// ownership pre-read on the account (the substrate carries our tags).
	st, resp, e := d.doARM("GET", acctURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc blobAccountDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "storage account tags do not match — refusing to delete a resource that is not ours"}
	}
	// deleting the account removes the whole composite. A WORM-locked container
	// blocks it (409) — surfaced, never forced.
	dst, dresp, de := d.doARM("DELETE", acctURL, nil)
	if de != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", de)}
	}
	if dst == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if dst == http.StatusConflict {
		return provider.CreateResult{Status: "failed",
			Reason: "the account has a WORM-locked container — retirement is blocked until the " +
				"immutability period expires; never forced: " + mutDetailAz(dresp)}
	}
	if dst >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", dst)}
	}
	if dst < 200 || dst >= 300 {
		// D237: throttle/503/live-403 -> unknown (keep the handle), never failed.
		if r := provider.MutationResult(dst, azErrCode(dresp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d", dst)}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
