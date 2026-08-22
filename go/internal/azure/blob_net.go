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
	// D1198 (owner decision, supersedes D989 for object storage): network.publicExposure
	// is ANONYMOUS DATA ACCESS, unified with AWS S3 within this capability — so it drives
	// allowBlobPublicAccess (and the container's publicAccess below), NOT publicNetworkAccess.
	// The account stays network-reachable (Enabled, like an always-reachable S3 bucket);
	// network-level lockdown is a separate concern this object-storage attribute no longer
	// expresses. allowBlobPublicAccess gates whether any container may be anonymous.
	acctProps := map[string]any{
		"publicNetworkAccess":   "Enabled",
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

// patchSetting PATCHes a partial property update onto a resource the caller has ALREADY
// ownership-checked (a PATCH leaves untouched properties alone). Four-valued via
// terminalOr; nil on success.
func (d *Driver) patchSetting(url string, body []byte, pid, what string) *provider.CreateResult {
	st, resp, err := d.doARM("PATCH", url, body)
	return terminalOr(st, resp, err, pid, what)
}

// azErrCode extracts the normalized error code from an Azure JSON error body:
// {"error":{"code":"TooManyRequests","message":"..."}}. Empty when unparseable.
func azErrCode(body []byte) string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
		// D929: some ARM errors (AKS managedClusters 400, etc.) carry {"code","message"}
		// at the TOP LEVEL rather than wrapped in "error" — fall back to it so the code
		// (e.g. K8sVersionNotSupported) is not swallowed.
		Code string `json:"code"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	if e.Error.Code != "" {
		return e.Error.Code
	}
	return e.Code
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
		PublicNetworkAccess   string `json:"publicNetworkAccess"`
		AllowBlobPublicAccess *bool  `json:"allowBlobPublicAccess"`
		Encryption            struct {
			KeySource string `json:"keySource"`
		} `json:"encryption"`
		// D1204: an in-progress redundancy migration is reported on the account itself,
		// so observe surfaces it for FREE from this same GET (no accountMigrations read).
		StorageAccountSkuConversionStatus struct {
			SkuConversionStatus string `json:"skuConversionStatus"`
			TargetSkuName       string `json:"targetSkuName"`
		} `json:"storageAccountSkuConversionStatus"`
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
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"storage account not found — bound resource is gone (will re-create)"}, nil
	}
	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
	}
	var diags []string
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: strings.ToLower(doc.Location), Derivation: "measured"})
	}
	obs = append(obs,
		provider.Observation{Path: "service.managed", Value: true, Derivation: "measured"},
		provider.Observation{Path: "encryption.atRest", Value: true, Derivation: "platform-invariant"},
	)
	switch doc.Sku.Name {
	case "Standard_LRS":
		obs = append(obs, provider.Observation{Path: "durability.class", Value: "single-zone", Derivation: "measured"})
	case "Standard_ZRS":
		obs = append(obs, provider.Observation{Path: "durability.class", Value: "regional", Derivation: "measured"})
	case "Standard_GZRS":
		obs = append(obs, provider.Observation{Path: "durability.class", Value: "multi-regional", Derivation: "measured"})
	}
	// D1204: durability.class is MEASURED from the standing SKU, which stays the OLD value
	// during an async redundancy migration (up to 72h). Surface the in-progress conversion —
	// read for free from this same account GET — so a read (observe/verify/posture) shows the
	// account is CONVERTING, not that the change silently failed to take. The value stays the
	// current SKU's class (honest: the redundancy IS still that until the migration completes).
	if cs := doc.Properties.StorageAccountSkuConversionStatus; cs.SkuConversionStatus == "InProgress" {
		tgt := blobSkuDurability(cs.TargetSkuName)
		if tgt == "" {
			tgt = cs.TargetSkuName
		}
		diags = append(diags, fmt.Sprintf("durability.class: a redundancy migration to %s is IN PROGRESS "+
			"(async, up to 72h) — the value above is the standing SKU and converts when the migration completes", tgt))
	}
	// network.publicExposure (D1198, owner decision): for capability.storage.object this
	// is ANONYMOUS DATA ACCESS — the same question AWS S3 answers, and the GDPR/data-
	// exposure intent of the control — NOT the network reachability D989 read from
	// publicNetworkAccess (the meaning every OTHER Azure driver keeps, but which made one
	// attribute mean two things across clouds within one capability). Anonymous access
	// needs the account to ALLOW it (allowBlobPublicAccess) AND the container to be set to
	// it (publicAccess). An account with allowBlobPublicAccess=false blocks all anonymous
	// access account-wide — the definitive not-public case (Azure's twin of an S3 Block
	// Public Access), no container read needed.
	if doc.Properties.AllowBlobPublicAccess != nil && !*doc.Properties.AllowBlobPublicAccess {
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: false, Derivation: "measured"})
	} else if level, known := d.blobContainerPublicAccess(rg, account, container); known {
		public := level == "Blob" || level == "Container"
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: public, Derivation: "measured"})
	} else {
		diags = append(diags, "network.publicExposure not observed: allowBlobPublicAccess does not block anonymous "+
			"access and the container's publicAccess could not be read — anonymous exposure undetermined (never fabricated private)")
	}
	obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: doc.Properties.Encryption.KeySource == "Microsoft.Keyvault", Derivation: "measured"})
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
	// retention.maximum: the lifecycle expiry create writes as a management policy.
	// D471 — this was WRITTEN and never read back, while its S3 twin has always read
	// the lifecycle Expiration rule. An attribute realised on one cloud and invisible
	// on the other is the same declaration answering `satisfied` in one estate and
	// `unverifiable` in the other.
	lcObs, lcDiags := d.observeBlobLifecycle(rg, account, container)
	obs = append(obs, lcObs...)
	diags = append(diags, lcDiags...)
	diags = append(diags, "versioning observed on the account/blobServices child — reconcile for full detail")
	return obs, diags, nil
}

// observeBlobImmutability MEASURES the container's immutability policy: the
// period reverse-maps to retention.minimum (a day-granular duration floor), and
// the policy state (Locked vs Unlocked) reverse-maps to retention.locked (the
// WORM guarantee vs a soft, shortenable floor).
// blobSkuZonal reports whether a storage SKU is ZONE-redundant (ZRS/GZRS). Flipping this
// dimension (LRS<->ZRS/GZRS) needs a customer-initiated migration; a change that keeps it
// (ZRS<->GZRS, only the geo dimension moving) is a synchronous SKU PATCH.
func blobSkuZonal(sku string) bool { return strings.Contains(sku, "ZRS") }

// blobSkuDurability reverse-maps a storage SKU to a durability.class ("" if unrecognized).
func blobSkuDurability(sku string) string {
	switch sku {
	case "Standard_LRS":
		return "single-zone"
	case "Standard_ZRS":
		return "regional"
	case "Standard_GZRS":
		return "multi-regional"
	}
	return ""
}

// blobContainerPublicAccess reads the container's anonymous-access level (None / Blob /
// Container) from its ARM properties. known=false when the container was unreadable, so
// the caller withholds rather than fabricating "private". Azure omits publicAccess for a
// private container, which reads as "None".
func (d *Driver) blobContainerPublicAccess(rg, account, container string) (level string, known bool) {
	cURL, err := d.armURL(rg,
		d.acctPath(account)+"/blobServices/default/containers/"+container, storageAPIVersion)
	if err != nil {
		return "", false
	}
	st, resp, e := d.doARM("GET", cURL, nil)
	if e != nil || st != http.StatusOK {
		return "", false
	}
	var doc struct {
		Properties struct {
			PublicAccess string `json:"publicAccess"`
		} `json:"properties"`
	}
	if json.Unmarshal(resp, &doc) != nil {
		return "", false
	}
	if doc.Properties.PublicAccess == "" {
		return "None", true
	}
	return doc.Properties.PublicAccess, true
}

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
		// D1041/D1069-class: a 404 is AUTHORITATIVE "no immutability policy", not a read
		// failure — a container with no WORM policy is definitively NOT compliance-locked,
		// a MEASURED false. Emitting nothing let a `retention.locked: true` candidate be
		// adopted/verified as satisfied over a freely-mutable container (a permanent false
		// WORM assurance — immutability is create-time, no converge could make it true).
		// retention.minimum stays absent: there is genuinely no floor (the S3 decision).
		return []provider.Observation{
			{Path: "retention.locked", Value: false, Derivation: "measured"},
		}, nil
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
		// a policy row with no active floor is also not WORM-locked — measured false,
		// same as the no-policy case (retention.minimum genuinely absent).
		return []provider.Observation{
			{Path: "retention.locked", Value: false, Derivation: "measured"},
		}, nil
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
		// D824: this said the redundancy is "fixed at creation". Microsoft publishes a page
		// titled "Change how a storage account is replicated": the geo-redundant and
		// read-access settings are changed from the portal, PowerShell or the CLI, and
		// LRS→ZRS has a documented conversion (Start-AzStorageAccountMigration). Replacing
		// a storage account to change this destroys every blob in it.
		// D1203: redundancy is changed in place, no account replacement. A geo-only change
		// that keeps the zone-redundancy (ZRS<->GZRS) is a synchronous SKU PATCH; a change
		// that flips the zone-redundancy (LRS<->ZRS/GZRS) is a customer-initiated MIGRATION
		// (POST startAccountMigration, async up to 72h), reported unknown-in-progress until
		// it completes. So `mutable`; the update sorts the two and never replaces the data.
		return "mutable", "redundancy is changed in place: a geo-only change (ZRS<->GZRS) is a " +
			"synchronous SKU PATCH; a zone-redundancy change (LRS<->ZRS/GZRS) is an async " +
			"customer-initiated migration reported in-progress until it converts"
	case "retention.locked":
		return "immutable", "locking an immutability policy is irreversible — a WORM floor " +
			"cannot be unlocked, so removing the lock is a replacement"
	case "retention.minimum":
		// D1201/D1202: the immutability floor is patched in place. An UNLOCKED policy is a
		// plain PUT with the policy's ETag as If-Match (shorten or lengthen). A LOCKED WORM
		// floor is a one-way ratchet: it can only be EXTENDED, via a dedicated POST :extend
		// with If-Match, and a request to shorten it is REFUSED at apply (acting would breach
		// the compliance guarantee the lock exists to make). So `mutable`, with the locked
		// shorten fenced off in the update — the AKS apiExposure shape.
		return "mutable", "the retention floor is patched in place: an unlocked policy PUT, a " +
			"locked policy EXTENDED (increase-only) via :extend; a locked shorten is refused"
	case "replication.enabled", "replication.destinationRegion":
		// D824: the reason already said this was about the DRIVER, not about Azure — and
		// `immutable` still made the plan destroy a stateful account. Object replication is
		// a POLICY applied to accounts that already exist (portal, PowerShell, CLI, REST),
		// not a create-time property.
		return "unsupported", "object replication is not wired for in-place update on the " +
			"blob driver — Azure configures it as a policy on existing accounts, so this is " +
			"a gap in groundhold rather than a reason to replace the account and its data"
	case "network.publicExposure":
		// D1200: anonymous access (D1198) is remediated ONLINE — a PATCH of the account's
		// allowBlobPublicAccess (the account-wide gate) and a PUT of the container's
		// publicAccess, both in place. So a discovered public blob converges to private
		// without replacing the account or destroying its data. D1199 recorded this as a
		// gap; updateBlob now closes it.
		return "mutable", "network.publicExposure is patched in place: allowBlobPublicAccess on " +
			"the account and the container's publicAccess"
	default:
		return "unsupported", "no azure blob in-place mapping for " + path
	}
}

// updateBlob remediates network.publicExposure in place (D1200): a PATCH of the
// account's allowBlobPublicAccess (the account-wide anonymous-access gate) and a PUT of
// the container's publicAccess. Ownership re-checked first (never patch a foreign
// account); four-valued (an ambiguous PATCH/PUT keeps the pid). Going to PRIVATE sets the
// account gate false FIRST — the account-wide lock lands before the container edit, so
// there is no window where the container is public with the gate already opened.
func (d *Driver) updateBlob(capability, environment, providerID string,
	attrs map[string]any, changes []string) provider.CreateResult {
	sub, rg, account, container, err := splitBlobProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	acctURL, _ := d.armURL(rg, d.acctPath(account), storageAPIVersion)
	st, resp, e := d.doARM("GET", acctURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{Status: "failed", Reason: "storage account no longer exists — cannot update"}
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-update read HTTP %d — reconcile", st)}
	}
	var doc blobAccountDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "storage account tags do not match — refusing to patch a resource that is not ours"}
	}

	for _, path := range changes {
		switch path {
		case "network.publicExposure":
			public, ok := attrs["network.publicExposure"].(bool)
			if !ok {
				return provider.CreateResult{Status: "failed", Reason: "network.publicExposure must be a bool"}
			}
			// (1) the account gate — allowBlobPublicAccess. false blocks all anonymous
			// access account-wide (the definitive lock); a PATCH leaves other properties alone.
			acctBody, _ := json.Marshal(map[string]any{"properties": map[string]any{"allowBlobPublicAccess": public}})
			if r := d.patchSetting(acctURL, acctBody, providerID, "account allowBlobPublicAccess"); r != nil {
				return *r
			}
			// (2) the container grant — publicAccess, set to agree with the gate.
			pubAccess := "None"
			if public {
				pubAccess = "Blob"
			}
			cURL, _ := d.armURL(rg, d.acctPath(account)+"/blobServices/default/containers/"+container, storageAPIVersion)
			cBody, _ := json.Marshal(map[string]any{"properties": map[string]any{"publicAccess": pubAccess}})
			if r := d.putSetting(cURL, cBody, providerID, "container publicAccess"); r != nil {
				return *r
			}
		case "retention.minimum":
			// D1201: patch an UNLOCKED immutability floor; REFUSE a locked one (WORM).
			days, derr := durationDays(attrs["retention.minimum"])
			if derr != nil {
				return provider.CreateResult{Status: "failed", Reason: "retention.minimum: " + derr.Error()}
			}
			if days <= 0 {
				return provider.CreateResult{Status: "failed",
					Reason: "in-place removal of a retention floor (retention.minimum -> 0/absent) is not wired " +
						"in this subset — refusing rather than silently dropping a compliance floor"}
			}
			ipURL, _ := d.armURL(rg,
				d.acctPath(account)+"/blobServices/default/containers/"+container+"/immutabilityPolicies/default", storageAPIVersion)
			gst, gresp, ge := d.doARM("GET", ipURL, nil)
			if ge != nil {
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: "pre-update immutability read gave no answer — reconcile: " + azReadWhy(gst, gresp, ge)}
			}
			etag := ""
			handled := false
			switch {
			case gst == http.StatusOK:
				var cur struct {
					Properties struct {
						Days  *int   `json:"immutabilityPeriodSinceCreationInDays"`
						State string `json:"state"`
					} `json:"properties"`
				}
				if json.Unmarshal(gresp, &cur) != nil {
					return provider.CreateResult{ProviderID: providerID, Status: "unknown",
						Reason: "immutability policy read answered 200 with an unparseable body — reconcile"}
				}
				if cur.Properties.State == "Locked" {
					// D1202: a LOCKED WORM floor can only be EXTENDED (increased), via a
					// dedicated POST :extend with If-Match — never a plain PUT, never a
					// shorten. A request to shorten (or leave equal) is refused: WORM is a
					// one-way ratchet, so acting would either fail at the API or breach the
					// compliance guarantee the lock exists to make.
					curDays := int64(0)
					if cur.Properties.Days != nil {
						curDays = int64(*cur.Properties.Days)
					}
					if days <= curDays {
						return provider.CreateResult{Status: "failed",
							Reason: fmt.Sprintf("retention.minimum on a LOCKED immutability policy (WORM) can only be "+
								"EXTENDED, never shortened — requested %dd is not greater than the locked floor of %dd; refusing", days, curDays)}
					}
					extURL, _ := d.armURL(rg, d.acctPath(account)+
						"/blobServices/default/containers/"+container+"/immutabilityPolicies/default/extend", storageAPIVersion)
					extBody, _ := json.Marshal(map[string]any{
						"properties": map[string]any{"immutabilityPeriodSinceCreationInDays": days}})
					est, eresp, ee := d.doARMIfMatch("POST", extURL, extBody, jsonEtag(gresp))
					if r := terminalOr(est, eresp, ee, providerID, "immutability-extend"); r != nil {
						return *r
					}
					handled = true
				} else {
					etag = jsonEtag(gresp) // an unlocked policy edit is a CAS — ARM requires If-Match
				}
			case gst == http.StatusNotFound:
				// no policy yet — create it (no If-Match)
			default:
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: fmt.Sprintf("pre-update immutability read HTTP %d — reconcile", gst)}
			}
			if !handled { // Unlocked edit or fresh create — a plain PUT
				body, _ := json.Marshal(map[string]any{
					"properties": map[string]any{"immutabilityPeriodSinceCreationInDays": days}})
				var pst int
				var presp []byte
				var pe error
				if etag != "" {
					pst, presp, pe = d.doARMIfMatch("PUT", ipURL, body, etag)
				} else {
					pst, presp, pe = d.doARM("PUT", ipURL, body)
				}
				if r := terminalOr(pst, presp, pe, providerID, "immutability-policy"); r != nil {
					return *r
				}
			}
		case "durability.class":
			// D1203: change redundancy in place — never a replacement of a data-bearing
			// account. A geo-only change that keeps zone-redundancy (ZRS<->GZRS) is a
			// synchronous SKU PATCH; a change that flips zone-redundancy (LRS<->ZRS/GZRS)
			// is an async customer-initiated migration (up to 72h), reported in-progress.
			cls, _ := attrs["durability.class"].(string)
			target := ""
			switch cls {
			case "single-zone":
				target = "Standard_LRS"
			case "regional":
				target = "Standard_ZRS"
			case "multi-regional":
				target = "Standard_GZRS"
			default:
				return provider.CreateResult{Status: "failed",
					Reason: fmt.Sprintf("durability.class %q has no Azure SKU mapping", cls)}
			}
			current := doc.Sku.Name // from the ownership pre-read above
			if current == target {
				break // already at the target SKU — nothing to do for this change
			}
			if blobSkuZonal(current) == blobSkuZonal(target) {
				// geo-only change (ZRS<->GZRS): a synchronous SKU PATCH, no migration.
				skuBody, _ := json.Marshal(map[string]any{"sku": map[string]any{"name": target}})
				if r := d.patchSetting(acctURL, skuBody, providerID, "storage account SKU"); r != nil {
					return *r
				}
				break
			}
			// zone-redundancy change: a customer-initiated migration. Idempotency first —
			// a converge must not start a SECOND migration while one is already running.
			migURL, _ := d.armURL(rg, d.acctPath(account)+"/accountMigrations/default", storageAPIVersion)
			mst, mresp, me := d.doARM("GET", migURL, nil)
			if me != nil {
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: "pre-migration read gave no answer — reconcile: " + azReadWhy(mst, mresp, me)}
			}
			if mst == http.StatusOK {
				var cur struct {
					Properties struct {
						MigrationStatus string `json:"migrationStatus"`
						TargetSkuName   string `json:"targetSkuName"`
					} `json:"properties"`
				}
				_ = json.Unmarshal(mresp, &cur)
				if cur.Properties.MigrationStatus == "SubmittedForConversion" || cur.Properties.MigrationStatus == "InProgress" {
					if cur.Properties.TargetSkuName == target {
						return provider.CreateResult{ProviderID: providerID, Status: "unknown",
							Reason: fmt.Sprintf("a redundancy migration to %s is already in progress (async, up to 72h) — reconcile confirms when it converts", target)}
					}
					return provider.CreateResult{Status: "failed",
						Reason: fmt.Sprintf("a redundancy migration to %s is already in progress; refusing to start a second migration to %s", cur.Properties.TargetSkuName, target)}
				}
			}
			// no active migration — initiate it.
			startURL, _ := d.armURL(rg, d.acctPath(account)+"/startAccountMigration", storageAPIVersion)
			startBody, _ := json.Marshal(map[string]any{"properties": map[string]any{"targetSkuName": target}})
			sst, sresp, se := d.doARM("POST", startURL, startBody)
			switch {
			case se != nil:
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: fmt.Sprintf("startAccountMigration to %s outcome unknown (may have started): %v", target, se)}
			case sst == http.StatusOK:
				// synchronous completion (a small account) — the SKU is converted.
			case sst == http.StatusAccepted:
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: fmt.Sprintf("redundancy migration to %s initiated (async, up to 72h) — reconcile confirms when the SKU converts", target)}
			default:
				if r := terminalOr(sst, sresp, se, providerID, "startAccountMigration"); r != nil {
					return *r
				}
			}
		default:
			// classifyBlobChange gates this (unsupported/immutable), so a reviewed plan
			// never reaches here — refuse honestly rather than silently no-op.
			return provider.CreateResult{Status: "failed", Reason: "no in-place azure blob mapping for " + path}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
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

// observeBlobLifecycle MEASURES retention.maximum from the account's management policy —
// the same object createBlob writes (managementPolicyBody). It reads back OUR rule by
// name and by the container prefix it filters on, because an account-level policy can
// carry rules nobody here wrote: attributing a stranger's expiry to this capability
// would be a measurement of the wrong thing, which is worse than no measurement.
//
// Absent (404) means no lifecycle policy — the path is simply absent, not an error, the
// same shape observeBlobImmutability uses for an unprotected container.
func (d *Driver) observeBlobLifecycle(rg, account, container string) ([]provider.Observation, []string) {
	mpURL, err := d.armURL(rg, d.acctPath(account)+"/managementPolicies/default", storageAPIVersion)
	if err != nil {
		return nil, []string{"retention.maximum not observed: " + err.Error()}
	}
	st, resp, e := d.doARM("GET", mpURL, nil)
	if e != nil {
		return nil, []string{"retention.maximum not observed: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return nil, nil // no lifecycle policy — absent, not an error
	}
	if st != http.StatusOK {
		return nil, []string{fmt.Sprintf("retention.maximum not observed: managementPolicies.get HTTP %d", st)}
	}
	var doc struct {
		Properties struct {
			Policy struct {
				Rules []struct {
					Name       string `json:"name"`
					Enabled    bool   `json:"enabled"`
					Definition struct {
						Filters struct {
							PrefixMatch []string `json:"prefixMatch"`
						} `json:"filters"`
						Actions struct {
							BaseBlob struct {
								Delete struct {
									Days *float64 `json:"daysAfterModificationGreaterThan"`
								} `json:"delete"`
							} `json:"baseBlob"`
						} `json:"actions"`
					} `json:"definition"`
				} `json:"rules"`
			} `json:"policy"`
		} `json:"properties"`
	}
	if json.Unmarshal(resp, &doc) != nil {
		return nil, []string{"retention.maximum not observed: managementPolicies.get unparseable"}
	}
	for _, r := range doc.Properties.Policy.Rules {
		if r.Name != "groundhold-retention-maximum" || !r.Enabled {
			continue
		}
		mine := false
		for _, p := range r.Definition.Filters.PrefixMatch {
			if p == container+"/" {
				mine = true
			}
		}
		if !mine {
			continue
		}
		if days := r.Definition.Actions.BaseBlob.Delete.Days; days != nil && *days > 0 {
			return []provider.Observation{{Path: "retention.maximum",
				Value: fmt.Sprintf("%dd", int64(*days)), Derivation: "measured"}}, nil
		}
	}
	return nil, nil // a policy exists but carries no expiry of ours
}
