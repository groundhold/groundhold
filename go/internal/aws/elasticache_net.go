// ElastiCache network shell (D100): the SigV4-signed, Query-protocol half of the
// AWS capability.cache.keyvalue driver. CreateReplicationGroup is async — the
// deterministic id makes the providerId knowable before the response (D29), so a
// lost/garbled outcome carries the handle. Ownership is TAGS (read via
// ListTagsForResource on the group ARN). A replication group is VPC-only, so
// observe reports publicExposure=false as measured. Engine version lives on the
// member clusters, not the group, so observe names it a diagnostic rather than
// guessing.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/adoptcheck"
	"groundhold/internal/provider"
)

func (d *Driver) ecacheBase(region string) string {
	if d.ElastiCacheBaseURL != "" {
		return d.ElastiCacheBaseURL
	}
	return "https://elasticache." + region + ".amazonaws.com"
}

func ecacheProviderID(region, account, id string) string {
	return "ecredis:" + region + ":" + account + ":" + id
}

func splitECacheProviderID(providerID string) (region, account, id string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "ecredis" {
		return "", "", "", fmt.Errorf("providerId %q is not ecredis:region:account:id", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !account12.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId account %q is invalid", parts[2])
	}
	if !ecacheIDOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId id %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func ecacheARN(region, account, id string) string {
	return "arn:aws:elasticache:" + region + ":" + account + ":replicationgroup:" + id
}

func (d *Driver) ecachePost(region, body string) (int, []byte, error) {
	return d.doSigned("POST", d.ecacheBase(region)+"/", "elasticache", region,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(body))
}

type replicationGroup struct {
	Status                   string `xml:"Status"`
	AtRestEncryptionEnabled  bool   `xml:"AtRestEncryptionEnabled"`
	TransitEncryptionEnabled bool   `xml:"TransitEncryptionEnabled"`
	TransitEncryptionMode    string `xml:"TransitEncryptionMode"` // preferred (plaintext still allowed) | required (enforced)
	AutomaticFailover        string `xml:"AutomaticFailover"`
	MultiAZ                  string `xml:"MultiAZ"`
	KmsKeyID                 string `xml:"KmsKeyId"`
}

// describeRG reads a replication group. found=false + readable=true is an
// authoritative "does not exist"; readable=false is a transport/HTTP/parse failure.
func (d *Driver) describeRG(region, id string) (replicationGroup, bool, error) {
	const op = "DescribeReplicationGroups"
	body := encodeForm(map[string]string{
		"Action": "DescribeReplicationGroups", "Version": elastiCacheVersion,
		"ReplicationGroupId": id})
	st, resp, err := d.ecachePost(region, body)
	if err != nil {
		return replicationGroup{}, false, readTransport(op, err)
	}
	if strings.Contains(rdsErrCode(resp), "ReplicationGroupNotFoundFault") {
		return replicationGroup{}, false, nil
	}
	if st != http.StatusOK {
		return replicationGroup{}, false, readHTTP(op, st, rdsErrCode(resp))
	}
	var r struct {
		Groups []replicationGroup `xml:"DescribeReplicationGroupsResult>ReplicationGroups>ReplicationGroup"`
	}
	// D523: this said `unmarshal != nil || len(Groups) == 0` and called BOTH a
	// read failure. An EMPTY result set is how this API says the group does not
	// exist — a fact about the world, not a failure to read it — and reporting it
	// as unparseable blocked the binding on unknown instead of re-creating.
	if xml.Unmarshal(resp, &r) != nil {
		return replicationGroup{}, false, readBody(op, st)
	}
	if len(r.Groups) == 0 {
		return replicationGroup{}, false, nil // authoritative: does not exist
	}
	return r.Groups[0], true, nil
}

// ecacheTags reads the group's ownership tags via the ARN. readable=false is a
// transport/parse failure (never "no tags").
func (d *Driver) ecacheTags(region, account, id string) (map[string]string, error) {
	const op = "ListTagsForResource"
	body := encodeForm(map[string]string{
		"Action": "ListTagsForResource", "Version": elastiCacheVersion,
		"ResourceName": ecacheARN(region, account, id)})
	st, resp, err := d.ecachePost(region, body)
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, rdsErrCode(resp))
	}
	var r struct {
		Tags []struct {
			Key   string `xml:"Key"`
			Value string `xml:"Value"`
		} `xml:"ListTagsForResourceResult>TagList>Tag"`
	}
	if xml.Unmarshal(resp, &r) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range r.Tags {
		m[t.Key] = t.Value
	}
	return m, nil
}

// ecacheAdoptControls are the controls ElastiCache sets INLINE in the create body,
// so on a 409-adopt they never applied to the pre-existing replication group (D1062).
// At-rest encryption and the customer key ARE fixed at create (a drift is a replacement),
// so a missing one FAILS the adopt. In-transit was thought create-fixed too — but D1220
// wired the two-step ModifyReplicationGroup TLS migration, so it is UpdateWired: an adopted
// group missing enforced TLS is bound-and-reconciled, not refused. availability.class
// (MultiAZ/AutomaticFailover) is a resilience control read carefully (D955) — not wired here.
var ecacheAdoptControls = []adoptcheck.Control{
	{Path: "encryption.atRest", Direction: adoptcheck.SecureTrue, ImmutableAtCreate: true},
	{Path: "encryption.inTransit", Direction: adoptcheck.SecureTrue, UpdateWired: true},
	{Path: "encryption.customerManagedKeys", Direction: adoptcheck.SecureTrue, ImmutableAtCreate: true},
}

func (d *Driver) createElastiCache(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildElastiCacheCreate(account, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := ecacheProviderID(region, account, plan.ID)
	adopted := false
	// D278: a derived cache subnet group stands BEFORE the replication group
	// that places into it — nothing else has landed yet, so an ensure failure
	// is a clean per-action refusal, and a leftover group self-heals via the
	// already-exists content check on the next attempt.
	if plan.DeriveSubnetGroup != "" {
		if r := d.ensureCacheSubnetGroup(region, plan.DeriveSubnetGroup, plan.SubnetIDs,
			capability, environment); r != nil {
			return *r
		}
	}
	st, resp, err := d.ecachePost(region, encodeForm(plan.createParams(capability, environment)))
	if err != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown: %v", err)}
	}
	switch {
	case st == http.StatusOK:
		// creating — poll below
	case strings.Contains(rdsErrCode(resp), "ReplicationGroupAlreadyExists"):
		tags, terr := d.ecacheTags(region, account, plan.ID)
		if terr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing group tags gave no answer — reconcile: " + terr.Error()}
		}
		if !groundholdTagsMatch(tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a replication group with this id exists and is not ours (tags do not match)"}
		}
		// ours — poll to available, then re-check declared controls (D1062)
		adopted = true
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create: HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	default:
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create: HTTP %d (%s): %s", st, rdsErrCode(resp), mutDetail(resp))}
	}

	deadline := d.Now().Add(d.PollTimeout)
	for {
		rg, found, rerr := d.describeRG(region, plan.ID)
		if rerr == nil && found {
			switch rg.Status {
			case "available":
				// D1062: an ADOPTED group (409, ours) never received the create body's
				// inline controls — at-rest/in-transit encryption and its KMS key, all
				// fixed at create. Re-check them against this driver's OWN measured
				// observations (cmek KMS-traced) before reporting succeeded; a missing
				// immutable control fails rather than lying that encryption is in place.
				if adopted {
					obs, _, oerr := d.observeElastiCache(capability, pid)
					if oerr != nil {
						return provider.CreateResult{ProviderID: pid, Status: "unknown",
							Reason: "adopted group re-observe gave no answer — reconcile: " + oerr.Error()}
					}
					switch v := adoptcheck.Compare(attrs, obs, ecacheAdoptControls); v.Status {
					case "failed":
						return provider.CreateResult{Status: "failed", Reason: v.Reason}
					case "unknown":
						return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: v.Reason}
					}
				}
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			case "create-failed":
				return provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "replication group entered status create-failed"}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "replication group still creating at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

func (d *Driver) observeElastiCache(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, id, err := splitECacheProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	rg, found, rerr := d.describeRG(region, id)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"replication group not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// a replication group is VPC-only — no public endpoint is assignable.
		{Path: "network.publicExposure", Value: false, Derivation: "measured"},
		{Path: "encryption.atRest", Value: rg.AtRestEncryptionEnabled, Derivation: "measured"},
	}
	var diags []string
	// D1219: encryption.inTransit is NOT just TransitEncryptionEnabled. AWS added a two-mode
	// migration: `preferred` means TransitEncryptionEnabled=true BUT the brokers still accept
	// PLAINTEXT connections ("allow both encrypted and unencrypted"), and only `required`
	// enforces TLS. Reading the bare boolean reported inTransit=true for a preferred-mode group
	// that still speaks plaintext — a false green. Enforced only when required (an empty mode on
	// an enabled group is a pre-migration cluster, enforced by construction); preferred is NOT.
	enforced := rg.TransitEncryptionEnabled && rg.TransitEncryptionMode != "preferred"
	obs = append(obs, provider.Observation{Path: "encryption.inTransit", Value: enforced, Derivation: "measured"})
	if rg.TransitEncryptionEnabled && rg.TransitEncryptionMode == "preferred" {
		diags = append(diags, "encryption.inTransit is false despite TransitEncryptionEnabled=true: the "+
			"group is in TransitEncryptionMode=preferred, which still accepts plaintext connections — TLS is "+
			"not enforced until the mode is `required`")
	}
	// D800: an encrypted replication group always reports a KMS key — the account-default
	// aws/elasticache one when the customer brought none — so "a key id is present" is not
	// "the customer brought a key". Trace it to KMS (DescribeKey -> KeyManager), the way
	// the RDS driver in this same package already does; an unreadable trace is a
	// diagnostic, never a false BYOK.
	if rg.KmsKeyID != "" {
		if customer, kerr := d.kmsKeyIsCustomerManaged(region, rg.KmsKeyID); kerr == nil {
			obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
				Value: customer, Derivation: "measured"})
		} else {
			diags = append(diags, "encryption.customerManagedKeys not observed on the replication group's "+
				"KMS key: "+kerr.Error()+" — probe/reconcile")
		}
	} else {
		// D1040/D1003: no key = at-rest encryption disabled = definitively not a
		// customer key, from the main describe → a MEASURED false, not an absence.
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
			Value: false, Derivation: "measured"})
	}
	// availability.class: zone survival is MultiAZ (replicas in DIFFERENT AZs), NOT
	// AutomaticFailover. A group with AutomaticFailover=enabled but MultiAZ=disabled keeps
	// its replica in the primary's OWN AZ — node failover, not zone survival — and AWS
	// accepts exactly that combination (field 2026-08-08: CreateReplicationGroup
	// AutomaticFailoverEnabled=true + MultiAZEnabled=false → 200, MultiAZ=disabled). Reading
	// AutomaticFailover reported that single-zone group as regional/measured, so a hard
	// availability.class==regional DR constraint read satisfied against a cache that loses
	// data on a zone outage — the D946 shape. Read MultiAZ, the field that carries the
	// guarantee (D955); MultiAZ=enabled implies AutomaticFailover=enabled (an AWS invariant),
	// so it is the authoritative single signal. The create sets BOTH for regional, matching.
	switch rg.MultiAZ {
	case "enabled":
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "regional", Derivation: "measured"})
	case "disabled":
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "zonal", Derivation: "measured"})
	}
	diags = append(diags, "engine.protocol not observed from the replication group "+
		"(the engine version lives on the member cache clusters — DescribeCacheClusters)")
	return obs, diags, nil
}

func (d *Driver) deleteElastiCache(capability, environment, providerID string) provider.CreateResult {
	region, account, id, err := splitECacheProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameAccount(account); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	_, found, rerr := d.describeRG(region, id)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	tags, terr := d.ecacheTags(region, account, id)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "replication group tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, e := d.ecachePost(region, encodeForm(map[string]string{
		"Action": "DeleteReplicationGroup", "Version": elastiCacheVersion,
		"ReplicationGroupId": id}))
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if strings.Contains(rdsErrCode(resp), "ReplicationGroupNotFoundFault") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete: HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete: HTTP %d (%s)", st, rdsErrCode(resp))}
	}
	// ---- poll the replication group to absence (D968 class, D970) ----
	// The delete is async: the group enters "deleting", not gone. Reporting
	// succeeded here tombstones a group still live and billing, and the subnet-group
	// cleanup below cannot succeed while the group still uses it. Poll to a confirmed
	// ReplicationGroupNotFound as createElastiCache polls to available; unknown on
	// timeout keeps the handle (the subnet group is left for the reconcile).
	deadline := d.Now().Add(d.PollTimeout)
	for {
		if _, found, rerr := d.describeRG(region, id); rerr == nil && !found {
			break // confirmed gone — proceed to subnet-group cleanup
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "replication group still deleting at poll timeout — reconcile via DescribeReplicationGroups"}
		}
		time.Sleep(d.PollInterval)
	}
	// D278: cleanup of the driver-DERIVED cache subnet group — part of this
	// capability's composite footprint, reported honestly: not-found means no
	// derived group was used, in-use means a successor still places into it
	// (left standing by design); an unresolved outcome is unknown, never
	// swallowed. Only the deterministic derived name is ever touched.
	sgName := derivedSubnetGroupName(environment, capability)
	sst, sbody, serr := d.ecachePost(region, encodeForm(map[string]string{
		"Action": "DeleteCacheSubnetGroup", "Version": elastiCacheVersion,
		"CacheSubnetGroupName": sgName}))
	switch {
	case serr != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("group deleted; derived cache subnet group %s cleanup outcome unknown — reconcile: %v", sgName, serr)}
	case sst == http.StatusOK,
		sst == http.StatusNotFound, // gone — the same reading describeCluster uses
		strings.Contains(rdsErrCode(sbody), "CacheSubnetGroupNotFoundFault"),
		strings.Contains(rdsErrCode(sbody), "CacheSubnetGroupInUse"):
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	default:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("group deleted; derived cache subnet group %s cleanup HTTP %d (%s) — reconcile", sgName, sst, rdsErrCode(sbody))}
	}
}

// ensureCacheSubnetGroup creates (or verifies) the driver-owned cache subnet
// group a derived placement uses (D278). Already-exists resolves by CONTENT —
// reuse only on an equal subnet set; foreign or drifted refuses. Tagged at
// birth so ownership is visible to tooling.
func (d *Driver) ensureCacheSubnetGroup(region, name string, subnetIDs []string,
	capability, environment string) *provider.CreateResult {
	params := map[string]string{
		"Action":                      "CreateCacheSubnetGroup",
		"Version":                     elastiCacheVersion,
		"CacheSubnetGroupName":        name,
		"CacheSubnetGroupDescription": "groundhold-derived placement group (D278)",
		"Tags.member.1.Key":           "groundhold-capability",
		"Tags.member.1.Value":         sanitizeTag(capability),
		"Tags.member.2.Key":           "groundhold-environment",
		"Tags.member.2.Value":         sanitizeTag(environment),
	}
	for i, id := range subnetIDs {
		params[fmt.Sprintf("SubnetIds.member.%d", i+1)] = id
	}
	st, body, err := d.ecachePost(region, encodeForm(params))
	if err != nil {
		r := provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateCacheSubnetGroup %s outcome unknown — retry (the replication group was not attempted): %v", name, err)}
		return &r
	}
	switch {
	case st == http.StatusOK:
		return nil
	case strings.Contains(rdsErrCode(body), "CacheSubnetGroupAlreadyExists"):
		got, found, gerr := d.describeCacheSubnetGroupSubnets(region, name)
		if gerr != nil || !found {
			r := provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("cache subnet group %s exists but gave no answer — retry: %v", name, gerr)}
			return &r
		}
		if !sameStringSet(got, subnetIDs) {
			r := provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("cache subnet group %s exists with DIFFERENT subnets (%v vs requested %v) — foreign or drifted, refusing to reuse it", name, got, subnetIDs)}
			return &r
		}
		return nil // ours by content — reuse
	default:
		r := provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateCacheSubnetGroup %s: HTTP %d (%s) — the replication group was not attempted", name, st, rdsErrCode(body))}
		return &r
	}
}

// describeCacheSubnetGroupSubnets returns the subnet ids of a cache subnet group.
func (d *Driver) describeCacheSubnetGroupSubnets(region, name string) (ids []string, found bool, err error) {
	const op = "DescribeCacheSubnetGroups"
	st, body, cerr := d.ecachePost(region, encodeForm(map[string]string{
		"Action": "DescribeCacheSubnetGroups", "Version": elastiCacheVersion,
		"CacheSubnetGroupName": name}))
	if cerr != nil {
		return nil, false, readTransport(op, cerr)
	}
	if strings.Contains(rdsErrCode(body), "CacheSubnetGroupNotFoundFault") {
		return nil, false, nil
	}
	if st != http.StatusOK {
		return nil, false, readHTTP(op, st, rdsErrCode(body))
	}
	var out struct {
		IDs []string `xml:"DescribeCacheSubnetGroupsResult>CacheSubnetGroups>CacheSubnetGroup>Subnets>Subnet>SubnetIdentifier"`
	}
	if xml.Unmarshal(body, &out) != nil {
		return nil, false, readBody(op, st)
	}
	return out.IDs, true, nil
}

// classifyElastiCacheChange decides whether a drift on a replication group is reconciled in place
// or replaced. Before D1220 elasticache had NO ClassifyChange, so every drift fell to the AWS
// default of "immutable" = replacement — and replacing a cache destroys its data and rotates its
// endpoint. That verdict was being applied to encryption.inTransit, which AWS enforces online via
// a two-step ModifyReplicationGroup migration. D1220: enabling is `mutable`; disabling is refused
// at apply (a weakening whose multi-step reverse is delicate — refusing beats a risky partial change).
func classifyElastiCacheChange(path string) (string, string) {
	switch path {
	case "encryption.inTransit":
		return "mutable", "encryption.inTransit is enforced in place via the two-step ModifyReplication" +
			"Group migration (TransitEncryptionMode preferred then required); no replacement"
	default:
		return "immutable", fmt.Sprintf(
			"ElastiCache has no in-place update path for %q — reconciling a drift is a replacement", path)
	}
}

// ecacheModifyAndPoll issues one ModifyReplicationGroup and POLLS to the applied state before
// returning nil (keep going). ApplyImmediately so the change starts now; the poll waits for the
// group back to `available` at the target (D953) — a group is UPDATING between phases and the API
// rejects a second modify until it settles, so each phase must land before the next.
func (d *Driver) ecacheModifyAndPoll(region, id, pid string, params map[string]string,
	applied func(replicationGroup) bool) *provider.CreateResult {
	form := map[string]string{"Action": "ModifyReplicationGroup", "Version": elastiCacheVersion,
		"ReplicationGroupId": id, "ApplyImmediately": "true"}
	for k, v := range params {
		form[k] = v
	}
	st, resp, err := d.ecachePost(region, encodeForm(form))
	switch {
	case err != nil:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("ModifyReplicationGroup outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// accepted — poll below
	case st >= 500:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("ModifyReplicationGroup HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, pid, "ModifyReplicationGroup"); r != nil {
			return r
		}
		return &provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("ModifyReplicationGroup HTTP %d: %s", st, rdsErrCode(resp))}
	}
	deadline := d.Now().Add(d.PollTimeout)
	for {
		rg, found, rerr := d.describeRG(region, id)
		if rerr == nil && found && applied(rg) {
			return nil
		}
		if d.Now().After(deadline) {
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "replication group still applying the TLS migration at poll timeout — reconcile via DescribeReplicationGroups"}
		}
		time.Sleep(d.PollInterval)
	}
}

// updateElastiCache enforces encryption.inTransit in place (D1220): the two-step, no-downtime TLS
// migration. Enabling on a group that has it off is `preferred` (both encrypted and plaintext
// accepted) and then `required` (TLS enforced); a group already `preferred` only needs the second
// step. Ownership is re-checked by tags; each phase polls to applied so succeeded is reported only
// once the group is `required` — plaintext refused — never while it still accepts plaintext.
func (d *Driver) updateElastiCache(capability, environment, providerID string,
	attrs map[string]any, changes []string) provider.CreateResult {
	region, account, id, err := splitECacheProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameAccount(account); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, found, rerr := d.describeRG(region, id)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "replication group no longer exists — cannot update"}
	}
	tags, terr := d.ecacheTags(region, account, id)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "replication group tags do not match — refusing to update a resource that is not ours"}
	}

	for _, path := range changes {
		switch path {
		case "encryption.inTransit":
			desired, ok := attrs["encryption.inTransit"].(bool)
			if !ok {
				return provider.CreateResult{Status: "failed", Reason: "encryption.inTransit must be a bool"}
			}
			enforced := rg.TransitEncryptionEnabled && rg.TransitEncryptionMode != "preferred"
			if desired == enforced {
				continue // already at the requested enforcement
			}
			if !desired {
				return provider.CreateResult{Status: "failed",
					Reason: "encryption.inTransit=false cannot be honored in place: disabling in-transit " +
						"encryption on ElastiCache is a weakening whose multi-step downgrade is delicate — " +
						"refusing rather than a risky partial change"}
			}
			// Enable + enforce. Step 1 (only if not yet enabled): enable with mode=preferred, so
			// clients migrate with no downtime. Step 2: mode=required — plaintext refused.
			if !rg.TransitEncryptionEnabled {
				if r := d.ecacheModifyAndPoll(region, id, providerID,
					map[string]string{"TransitEncryptionEnabled": "true", "TransitEncryptionMode": "preferred"},
					func(g replicationGroup) bool {
						return g.Status == "available" && g.TransitEncryptionEnabled && g.TransitEncryptionMode == "preferred"
					}); r != nil {
					return *r
				}
			}
			if r := d.ecacheModifyAndPoll(region, id, providerID,
				map[string]string{"TransitEncryptionMode": "required"},
				func(g replicationGroup) bool {
					return g.Status == "available" && g.TransitEncryptionMode == "required"
				}); r != nil {
				return *r
			}
		default:
			return provider.CreateResult{Status: "failed",
				Reason: "no elasticache in-place mapping for " + path}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
