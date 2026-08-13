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

func (d *Driver) createElastiCache(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildElastiCacheCreate(account, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := ecacheProviderID(region, account, plan.ID)
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
		// ours — poll to available
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
		{Path: "encryption.inTransit", Value: rg.TransitEncryptionEnabled, Derivation: "measured"},
	}
	var diags []string
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
