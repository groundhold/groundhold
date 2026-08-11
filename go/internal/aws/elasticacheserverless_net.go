// ElastiCache Serverless network shell: the SigV4-signed, Query-protocol half of
// the second AWS capability.cache.keyvalue backend. CreateServerlessCache is
// async — the deterministic name makes the providerId knowable before the
// response (D29), so a lost/garbled outcome carries the handle. Ownership is
// TAGS (ListTagsForResource on the cache ARN, read off the describe). A
// serverless cache is VPC-only, so observe reports publicExposure=false as
// measured; at-rest + in-transit encryption are always on (config-intent, like
// App Runner's HTTPS).
//
// CRITICAL LRO discipline (the F29/D273 lesson): the create/delete polls read the
// OBSERVABLE resource state via DescribeServerlessCaches and conclude on
// ServerlessCache.Status (AVAILABLE = done; CREATING/MODIFYING = keep polling;
// CREATE-FAILED = failed). They NEVER construct an operation-by-id path. The poll
// is bounded by PollTimeout; a still-in-progress cache at the deadline is
// unknown-with-pid, never a hang and never a fabricated success.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func (d *Driver) ecacheServerlessBase(region string) string {
	if d.ElastiCacheServerlessBaseURL != "" {
		return d.ElastiCacheServerlessBaseURL
	}
	// same regional endpoint as the provisioned driver — serverless is the same API family.
	return "https://elasticache." + region + ".amazonaws.com"
}

func ecacheServerlessProviderID(region, account, name string) string {
	return "ecserverless:" + region + ":" + account + ":" + name
}

func splitECacheServerlessProviderID(providerID string) (region, account, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "ecserverless" {
		return "", "", "", fmt.Errorf("providerId %q is not ecserverless:region:account:name", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !account12.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId account %q is invalid", parts[2])
	}
	if !ecacheIDOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId name %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) ecacheServerlessPost(region, body string) (int, []byte, error) {
	return d.doSigned("POST", d.ecacheServerlessBase(region)+"/", "elasticache", region,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(body))
}

type serverlessCache struct {
	Name               string `xml:"ServerlessCacheName"`
	Status             string `xml:"Status"`
	ARN                string `xml:"ARN"`
	Engine             string `xml:"Engine"`
	MajorEngineVersion string `xml:"MajorEngineVersion"`
	Endpoint           struct {
		Address string `xml:"Address"`
		Port    int    `xml:"Port"`
	} `xml:"Endpoint"`
}

// describeServerlessCache reads a serverless cache by name. found=false +
// readable (nil err) is an authoritative "does not exist"; a non-nil error is a
// transport/HTTP/parse failure that NAMES the cause (D296), never a fabricated absence.
func (d *Driver) describeServerlessCache(region, name string) (serverlessCache, bool, error) {
	const op = "DescribeServerlessCaches"
	body := encodeForm(map[string]string{
		"Action": "DescribeServerlessCaches", "Version": elastiCacheVersion,
		"ServerlessCacheName": name})
	st, resp, err := d.ecacheServerlessPost(region, body)
	if err != nil {
		return serverlessCache{}, false, readTransport(op, err)
	}
	if strings.Contains(rdsErrCode(resp), "ServerlessCacheNotFoundFault") {
		return serverlessCache{}, false, nil
	}
	if st != http.StatusOK {
		return serverlessCache{}, false, readHTTP(op, st, rdsErrCode(resp))
	}
	var r struct {
		// D936: AWS wraps each list member in <member>, not <ServerlessCache> — the
		// old tag matched nothing, so a live cache read as len==0 (an unreadable
		// error), and the driver could POST a create but never confirm, observe,
		// resume, or verify-delete one. The golden fixture emitted the fake
		// <ServerlessCache> shape, so the test agreed with the bug.
		Caches []serverlessCache `xml:"DescribeServerlessCachesResult>ServerlessCaches>member"`
	}
	if xml.Unmarshal(resp, &r) != nil || len(r.Caches) == 0 {
		return serverlessCache{}, false, readBody(op, st)
	}
	return r.Caches[0], true, nil
}

// serverlessCacheTags reads the cache's ownership tags via its ARN. A non-nil
// error is a transport/HTTP/parse failure naming the cause (never "no tags").
func (d *Driver) serverlessCacheTags(region, arn string) (map[string]string, error) {
	const op = "ListTagsForResource"
	body := encodeForm(map[string]string{
		"Action": "ListTagsForResource", "Version": elastiCacheVersion,
		"ResourceName": arn})
	st, resp, err := d.ecacheServerlessPost(region, body)
	if err != nil {
		return nil, readTransport(op, err)
	}
	if st != http.StatusOK {
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

func (d *Driver) createElastiCacheServerless(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildElastiCacheServerlessCreate(account, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := ecacheServerlessProviderID(region, account, plan.Name)

	st, resp, err := d.ecacheServerlessPost(region, encodeForm(plan.createParams(capability, environment)))
	if err != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown: %v", err)}
	}
	switch {
	case st == http.StatusOK:
		// creating — poll below
	case strings.Contains(rdsErrCode(resp), "ServerlessCacheAlreadyExistsFault"):
		// a serverless cache with this name exists — adopt only if ours (tags off the ARN).
		cur, found, derr := d.describeServerlessCache(region, plan.Name)
		if derr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing cache read gave no answer — reconcile: " + derr.Error()}
		}
		if !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict but the existing cache then read as absent — reconcile"}
		}
		tags, terr := d.serverlessCacheTags(region, cur.ARN)
		if terr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing cache tags gave no answer — reconcile: " + terr.Error()}
		}
		if !groundholdTagsMatch(tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a serverless cache with this name exists and is not ours (tags do not match)"}
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

	// LRO: poll the OBSERVABLE cache state to a terminal Status (D273 — never an
	// operation-by-id path). AVAILABLE = succeeded; CREATE-FAILED = failed WITH the
	// pid; the poll timeout is unknown WITH the pid. Bounded by PollTimeout, never a hang.
	deadline := d.Now().Add(d.PollTimeout)
	for {
		c, found, rerr := d.describeServerlessCache(region, plan.Name)
		if rerr == nil && found {
			switch strings.ToUpper(c.Status) {
			case "AVAILABLE":
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			case "CREATE-FAILED":
				return provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "serverless cache entered status CREATE-FAILED"}
				// CREATING / MODIFYING -> keep polling
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "serverless cache still creating at poll timeout — reconcile via DescribeServerlessCaches"}
		}
		d.progress("ElastiCache Serverless cache provisioning — waiting for AVAILABLE")
		time.Sleep(d.PollInterval)
	}
}

func (d *Driver) observeElastiCacheServerless(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, name, err := splitECacheServerlessProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	c, found, rerr := d.describeServerlessCache(region, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"serverless cache not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// a serverless cache is VPC-only — no public endpoint is assignable.
		{Path: "network.publicExposure", Value: false, Derivation: "measured"},
		// serverless ALWAYS encrypts at rest and in transit — structural guarantees
		// (config-intent, like App Runner's HTTPS-only endpoint), not read fields.
		{Path: "encryption.atRest", Value: true, Derivation: "platform-invariant"},
		{Path: "encryption.inTransit", Value: true, Derivation: "platform-invariant"},
		// regional (multi-AZ) by construction.
		{Path: "availability.class", Value: "regional", Derivation: "platform-invariant"},
	}
	var diags []string
	if c.Engine != "" && c.MajorEngineVersion != "" {
		obs = append(obs, provider.Observation{Path: "engine.protocol",
			Value: strings.ToLower(c.Engine) + "/" + c.MajorEngineVersion, Derivation: "measured"})
	} else {
		diags = append(diags, "engine.protocol not observed — the serverless cache did not report Engine/MajorEngineVersion")
	}
	// encryption.customerManagedKeys is not exposed on the serverless cache read
	// used here — do not fabricate it; a CMK trace is left to probe/reconcile.
	diags = append(diags, "encryption.customerManagedKeys not observed from DescribeServerlessCaches — probe/reconcile")
	return obs, diags, nil
}

func (d *Driver) deleteElastiCacheServerless(capability, environment, providerID string) provider.CreateResult {
	region, _, name, err := splitECacheServerlessProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	cur, found, rerr := d.describeServerlessCache(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	tags, terr := d.serverlessCacheTags(region, cur.ARN)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "serverless cache tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, e := d.ecacheServerlessPost(region, encodeForm(map[string]string{
		"Action": "DeleteServerlessCache", "Version": elastiCacheVersion,
		"ServerlessCacheName": name}))
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if strings.Contains(rdsErrCode(resp), "ServerlessCacheNotFoundFault") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete: HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete: HTTP %d (%s)", st, rdsErrCode(resp))}
	}
	// DeleteServerlessCache is async — poll DescribeServerlessCaches until the cache
	// is READABLY gone (D273: read the observable state, never an operation-by-id
	// path). A DELETE-FAILED, or the poll timeout, is unknown WITH the pid.
	deadline := d.Now().Add(d.PollTimeout)
	for {
		c, stillThere, derr := d.describeServerlessCache(region, name)
		if derr == nil && !stillThere {
			return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
		}
		if derr == nil && stillThere && strings.ToUpper(c.Status) == "DELETE-FAILED" {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "serverless cache entered DELETE-FAILED — reconcile"}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "serverless cache still deleting at poll timeout — reconcile via DescribeServerlessCaches"}
		}
		time.Sleep(d.PollInterval)
	}
}

// discoverElastiCacheServerless enumerates serverless caches in the region as
// capability.cache.keyvalue — so `discover --provider aws` surfaces a
// console/TF-stood serverless cache for adoption. DescribeServerlessCaches (no
// name = list all) -> per-cache reverse map.
func (d *Driver) discoverElastiCacheServerless(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("elasticache-serverless: %v", err)
	}
	st, body, err := d.ecacheServerlessPost(region, encodeForm(map[string]string{
		"Action": "DescribeServerlessCaches", "Version": elastiCacheVersion}))
	if err != nil {
		return nil, nil, fmt.Errorf("elasticache-serverless DescribeServerlessCaches: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("elasticache-serverless DescribeServerlessCaches: HTTP %d: %s", st, rdsErrCode(body))
	}
	var r struct {
		Caches []struct {
			Name string `xml:"ServerlessCacheName"`
		} `xml:"DescribeServerlessCachesResult>ServerlessCaches>member"` // D937: <member>, not <ServerlessCache> — see D936
	}
	if xml.Unmarshal(body, &r) != nil {
		return nil, nil, fmt.Errorf("elasticache-serverless DescribeServerlessCaches: HTTP %d but the response did not parse", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, c := range r.Caches {
		if c.Name == "" {
			continue
		}
		if !ecacheIDOK.MatchString(c.Name) {
			diags = append(diags, c.Name+": name not representable as ecserverless:region:account:name — needs adoption by explicit id")
			continue
		}
		pid := ecacheServerlessProviderID(region, account, c.Name)
		obs, odiags, oerr := d.observeElastiCacheServerless("", pid)
		if oerr != nil {
			diags = append(diags, c.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, c.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID: pid, ResourceType: "capability.cache.keyvalue", Observations: provider.WithoutAbsence(obs)})
	}
	return out, diags, nil
}

// serverlessCacheEndpoint returns the cache's client endpoint as host:port,
// read from the live cache (the address is server-assigned, not in the pid — the
// same honest one-read source vpc uses for its subnet ids). A non-nil error is a
// read failure naming the cause; a missing endpoint is an error, never a guess.
func (d *Driver) serverlessCacheEndpoint(region, name string) (string, error) {
	c, found, err := d.describeServerlessCache(region, name)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("serverless cache %s not found", name)
	}
	if c.Endpoint.Address == "" || c.Endpoint.Port == 0 {
		return "", fmt.Errorf("serverless cache %s reported no endpoint yet", name)
	}
	return c.Endpoint.Address + ":" + strconv.Itoa(c.Endpoint.Port), nil
}
