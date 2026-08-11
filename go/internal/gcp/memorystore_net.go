// GCP Memorystore network shell (D100): the bearer-signed REST half of the
// capability.cache.keyvalue driver. Create/delete are async (LRO) — the
// deterministic instance name means the providerId is knowable BEFORE the create
// response, so a lost/garbled outcome (D29) always carries the handle. Ownership is
// labels; the instance is always VPC-private (observe reports publicExposure=false
// as a measured fact, never a hopeful default). D29/D87 honesty throughout.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func (d *Driver) memorystoreBase() string {
	if d.MemorystoreBaseURL != "" {
		return d.MemorystoreBaseURL
	}
	return memorystoreBaseURL
}

func gredisProviderID(project, region, name string) string {
	return "gredis:" + project + ":" + region + ":" + name
}

func splitGRedisProviderID(providerID string) (project, region, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "gredis" {
		return "", "", "", fmt.Errorf("providerId %q is not gredis:project:region:name", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !redisRegionOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[2])
	}
	if !gcpName.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId instance %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

// redisRegionOK bounds a GCP region before it is interpolated into an instance
// URL (D73 boundary): lowercase letters, then a digit-suffixed region token.
var redisRegionOK = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]$`)

func (d *Driver) redisInstanceURL(project, region, name string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/instances/%s",
		d.memorystoreBase(), project, region, name)
}

type redisDoc struct {
	Name                  string            `json:"name"`
	Labels                map[string]string `json:"labels"`
	RedisVersion          string            `json:"redisVersion"`
	Tier                  string            `json:"tier"`
	TransitEncryptionMode string            `json:"transitEncryptionMode"`
	CustomerManagedKey    string            `json:"customerManagedKey"`
	State                 string            `json:"state"`
}

func (d *Driver) getRedis(project, region, name string) (redisDoc, bool, error) {
	const op = "redis.get"
	st, body, err := d.call("GET", d.redisInstanceURL(project, region, name), nil)
	if err != nil {
		return redisDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return redisDoc{}, false, nil
	}
	if st != http.StatusOK {
		return redisDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc redisDoc
	if json.Unmarshal(body, &doc) != nil {
		return redisDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createMemorystore(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildMemorystoreCreate(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := gredisProviderID(d.Project, plan.Region, plan.Name)
	url := fmt.Sprintf("%s/projects/%s/locations/%s/instances?instanceId=%s",
		d.memorystoreBase(), d.Project, plan.Region, plan.Name)
	st, body, err := d.call("POST", url, plan.createBody(capability, environment))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// LRO started — poll below
	case st == http.StatusConflict:
		doc, found, rerr := d.getRedis(d.Project, plan.Region, plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing instance gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
			doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "an instance with this name exists and is not ours (labels do not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // ours, already present
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "create response carried no operation — reconcile"}
	}
	res := d.pollRedisOperation(op.Name)
	if res.Status == "succeeded" {
		res.ProviderID = pid
	} else if res.ProviderID == "" {
		res.ProviderID = pid
	}
	return res
}

// pollRedisOperation polls an LRO to done. A still-running op at timeout is
// unknown WITH the operation id (never a confident success).
func (d *Driver) pollRedisOperation(opName string) provider.CreateResult {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		st, body, err := d.call("GET", d.memorystoreBase()+"/"+opName, nil)
		if err == nil && st == http.StatusOK {
			var op struct {
				Done  bool `json:"done"`
				Error *struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &op) == nil && op.Done {
				if op.Error != nil {
					return provider.CreateResult{Status: "failed", OperationID: opName,
						Reason: fmt.Sprintf("operation failed: %s", op.Error.Message)}
				}
				return provider.CreateResult{Status: "succeeded", OperationID: opName}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{Status: "unknown", OperationID: opName,
				Reason: "memorystore operation still running at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

func (d *Driver) observeMemorystore(capability, providerID string) ([]provider.Observation, []string, error) {
	project, region, name, err := splitGRedisProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getRedis(project, region, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"cache instance not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "encryption.atRest", Value: true, Derivation: "platform-invariant"},
		// Memorystore for Redis is always VPC-private — no public IP is assignable.
		{Path: "network.publicExposure", Value: false, Derivation: "measured"},
	}
	if v := redisProtocolFor(doc.RedisVersion); v != "" {
		obs = append(obs, provider.Observation{Path: "engine.protocol", Value: v, Derivation: "measured"})
	}
	obs = append(obs, provider.Observation{Path: "encryption.inTransit",
		Value: doc.TransitEncryptionMode == "SERVER_AUTHENTICATION", Derivation: "measured"})
	if doc.CustomerManagedKey != "" {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
			Value: true, Derivation: "measured"})
	}
	switch doc.Tier {
	case "BASIC":
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "zonal", Derivation: "measured"})
	case "STANDARD_HA":
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "regional", Derivation: "measured"})
	}
	return obs, nil, nil
}

// redisProtocolFor reverse-maps the Memorystore enum to engine.protocol.
func redisProtocolFor(v string) string {
	switch v {
	case "REDIS_7_0", "REDIS_7_2":
		return "redis/7"
	case "REDIS_6_X":
		return "redis/6"
	case "REDIS_5_0":
		return "redis/5"
	case "REDIS_4_0":
		return "redis/4"
	default:
		return ""
	}
}

func (d *Driver) deleteMemorystore(capability, environment, providerID string) provider.CreateResult {
	project, region, name, err := splitGRedisProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getRedis(project, region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
		doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "instance labels do not match — refusing to delete a resource that is not ours"}
	}
	st, body, e := d.call("DELETE", d.redisInstanceURL(project, region, name), nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		if r := provider.MutationResult(st, gcpErrCode(body), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "delete response carried no operation — reconcile"}
	}
	res := d.pollRedisOperation(op.Name)
	if res.Status == "succeeded" {
		res.ProviderID = providerID
	} else if res.ProviderID == "" {
		res.ProviderID = providerID
	}
	return res
}
