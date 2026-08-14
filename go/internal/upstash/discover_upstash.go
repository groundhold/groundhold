package upstash

import (
	"encoding/json"
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

// List enumerates existing Upstash resources as vocabulary capabilities — the
// upstash half of the gentle crawl (pair -> discover for context). Strictly
// read-only. Today it sweeps Redis databases only; Kafka/QStash are a deferred
// follow-up (a new sweep appended here, mirroring the AWS multi-service loop).
//
// Upstash's list endpoint is ACCOUNT-GLOBAL — GET /v2/redis/databases returns
// every database across all regions in a single call, with no project/region
// query axis. So `region` is a FILTER, not a scope: "" returns every database
// (the crawl's default), a non-empty region keeps only databases in it. This is
// why the driver implements NO Enumerator — there are no crawlable scopes to
// fan out over.
func (d *Driver) List(region string) ([]provider.Discovered, []string, error) {
	return d.discoverRedis(region)
}

// redisDB is the subset of the Upstash database object we read. Secret fields
// (password, rest_token, read_only_rest_token) are never even requested — the
// LIST endpoint does not return them, and the driver never calls get_database.
type redisDB struct {
	ID             string `json:"database_id"`
	Name           string `json:"database_name"`
	Region         string `json:"region"`
	PrimaryRegion  string `json:"primary_region"`
	TLS            bool   `json:"tls"`
	Eviction       bool   `json:"eviction"`
	Type           string `json:"type"`
	State          string `json:"state"`
	SecurityAddons struct {
		VPCPeering       bool `json:"vpcPeering"`
		PrivateLink      bool `json:"privateLink"`
		EncryptionAtRest bool `json:"encryptionAtRest"`
	} `json:"securityAddons"`
}

// effectiveRegion is the database's home region, falling back to the cluster
// primary_region when the plain region field is empty (Global databases).
func (db redisDB) effectiveRegion() string {
	if db.Region != "" {
		return db.Region
	}
	return db.PrimaryRegion
}

// discoverRedis lists Upstash Redis databases as capability.cache.keyvalue.
func (d *Driver) discoverRedis(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.doGET("/redis/databases")
	if err != nil {
		return nil, nil, err
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("upstash list databases: HTTP %d", st)
	}
	var dbs []redisDB
	if err := json.Unmarshal(body, &dbs); err != nil {
		return nil, nil, fmt.Errorf("upstash list databases: %w", err)
	}
	var out []provider.Discovered
	var diags []string
	for _, db := range dbs {
		if db.ID == "" {
			continue
		}
		if region != "" && db.effectiveRegion() != region {
			continue // lives in another region — not this sweep
		}
		obs, odiags := mapRedisDB(db)
		for _, dg := range odiags {
			diags = append(diags, db.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   upstashProviderID(db.ID),
			ResourceType: "capability.cache.keyvalue",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// upstashProviderID pins the identity. Upstash database ids are globally unique,
// so region/account are not part of the identity (unlike AWS's ecredis:...).
func upstashProviderID(id string) string { return "upstash:redis:" + id }

// mapRedisDB is the PURE reverse-map from an Upstash Redis database to
// capability.cache.keyvalue observations — the same mapping an Observe would
// use. Every observation is `measured` (read from the live API). Fields that
// are sizing/tuning noise (eviction, port, endpoint, plan tier, db_* limits)
// are deliberately dropped, per the vocab's "Deliberately absent" list. Values
// we did not measure are OMITTED (unknown != false), never guessed.
func mapRedisDB(db redisDB) ([]provider.Observation, []string) {
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "location.region", Value: db.effectiveRegion(), Derivation: "measured"},
		// Upstash `tls` = client connections must be TLS.
		{Path: "encryption.inTransit", Value: db.TLS, Derivation: "measured"},
		// Upstash databases expose a public TLS endpoint by default; only a
		// PrivateLink / VPC-peering addon fronts them privately.
		{Path: "network.publicExposure",
			Value:      !(db.SecurityAddons.PrivateLink || db.SecurityAddons.VPCPeering),
			Derivation: "measured"},
		// D1050: at-rest encryption is a security addon read from the same list response,
		// so its absence is a MEASURED false, not an unknown — emit the bool for BOTH
		// states (D1040/D1003). Emitting only the true case let an `encryption.atRest: true`
		// candidate be adopted over a database without the addon; a false here blocks/refuses
		// instead, the safe direction even if the field were ever absent from the response.
		{Path: "encryption.atRest", Value: db.SecurityAddons.EncryptionAtRest, Derivation: "measured"},
	}
	// engine.protocol: Upstash is Redis-compatible but the list endpoint reports
	// no explicit version, and availability.class (multi-regional) has no single
	// managed primitive in the vocab — both are omitted rather than faked.
	diags := []string{
		"engine.protocol not observed — the list endpoint reports no explicit Redis version",
	}
	return obs, diags
}
