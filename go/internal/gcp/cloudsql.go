// Cloud SQL request building: a PURE function of its inputs, pinned by
// golden tests. The mapping table is the executable form of the
// vocabulary's gcp.cloudsql mappings — and the rule is REFUSE what
// cannot be honored (D43): silently dropping an attribute that satisfied
// a constraint would fake compliance.
package gcp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"groundhold/internal/scalars"
)

const baseURL = "https://sqladmin.googleapis.com/v1"

type Request struct {
	Method string
	URL    string
	Body   map[string]any
}

var protoRE = regexp.MustCompile(`^([a-z][a-z0-9\-]*)/(\d+)(?:\.(\d+))?`)
var nameOK = regexp.MustCompile(`[^a-z0-9-]`)

// InstanceName derives deterministically from (project, environment,
// capability, generation): a sanitized slug plus a short stable hash.
// Deterministic names are the idempotency mechanism — Cloud SQL insert
// has no idempotency-key parameter. Generation 1 keeps the historical
// shape so every existing binding stays valid; generations >= 2 (D48:
// replacements) carry a visible -gN and a generation-salted hash, so
// old and new instances coexist. The SLUG truncates, never the suffix —
// the 98-char limit must not chop uniqueness away.
func InstanceName(project, environment, capability string,
	generation int) string {
	return resourceName(project, environment, capability, generation, 98)
}

// resourceName is the shared deterministic-name logic (D43): a sanitized slug
// plus a short stable hash, generation-salted from g2 (D48). maxLen differs
// per service — Cloud SQL instances allow 98, Cloud Run services 63 — but the
// SLUG truncates, never the suffix, so uniqueness survives.
func resourceName(project, environment, capability string,
	generation, maxLen int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = nameOK.ReplaceAllString(strings.ToLower(slug), "-")

	suffix := ""
	hashInput := project + "|" + environment + "|" + capability
	if generation >= 2 {
		suffix = fmt.Sprintf("-g%d", generation)
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	tail := suffix + "-" + hex.EncodeToString(sum[:])[:8]
	if len(slug)+len(tail) > maxLen {
		slug = slug[:maxLen-len(tail)]
	}
	name := slug + tail
	if name[0] < 'a' || name[0] > 'z' {
		name = "p" + name[1:]
	}
	return name
}

// BuildCreateRequest maps semantic attributes + the implementation block
// to an instances.insert request. Every error here is a refusal that
// apply surfaces in preflight, before any mutation.
func BuildCreateRequest(project, environment, capability string,
	attrs, impl map[string]any, generation int) (Request, error) {

	if generation < 1 {
		generation = 1
	}
	settings := map[string]any{}
	body := map[string]any{
		"name":     InstanceName(project, environment, capability, generation),
		"settings": settings,
	}
	ipConfig := map[string]any{}
	haveRPO := false

	// deterministic iteration
	paths := make([]string, 0, len(attrs))
	for p := range attrs {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "engine.protocol":
			s, _ := raw.(string)
			m := protoRE.FindStringSubmatch(s)
			if m == nil {
				return Request{}, fmt.Errorf("cannot parse engine.protocol %q", s)
			}
			switch m[1] {
			case "postgresql":
				body["databaseVersion"] = "POSTGRES_" + m[2]
			case "mysql":
				v := "MYSQL_" + m[2]
				if m[3] != "" {
					v += "_" + m[3]
				}
				body["databaseVersion"] = v
			default:
				return Request{}, fmt.Errorf(
					"engine %q has no Cloud SQL mapping", m[1])
			}
		case "location.region":
			s, _ := raw.(string)
			body["region"] = s
		case "availability.class":
			switch raw {
			case "zonal":
				settings["availabilityType"] = "ZONAL"
			case "regional":
				settings["availabilityType"] = "REGIONAL"
			default:
				// multi-regional has no Cloud SQL equivalent — refuse
				return Request{}, fmt.Errorf(
					"availability.class %v cannot be honored by Cloud SQL", raw)
			}
		case "network.publicExposure":
			exposed, _ := raw.(bool)
			if exposed {
				ipConfig["ipv4Enabled"] = true
			} else {
				// private IP requires an EXPLICIT, pre-provisioned VPC
				// link — a database driver must not create network
				// peering as a side effect (D43)
				network, _ := impl["network"].(map[string]any)
				link, _ := network["privateNetwork"].(string)
				if link == "" {
					return Request{}, fmt.Errorf(
						"network.publicExposure=false requires " +
							"implementation.network.privateNetwork " +
							"(a prepared Private Services Access link)")
				}
				ipConfig["ipv4Enabled"] = false
				ipConfig["privateNetwork"] = link
				ipConfig["authorizedNetworks"] = []any{}
				if r, _ := network["allocatedIpRange"].(string); r != "" {
					ipConfig["allocatedIpRange"] = r
				}
			}
		case "recovery.rpo":
			sc, err := scalars.Parse(raw)
			if err != nil || sc.Kind != scalars.Duration {
				return Request{}, fmt.Errorf("recovery.rpo is not a duration")
			}
			if sc.Value.(float64) > 7*24*3600*1000 {
				return Request{}, fmt.Errorf(
					"recovery.rpo beyond PITR bounds (transaction log " +
						"retention is at most 7 days)")
			}
			// The backupConfiguration is assembled AFTER the loop: the PITR
			// mechanism is engine-specific (see below) and databaseVersion may
			// not be set yet.
			haveRPO = true
		case "encryption.atRest":
			if raw != true {
				// GCP encrypts at rest unconditionally; "unencrypted"
				// cannot be honored. And managed encryption must never
				// satisfy a future CMEK-specific constraint.
				return Request{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored by Cloud SQL")
			}
		case "encryption.customerManagedKeys":
			// CMEK: only true is actionable — false is the provider default
			// (already the baseline), so it configures nothing. A true value
			// needs the key id, which is implementation detail (D26).
			if raw == true {
				key, _ := impl["kms_key_name"].(string)
				if key == "" {
					return Request{}, fmt.Errorf(
						"encryption.customerManagedKeys requires " +
							"implementation.kms_key_name (a Cloud KMS key resource) — " +
							"the provider default key does not satisfy it")
				}
				settings["diskEncryptionConfiguration"] = map[string]any{
					"kmsKeyName": key}
			}
		case "encryption.inTransit":
			// enforce TLS on the SAME ipConfiguration the insert already sets.
			// Only true is actionable — false is the provider default (allow both).
			if raw == true {
				ipConfig["sslMode"] = "ENCRYPTED_ONLY"
			}
		case "service.managed":
			if raw != true {
				return Request{}, fmt.Errorf(
					"service.managed=false cannot be honored by Cloud SQL")
			}
		default:
			return Request{}, fmt.Errorf(
				"attribute %s has no Cloud SQL mapping — refusing rather "+
					"than silently dropping it", path)
		}
	}

	if body["region"] == nil {
		return Request{}, fmt.Errorf("location.region is required")
	}
	if body["databaseVersion"] == nil {
		return Request{}, fmt.Errorf("engine.protocol is required")
	}

	// recovery.rpo -> point-in-time recovery, but the MECHANISM is engine-specific
	// and the two spellings are MUTUALLY EXCLUSIVE at the API (field 2026-08-08, D950):
	// a MySQL instance rejects pointInTimeRecoveryEnabled ("Point-in-time recovery can
	// only be enabled for Postgres and SQL Server instances", 400) — its PITR is
	// binaryLogEnabled; a Postgres instance rejects binaryLogEnabled ("Binary log can
	// only be enabled for MySQL instances", 400). The old body sent
	// pointInTimeRecoveryEnabled for EVERY engine, so it was uncreatable for MySQL —
	// the flagship engine (CLAUDE.md's first real-cloud run) — while the golden test
	// only exercised Postgres and stayed green.
	if haveRPO {
		dv, _ := body["databaseVersion"].(string)
		backup := map[string]any{"enabled": true}
		if strings.HasPrefix(dv, "MYSQL_") {
			backup["binaryLogEnabled"] = true
		} else {
			backup["pointInTimeRecoveryEnabled"] = true
		}
		settings["backupConfiguration"] = backup
	}

	// implementation block (D26): provider detail
	tier, _ := impl["tier"].(string)
	if tier == "" {
		return Request{}, fmt.Errorf("implementation.tier is required")
	}
	settings["tier"] = tier
	// edition (ENTERPRISE | ENTERPRISE_PLUS): tiers are edition-specific and
	// GCP's DEFAULT edition has flipped under us more than once (found by the
	// D79 canary: db-perf-optimized-N-2 is ENTERPRISE_PLUS-only, rejected under
	// an ENTERPRISE default). Pinning it makes the create depend on what we
	// declare, not on a shifting account default. Refuse an unknown value rather
	// than let GCP reinterpret it.
	if ed, has := impl["edition"]; has {
		edition, _ := ed.(string)
		switch edition {
		case "ENTERPRISE", "ENTERPRISE_PLUS":
			settings["edition"] = edition
		default:
			return Request{}, fmt.Errorf(
				"implementation.edition %q is not ENTERPRISE or ENTERPRISE_PLUS", ed)
		}
	}
	if dt, _ := impl["disk_type"].(string); dt != "" {
		settings["dataDiskType"] = dt
	}
	if flags, ok := impl["flags"].(map[string]any); ok {
		names := make([]string, 0, len(flags))
		for n := range flags {
			names = append(names, n)
		}
		sort.Strings(names)
		list := []any{}
		for _, n := range names {
			v := flags[n]
			var s string
			switch x := v.(type) {
			case bool:
				s = "off"
				if x {
					s = "on"
				}
			case string:
				s = x
			case int:
				s = fmt.Sprintf("%d", x)
			default:
				return Request{}, fmt.Errorf(
					"flag %s has unsupported value type", n)
			}
			list = append(list, map[string]any{"name": n, "value": s})
		}
		settings["databaseFlags"] = list
	}
	if len(ipConfig) > 0 {
		settings["ipConfiguration"] = ipConfig
	}
	// ownership labels: the 409 continuation path adopts ONLY instances
	// carrying matching labels (D43)
	settings["userLabels"] = map[string]any{
		"groundhold-capability":  sanitizeLabel(capability),
		"groundhold-environment": sanitizeLabel(environment),
	}
	// D47: databases are stateful — deletion protection defaults ON.
	// Opting out is a reviewed, hash-pinned decision in the candidate.
	// FAIL CLOSED: a present-but-non-bool value (a typo like the string
	// "true", a null, a number) must NOT silently disable protection —
	// that would turn a typo into the opposite of intent. Only a real
	// bool false opts out.
	protection := true
	if v, has := impl["deletion_protection"]; has {
		b, ok := v.(bool)
		if !ok {
			return Request{}, fmt.Errorf(
				"deletion_protection must be a boolean, got %T (%v) — "+
					"refusing to guess; protection stays on", v, v)
		}
		protection = b
	}
	settings["deletionProtectionEnabled"] = protection

	return Request{
		Method: "POST",
		URL:    fmt.Sprintf("%s/projects/%s/instances", baseURL, project),
		Body:   body,
	}, nil
}
