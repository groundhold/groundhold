// Reverse mapping: instances.get -> semantic vocabulary attributes.
// A PURE function pinned by golden tests (D44). The rules of honesty:
//   - absent fields emit NOTHING, never a zero-value default;
//   - unknown enums skip that path with a diagnostic, never crash;
//   - config-derived values carry derivation "config-intent", state-
//     backed values "measured" — mirroring candidate provenance (D5);
//   - never fabricate a measurement from intent: PITR implies a good
//     RPO but its VALUE needs a probe, so nothing is emitted for it.
package gcp

import (
	"fmt"
	"strings"

	"groundhold/internal/caplens"
)

type Observed struct {
	Path       string
	Value      any
	Derivation string // config-intent | measured
}

// MapInstance extracts semantic observations from an instances.get
// response. Diagnostics name what was deliberately not observed and why.
func MapInstance(inst map[string]any) ([]Observed, []string) {
	var out []Observed
	var diags []string
	settings, _ := inst["settings"].(map[string]any)

	// engine.protocol: never invent a minor version (POSTGRES_16 is 16)
	if dv, ok := inst["databaseVersion"].(string); ok {
		if proto, ok := VersionToProtocol(dv); ok {
			out = append(out, Observed{"engine.protocol", proto, "measured"})
		} else {
			diags = append(diags,
				fmt.Sprintf("databaseVersion %q: unknown enum, skipped", dv))
		}
	}

	if region, ok := inst["region"].(string); ok && region != "" {
		out = append(out, Observed{"location.region", region, "measured"})
	}

	if at, ok := settings["availabilityType"].(string); ok {
		if class, ok := AvailabilityToClass(at); ok {
			out = append(out, Observed{"availability.class", class, "measured"})
		} else {
			diags = append(diags, fmt.Sprintf(
				"availabilityType %q: unknown enum, skipped", at))
		}
	}

	observeExposure(inst, settings, &out, &diags)
	observeRPO(settings, &out, &diags)

	// platform properties of Cloud SQL itself
	out = append(out, Observed{"service.managed", true, "measured"})
	out = append(out, Observed{"encryption.atRest", true, "config-intent"})

	// customerManagedKeys: a CMEK is present iff diskEncryptionConfiguration
	// carries a kmsKeyName. Absent means the Google-managed default key — which
	// does NOT satisfy the constraint, so emit nothing rather than a false.
	if dek, ok := settings["diskEncryptionConfiguration"].(map[string]any); ok {
		if key, _ := dek["kmsKeyName"].(string); key != "" {
			out = append(out, Observed{"encryption.customerManagedKeys", true, "measured"})
		}
	}

	// inTransit: sslMode reports whether TLS is ENFORCED. ENCRYPTED_ONLY and
	// TRUSTED_CLIENT_CERTIFICATE_REQUIRED both require TLS; the default
	// ALLOW_UNENCRYPTED_AND_ENCRYPTED does NOT. Absent sslMode emits nothing.
	if ipConfig, ok := settings["ipConfiguration"].(map[string]any); ok {
		if mode, _ := ipConfig["sslMode"].(string); mode != "" {
			enforced := mode == "ENCRYPTED_ONLY" ||
				mode == "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
			out = append(out, Observed{"encryption.inTransit", enforced, "measured"})
		}
	}

	return out, diags
}

// observeExposure requires BOTH config intent and observed state to
// claim publicExposure=false; either surface saying "exposed" wins, and
// missing fields emit nothing rather than defaulting to safe.
func observeExposure(inst, settings map[string]any,
	out *[]Observed, diags *[]string) {
	ipConfig, _ := settings["ipConfiguration"].(map[string]any)
	ipv4, hasIpv4 := ipConfig["ipv4Enabled"].(bool)
	if !hasIpv4 {
		*diags = append(*diags,
			"ipConfiguration.ipv4Enabled absent — exposure not observed")
		return
	}
	authorized, _ := ipConfig["authorizedNetworks"].([]any)

	// evidence: assigned addresses
	var hasPublicAddr bool
	addrs, hasAddrs := inst["ipAddresses"].([]any)
	if hasAddrs {
		for _, a := range addrs {
			m, _ := a.(map[string]any)
			if t, _ := m["type"].(string); t == "PRIMARY" {
				hasPublicAddr = true
			}
		}
	}

	// newer exposure surface: Data API access from the public internet
	dataAPIExposed := false
	if da, ok := settings["dataApiAccess"].(string); ok &&
		strings.Contains(da, "ENABLED") {
		dataAPIExposed = true
	}

	switch {
	case ipv4 || hasPublicAddr || len(authorized) > 0 || dataAPIExposed:
		*out = append(*out, Observed{"network.publicExposure", true, "measured"})
	case !hasAddrs:
		*diags = append(*diags,
			"ipAddresses absent — cannot evidence publicExposure=false "+
				"from config intent alone")
	default:
		*out = append(*out, Observed{"network.publicExposure", false, "measured"})
	}
}

// observeRPO emits only what is honestly derivable: daily backups
// without PITR bound the data-loss window at 24h (config intent). PITR
// implies a far better RPO, but its VALUE is a measurement — a probe's
// job, not a config reader's.
func observeRPO(settings map[string]any, out *[]Observed, diags *[]string) {
	backup, _ := settings["backupConfiguration"].(map[string]any)
	enabled, hasEnabled := backup["enabled"].(bool)
	if !hasEnabled || !enabled {
		return
	}
	if pitr, _ := backup["pointInTimeRecoveryEnabled"].(bool); pitr {
		*diags = append(*diags, "PITR enabled — recovery.rpo value "+
			"requires a probe, not fabricated from config")
		return
	}
	*out = append(*out, Observed{"recovery.rpo", "24h", "config-intent"})
}

// VersionToProtocol translates the Cloud SQL databaseVersion enum into
// the vocabulary's engine.protocol — ONE table for observe (API shape)
// and the state importer (D53); the two must never drift.
func VersionToProtocol(dv string) (string, bool) {
	switch {
	case strings.HasPrefix(dv, "POSTGRES_"):
		return caplens.EngineProtocol(caplens.EnginePostgres, strings.TrimPrefix(dv, "POSTGRES_")), true
	case strings.HasPrefix(dv, "MYSQL_"):
		parts := strings.Split(strings.TrimPrefix(dv, "MYSQL_"), "_")
		return caplens.EngineProtocol(caplens.EngineMySQL, strings.Join(parts, ".")), true
	}
	return "", false
}

// AvailabilityToClass translates the Cloud SQL availabilityType enum onto the
// shared availability vocabulary (caplens) — one authority for the class values.
func AvailabilityToClass(at string) (string, bool) {
	switch at {
	case "ZONAL":
		return caplens.ClassZonal, true
	case "REGIONAL":
		return caplens.ClassRegional, true
	}
	return "", false
}
