// RDS request building (D86): the semantic core of the AWS database.relational
// driver — the SAME vocabulary Cloud SQL fulfils (thesis proof, D85). RDS uses
// the AWS Query protocol (form-urlencoded params, XML response) and CreateDB is
// ASYNC — no LRO/operation; the shell polls DescribeDBInstances until the
// instance is "available". Engine/version, tier, storage and credentials are
// implementation detail; the vocabulary carries capability semantics only.
package aws

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const rdsVersion = "2014-10-31"

// dbIDOK bounds an RDS DB instance identifier before path/param interpolation.
var dbIDOK = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// DBIdentifier is the deterministic instance id (RDS: 1-63 chars, start with a
// letter, alphanumeric + hyphen, no consecutive/trailing hyphens). Letters-only
// tail keeps it valid under the strict charset.
func DBIdentifier(account, environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	var b strings.Builder
	prevHyphen := false
	for _, r := range strings.ToLower(slug) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			prevHyphen = false
		} else if !prevHyphen {
			// collapse runs of disallowed chars to a SINGLE hyphen — RDS rejects
			// consecutive hyphens, so this must be a builder concern (D-battery).
			b.WriteByte('-')
			prevHyphen = true
		}
	}
	slug = strings.Trim(b.String(), "-")
	tail := "-" + letterHash(account+"|"+environment+"|"+capability+genSuffix(generation), 8)
	const maxLen = 63
	if len(slug)+len(tail) > maxLen {
		slug = slug[:maxLen-len(tail)]
		slug = strings.TrimRight(slug, "-")
	}
	name := slug + tail
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		name = "d" + strings.TrimLeft(name, "-")
	}
	return name
}

func genSuffix(generation int) string {
	if generation >= 2 {
		return fmt.Sprintf("|g%d", generation)
	}
	return ""
}

// engineFromProtocol maps a vocab engine.protocol ("postgresql/16", "mysql/8.0")
// to the RDS (Engine, EngineVersion). Unknown engines are refused.
func engineFromProtocol(proto string) (engine, version string, err error) {
	parts := strings.SplitN(proto, "/", 2)
	name := parts[0]
	if len(parts) == 2 {
		version = parts[1]
	}
	switch name {
	case "postgresql", "postgres":
		return "postgres", version, nil
	case "mysql":
		return "mysql", version, nil
	case "mariadb":
		return "mariadb", version, nil
	default:
		return "", "", fmt.Errorf("engine %q has no RDS mapping", name)
	}
}

// BuildRDSCreate maps capability.database.relational attributes + the impl block
// to a CreateDBInstance query body. Every error is a refusal apply surfaces in
// preflight, before any mutation.
func BuildRDSCreate(account, environment, capability string,
	attrs, impl map[string]any, generation int) (id string, body string, err error) {
	id = DBIdentifier(account, environment, capability, generation)
	p := map[string]string{
		"Action":               "CreateDBInstance",
		"Version":              rdsVersion,
		"DBInstanceIdentifier": id,
		"StorageEncrypted":     "true", // encryption.atRest baseline
		// ownership tags
		"Tags.member.1.Key":   "groundhold-capability",
		"Tags.member.1.Value": sanitizeTag(capability),
		"Tags.member.2.Key":   "groundhold-environment",
		"Tags.member.2.Value": sanitizeTag(environment),
	}

	// implementation block (D26): provider detail
	class, _ := impl["instance_class"].(string)
	if class == "" {
		return "", "", fmt.Errorf("rds requires implementation.instance_class (e.g. db.t3.micro)")
	}
	p["DBInstanceClass"] = class
	storage, _ := impl["allocated_storage"].(string)
	if storage == "" {
		storage = "20"
	}
	p["AllocatedStorage"] = storage
	user, _ := impl["master_username"].(string)
	if user == "" {
		return "", "", fmt.Errorf("rds requires implementation.master_username")
	}
	p["MasterUsername"] = user
	pass, _ := impl["master_password"].(string)
	if pass == "" {
		return "", "", fmt.Errorf("rds requires implementation.master_password")
	}
	p["MasterUserPassword"] = pass
	// optional DB subnet group (network placement — impl detail). Without it RDS
	// uses default subnets, which a VPC may lack.
	if sg, _ := impl["db_subnet_group"].(string); sg != "" {
		p["DBSubnetGroupName"] = sg
	}
	// deletion protection defaults ON (D47 posture); a reviewed opt-out is explicit
	if dp, has := impl["deletion_protection"]; has {
		b, ok := dp.(bool)
		if !ok {
			return "", "", fmt.Errorf("deletion_protection must be a boolean")
		}
		p["DeletionProtection"] = boolStr(b)
	} else {
		p["DeletionProtection"] = "true"
	}

	rpoSet := false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "engine.protocol":
			proto, _ := raw.(string)
			eng, ver, e := engineFromProtocol(proto)
			if e != nil {
				return "", "", e
			}
			p["Engine"] = eng
			if ver != "" {
				p["EngineVersion"] = ver
			}
		case "location.region":
			// the region is the endpoint (driver-level), not a create param
		case "network.publicExposure":
			p["PubliclyAccessible"] = boolStr(raw == true)
		case "encryption.atRest":
			if raw != true {
				return "", "", fmt.Errorf(
					"encryption.atRest=false cannot be honored (StorageEncrypted is set true)")
			}
		case "encryption.customerManagedKeys":
			// CMEK: StorageEncrypted is already the baseline; a customer key is
			// the KmsKeyId param on the SAME CreateDBInstance call (no second
			// resource). Only true is actionable — false is the account-default
			// aws/rds key. The key id is implementation detail (D26).
			if raw == true {
				key, _ := impl["kms_key_id"].(string)
				if key == "" {
					return "", "", fmt.Errorf(
						"encryption.customerManagedKeys requires " +
							"implementation.kms_key_id (a customer KMS key) — " +
							"the account-default aws/rds key does not satisfy it")
				}
				p["KmsKeyId"] = key
			}
		case "availability.class":
			switch raw {
			case "regional":
				p["MultiAZ"] = "true"
			case "zonal":
				p["MultiAZ"] = "false"
			case "multi-regional":
				return "", "", fmt.Errorf("availability.class multi-regional has no single-instance RDS mapping")
			default:
				// refuse rather than silently building single-AZ (the builder's
				// contract elsewhere: never silently drop an attribute)
				return "", "", fmt.Errorf("availability.class %v has no RDS mapping", raw)
			}
		case "recovery.rpo":
			// any finite RPO requires automated backups; default a 7-day window.
			p["BackupRetentionPeriod"] = "7"
			rpoSet = true
		case "encryption.inTransit":
			// Enforcing TLS on RDS needs a DB PARAMETER GROUP with rds.force_ssl=1 —
			// a SEPARATE binding the driver must not create as a side effect (the
			// one-binding rule). The operator BRINGS a pre-created one, exactly as
			// they bring the DB subnet group and the KMS key (D26); the driver
			// REFERENCES it on the same CreateDBInstance call. Refuse only when the
			// operand is absent. The create trusts the operand; observe reads the
			// group's rds.force_ssl and reports the measured reality.
			if raw == true {
				pg, _ := impl["db_parameter_group"].(string)
				if pg == "" {
					return "", "", fmt.Errorf(
						"encryption.inTransit=true requires implementation.db_parameter_group " +
							"(a DB parameter group with rds.force_ssl=1) — a separate binding " +
							"the driver references but does not create")
				}
				p["DBParameterGroupName"] = pg
			}
		case "service.managed":
			if raw != true {
				return "", "", fmt.Errorf("service.managed=false cannot be honored by RDS")
			}
		default:
			return "", "", fmt.Errorf(
				"attribute %s has no RDS mapping — refusing rather than silently dropping it", path)
		}
	}
	_ = rpoSet
	if p["Engine"] == "" {
		return "", "", fmt.Errorf("rds requires engine.protocol")
	}
	return id, encodeForm(p), nil
}

// encodeForm renders sorted form-urlencoded params (sorted for golden tests;
// the wire order does not affect the SigV4 payload hash — the body is hashed
// whole).
func encodeForm(p map[string]string) string {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, rfc3986(k)+"="+rfc3986(p[k]))
	}
	return strings.Join(parts, "&")
}

// rdsSimpleBody builds a query body for a parameterless-ish action (describe,
// delete) with the given extra params.
func rdsSimpleBody(action string, extra map[string]string) string {
	p := map[string]string{"Action": action, "Version": rdsVersion}
	for k, v := range extra {
		p[k] = v
	}
	return encodeForm(p)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
