// Aurora request building (D152): the SAME capability.database.relational
// vocabulary RDS fulfils (D85 thesis proof, D76 one-TYPE-many-services) but as a
// distinct SERVICE token "aurora" — an Aurora PostgreSQL Serverless v2 CLUSTER
// (a writer, optionally a reader), not a single RDS instance. Aurora speaks the
// SAME rds.<region>.amazonaws.com RDS Query protocol (form-urlencoded params, XML
// response), so the SigV4 plumbing, encodeForm and error decoding are reused
// verbatim; only the Actions differ (CreateDBCluster + CreateDBInstance).
//
// Semantics live here, in a PURE builder: engine/version, encryption and
// availability come from the vocabulary; the DB subnet group, the Serverless v2
// ACU floor/ceiling, the KMS key and the security groups are implementation
// operands (D26). Every refusal here surfaces in preflight, before any mutation.
package aws

import (
	"fmt"
	"strconv"
	"strings"
)

// auroraEngine is the only PostgreSQL Aurora engine name; the reverse map strips
// the "aurora-" prefix back onto the capability protocol.
const auroraEngine = "aurora-postgresql"

// AuroraPlan is the compiled two-step composite: one CreateDBCluster plus one
// (zonal) or two (regional) CreateDBInstance calls. The bodies are built from
// this — deterministic, so the providerId is knowable before any response.
type AuroraPlan struct {
	ClusterID     string
	WriterID      string
	ReaderID      string // "" unless availability.class=regional
	Regional      bool
	Engine        string
	EngineVersion string

	// DeriveSubnetGroup + SubnetIDs (D278): the operator gave subnet ids
	// (typically {$ref: vpc.privateSubnetIds}) instead of a pre-created DB
	// subnet group — the driver derives and OWNS the group as a sub-resource
	// of this cluster's composite create, exactly as vpc owns its subnets.
	DeriveSubnetGroup string
	SubnetIDs         []string

	// DeriveParamGroup + TLSParam (D288): encryption.inTransit=true with no
	// operator-supplied group — the driver derives and OWNS a cluster parameter
	// group carrying exactly the one parameter that enforces TLS, and attaches
	// it at create. ParamFamily is the engine family AWS requires to create it.
	DeriveParamGroup string
	ParamFamily      string
	TLSParamName     string
	TLSParamValue    string

	clusterParams      map[string]string
	publiclyAccessible bool
	publicSet          bool
}

// derivedSubnetGroupName is the deterministic name of a driver-owned subnet
// group (D278) — shared by aurora (DB subnet group) and elasticache (cache
// subnet group). Generation-free on purpose: a D48 replacement's successor
// reuses the group (it is free placement wiring), so the old generation's
// delete leaves it standing while in use.
func derivedSubnetGroupName(environment, capability string) string {
	slug := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, capability+"-"+environment)
	slug = strings.Trim(slug, "-")
	return "pv-" + slug + "-sng-" + letterHash("sng|"+environment+"|"+capability, 8)
}

// auroraEngineFromProtocol maps a vocab engine.protocol ("postgresql/16") to the
// Aurora (Engine, EngineVersion). Unknown engines are refused, never dropped.
func auroraEngineFromProtocol(proto string) (engine, version string, err error) {
	parts := strings.SplitN(proto, "/", 2)
	name := parts[0]
	if len(parts) == 2 {
		version = parts[1]
	}
	switch name {
	case "postgresql", "postgres":
		return auroraEngine, version, nil
	case "mysql":
		return "aurora-mysql", version, nil
	default:
		return "", "", fmt.Errorf("engine %q has no Aurora mapping", name)
	}
}

// derivedParamGroupName is the deterministic name of the driver-owned cluster
// parameter group (D288). Generation-free like the subnet group: a D48
// replacement's successor attaches the same group.
func derivedParamGroupName(environment, capability string) string {
	slug := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, capability+"-"+environment)
	slug = strings.Trim(slug, "-")
	return "pv-" + slug + "-tls-" + letterHash("tls|"+environment+"|"+capability, 8)
}

// auroraTLSParam names the parameter that ENFORCES TLS for an Aurora engine.
// The two engines do NOT share it — PostgreSQL rejects connections via
// rds.force_ssl, MySQL via require_secure_transport — so a single hardcoded
// name would create a group that enforces NOTHING on the other engine while
// the contract claims encryption.inTransit=true. That is a security-shaped
// lie, so an engine this driver cannot name refuses instead.
func auroraTLSParam(engine string) (name, value string, ok bool) {
	switch engine {
	case auroraEngine: // aurora-postgresql
		return "rds.force_ssl", "1", true
	case "aurora-mysql":
		return "require_secure_transport", "ON", true
	}
	return "", "", false
}

// auroraParamFamily derives the DB parameter group family AWS requires to
// CREATE a group (e.g. "aurora-postgresql16", "aurora-mysql8.0"). A family
// this driver cannot derive with certainty REFUSES — a wrong family is
// rejected by AWS mid-create, and guessing one is exactly the behaviour the
// never-fabricate rule forbids.
func auroraParamFamily(engine, version string) (string, error) {
	major := strings.SplitN(version, ".", 2)[0]
	switch engine {
	case auroraEngine:
		if major == "" || !isDigits(major) {
			return "", fmt.Errorf(
				"cannot derive the parameter-group family for %s without a major "+
					"engine version (engine.protocol: postgresql/<major>)", engine)
		}
		return "aurora-postgresql" + major, nil
	case "aurora-mysql":
		switch {
		case strings.HasPrefix(version, "8.0"), version == "8":
			return "aurora-mysql8.0", nil
		case strings.HasPrefix(version, "5.7"):
			return "aurora-mysql5.7", nil
		}
		return "", fmt.Errorf(
			"cannot derive the parameter-group family for aurora-mysql from version %q "+
				"(known families: 8.0, 5.7)", version)
	}
	return "", fmt.Errorf("engine %q has no parameter-group family mapping", engine)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// auroraInstanceID derives a member instance id from the cluster id, bounded to
// the RDS 63-char identifier limit (letter start, no trailing hyphen).
func auroraInstanceID(clusterID, suffix string) string {
	max := 63 - 1 - len(suffix)
	base := clusterID
	if len(base) > max {
		base = base[:max]
	}
	base = strings.TrimRight(base, "-")
	return base + "-" + suffix
}

// acuOperand reads a required Serverless v2 ACU operand and renders it for the
// wire. Accepts a JSON/YAML number or a numeric string; anything else refuses.
// allowZero permits 0 on the MIN operand — Serverless v2 auto-pause (scale to
// zero, MinCapacity=0); the MAX operand still refuses 0.
func acuOperand(impl map[string]any, key string, allowZero bool) (string, float64, error) {
	v, has := impl[key]
	if !has {
		return "", 0, fmt.Errorf("aurora requires implementation.%s (Serverless v2 ACU, e.g. 0.5)", key)
	}
	var f float64
	switch t := v.(type) {
	case float64:
		f = t
	case int:
		f = float64(t)
	case string:
		parsed, err := strconv.ParseFloat(t, 64)
		if err != nil {
			return "", 0, fmt.Errorf("implementation.%s must be a number of ACUs, got %q", key, t)
		}
		f = parsed
	default:
		return "", 0, fmt.Errorf("implementation.%s must be a number of ACUs", key)
	}
	if f < 0 || (f == 0 && !allowZero) {
		return "", 0, fmt.Errorf("implementation.%s must be > 0", key)
	}
	return strconv.FormatFloat(f, 'f', -1, 64), f, nil
}

// stringList coerces a vpcSecurityGroupIds operand (a list, or a single string)
// to a slice; a non-string element refuses.
func stringList(v any) ([]string, error) {
	switch t := v.(type) {
	case []string:
		return t, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("vpcSecurityGroupIds must be a list of strings")
			}
			out = append(out, s)
		}
		return out, nil
	case string:
		return []string{t}, nil
	default:
		return nil, fmt.Errorf("vpcSecurityGroupIds must be a list of strings")
	}
}

// BuildAurora maps capability.database.relational attributes + the impl operands
// to an AuroraPlan (CreateDBCluster params + the member instance ids). Every
// error is a refusal apply surfaces in preflight, before any mutation.
func BuildAurora(account, environment, capability string,
	attrs, impl map[string]any, generation int) (AuroraPlan, error) {
	clusterID := DBIdentifier(account, environment, capability, generation)
	p := AuroraPlan{ClusterID: clusterID}
	cp := map[string]string{
		"Action":              "CreateDBCluster",
		"Version":             rdsVersion,
		"DBClusterIdentifier": clusterID,
		// ownership tags (D52) — ownership lives on the CLUSTER
		"Tags.member.1.Key":   "groundhold-capability",
		"Tags.member.1.Value": sanitizeTag(capability),
		"Tags.member.2.Key":   "groundhold-environment",
		"Tags.member.2.Value": sanitizeTag(environment),
	}

	// ---- implementation operands (D26): provider placement detail ----
	// D278: placement arrives as EITHER a pre-created DB subnet group name OR
	// the subnet ids themselves (typically {$ref: vpc.privateSubnetIds}) — the
	// driver then derives and owns the group. One source of truth: both given
	// is refused, never silently arbitrated.
	subnet, _ := impl["subnetGroupName"].(string)
	subnetIDs := implStrings(impl, "subnetIds")
	switch {
	case subnet != "" && len(subnetIDs) > 0:
		return AuroraPlan{}, fmt.Errorf(
			"implementation.subnetGroupName and implementation.subnetIds are both set — one source of truth, refusing")
	case subnet != "":
		cp["DBSubnetGroupName"] = subnet
	case len(subnetIDs) >= 2:
		p.DeriveSubnetGroup = derivedSubnetGroupName(environment, capability)
		p.SubnetIDs = subnetIDs
		cp["DBSubnetGroupName"] = p.DeriveSubnetGroup
	case len(subnetIDs) == 1:
		return AuroraPlan{}, fmt.Errorf(
			"implementation.subnetIds needs >=2 subnets in distinct availability zones (a DB subnet group spans AZs)")
	default:
		return AuroraPlan{}, fmt.Errorf(
			"aurora requires implementation.subnetGroupName (a pre-created DB subnet group) OR " +
				"implementation.subnetIds (>=2 private subnets, e.g. {$ref: {capability: <vpc-cap>, output: privateSubnetIds}})")
	}

	// master credentials: CreateDBCluster REQUIRES a master user, so this is
	// checked HERE (Validate delegates to BuildAurora) — a missing credential
	// refuses in preflight, never mid-flight at CreateDBCluster after a sibling
	// resource already landed. Two honest shapes: an explicit password, or
	// AWS-managed via manageMasterUserPassword=true (Secrets Manager holds it — no
	// plaintext in the candidate, the more secure choice). Exactly one.
	user, _ := impl["masterUsername"].(string)
	if user == "" {
		return AuroraPlan{}, fmt.Errorf("aurora requires implementation.masterUsername (the DB master user)")
	}
	cp["MasterUsername"] = user
	pass, _ := impl["masterPassword"].(string)
	managed, _ := impl["manageMasterUserPassword"].(bool)
	switch {
	case pass != "" && managed:
		return AuroraPlan{}, fmt.Errorf(
			"aurora: set exactly one of implementation.masterPassword or " +
				"implementation.manageMasterUserPassword=true, not both")
	case managed:
		cp["ManageMasterUserPassword"] = "true"
	case pass != "":
		cp["MasterUserPassword"] = pass
	default:
		return AuroraPlan{}, fmt.Errorf(
			"aurora requires a master credential: implementation.masterPassword " +
				"(an explicit password) or implementation.manageMasterUserPassword=true " +
				"(AWS Secrets Manager manages it — no plaintext in the candidate)")
	}

	minStr, minACU, err := acuOperand(impl, "serverlessMinACU", true) // 0 = auto-pause
	if err != nil {
		return AuroraPlan{}, err
	}
	maxStr, maxACU, err := acuOperand(impl, "serverlessMaxACU", false)
	if err != nil {
		return AuroraPlan{}, err
	}
	if maxACU < minACU {
		return AuroraPlan{}, fmt.Errorf(
			"serverlessMaxACU (%s) must be >= serverlessMinACU (%s)", maxStr, minStr)
	}
	cp["ServerlessV2ScalingConfiguration.MinCapacity"] = minStr
	cp["ServerlessV2ScalingConfiguration.MaxCapacity"] = maxStr
	// Auto-pause (scale to zero): MinCapacity=0 pauses the cluster after a window of
	// inactivity, cutting the Serverless-v2 idle floor to ~0. AWS requires the delay
	// in SecondsUntilAutoPause (300..86400, default 300); it is meaningful ONLY when
	// min is 0, so it is refused otherwise rather than silently ignored.
	if secRaw, has := impl["serverlessSecondsUntilAutoPause"]; has {
		if minACU != 0 {
			return AuroraPlan{}, fmt.Errorf(
				"implementation.serverlessSecondsUntilAutoPause is only valid with serverlessMinACU=0 (auto-pause)")
		}
		sec, ok := intOperand(secRaw)
		if !ok {
			return AuroraPlan{}, fmt.Errorf(
				"implementation.serverlessSecondsUntilAutoPause must be a whole number of seconds")
		}
		if sec < 300 || sec > 86400 {
			return AuroraPlan{}, fmt.Errorf(
				"implementation.serverlessSecondsUntilAutoPause must be 300..86400, got %d", sec)
		}
		cp["ServerlessV2ScalingConfiguration.SecondsUntilAutoPause"] = strconv.Itoa(sec)
	} else if minACU == 0 {
		// auto-pause with the AWS default delay (300s), made explicit on the wire.
		cp["ServerlessV2ScalingConfiguration.SecondsUntilAutoPause"] = "300"
	}

	if raw, has := impl["vpcSecurityGroupIds"]; has {
		list, err := stringList(raw)
		if err != nil {
			return AuroraPlan{}, err
		}
		for i, sg := range list {
			// D884: the member name IS VpcSecurityGroupId — a trailing `.member.N` after it
			// is a SECOND list level the query protocol never expects, and CreateDBCluster
			// 400s "MalformedInput: Start of list found where not expected". botocore
			// serializes it as VpcSecurityGroupIds.VpcSecurityGroupId.N; match that exactly.
			cp[fmt.Sprintf("VpcSecurityGroupIds.VpcSecurityGroupId.%d", i+1)] = sg
		}
	}

	// deletion protection defaults ON (D47 posture); a reviewed opt-out is explicit.
	if dp, has := impl["deletion_protection"]; has {
		b, ok := dp.(bool)
		if !ok {
			return AuroraPlan{}, fmt.Errorf("deletion_protection must be a boolean")
		}
		cp["DeletionProtection"] = boolStr(b)
	} else {
		cp["DeletionProtection"] = "true"
	}

	// ---- capability attributes ----
	wantTLS := false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "engine.protocol":
			proto, _ := raw.(string)
			eng, ver, e := auroraEngineFromProtocol(proto)
			if e != nil {
				return AuroraPlan{}, e
			}
			p.Engine = eng
			cp["Engine"] = eng
			if ver != "" {
				cp["EngineVersion"] = ver
				p.EngineVersion = ver
			}
		case "location.region":
			// the region is the endpoint (driver-level), not a create param
		case "network.publicExposure":
			// public exposure is a MEMBER (instance) property on Aurora, not a
			// cluster one — carry it onto the CreateDBInstance calls.
			p.publicSet = true
			p.publiclyAccessible = raw == true
		case "encryption.atRest":
			if raw != true {
				return AuroraPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored (Aurora storage encryption is set at cluster creation)")
			}
			key, _ := impl["kmsKeyArn"].(string)
			if key == "" {
				return AuroraPlan{}, fmt.Errorf(
					"encryption.atRest requires implementation.kmsKeyArn (a customer KMS key)")
			}
			cp["StorageEncrypted"] = "true"
			cp["KmsKeyId"] = key
		case "encryption.customerManagedKeys":
			// the kmsKeyArn operand encryption.atRest already requires IS a customer
			// key; a true here is satisfied by that same key on the same call.
			if raw == true {
				key, _ := impl["kmsKeyArn"].(string)
				if key == "" {
					return AuroraPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kmsKeyArn (a customer KMS key)")
				}
				cp["StorageEncrypted"] = "true"
				cp["KmsKeyId"] = key
			}
		case "availability.class":
			switch raw {
			case "regional":
				p.Regional = true // writer + reader in 2 AZ
			case "zonal":
				p.Regional = false // single writer
			case "multi-regional":
				return AuroraPlan{}, fmt.Errorf(
					"availability.class multi-regional has no single-cluster Aurora mapping (a global database is a second binding)")
			default:
				return AuroraPlan{}, fmt.Errorf("availability.class %v has no Aurora mapping", raw)
			}
		case "recovery.rpo":
			// any finite RPO requires automated backups; default a 7-day window.
			cp["BackupRetentionPeriod"] = "7"
		case "encryption.inTransit":
			// Enforcing TLS on Aurora needs a DB CLUSTER PARAMETER GROUP carrying
			// the engine's TLS parameter. D288: the driver DERIVES and owns that
			// group when the operator does not bring one — the group is the
			// MECHANISM by which a declared attribute is realized, not an
			// independent binding (D278's shape, and D278's aside about this case
			// was wrong; the entry says why). An operator-supplied group still
			// wins. Resolved AFTER this loop: the engine is parsed in the SAME
			// pass and "encryption.inTransit" sorts before "engine.protocol".
			if raw == true {
				wantTLS = true
			}
		case "service.managed":
			if raw != true {
				return AuroraPlan{}, fmt.Errorf("service.managed=false cannot be honored by Aurora")
			}
		default:
			return AuroraPlan{}, fmt.Errorf(
				"attribute %s has no Aurora mapping — refusing rather than silently dropping it", path)
		}
	}
	if cp["Engine"] == "" {
		return AuroraPlan{}, fmt.Errorf("aurora requires engine.protocol")
	}

	// D288: resolve encryption.inTransit now that the engine is known. An
	// operator-supplied group WINS (they may carry other parameters we must not
	// second-guess); both sources set is refused, one source of truth. Otherwise
	// derive a group carrying EXACTLY the engine's TLS parameter — the mechanism
	// that realizes the declared attribute, owned and cleaned up like the D278
	// subnet group. What the driver will not do is guess: an engine whose TLS
	// parameter or family it cannot name refuses, because a group that enforces
	// nothing while the contract claims TLS is worse than a refusal.
	if pg, _ := impl["clusterParameterGroupName"].(string); pg != "" {
		// An operator group may carry parameters beyond TLS; the driver attaches
		// it verbatim and never edits it. observe still reads the LIVE parameter,
		// so a group that does not actually enforce TLS is caught as violated.
		cp["DBClusterParameterGroupName"] = pg
	} else if wantTLS {
		name, value, ok := auroraTLSParam(cp["Engine"])
		if !ok {
			return AuroraPlan{}, fmt.Errorf(
				"encryption.inTransit=true cannot be honored on engine %q: this driver "+
					"does not know which parameter enforces TLS there — supply "+
					"implementation.clusterParameterGroupName (a group that enforces it) "+
					"rather than have the driver create one that enforces nothing", cp["Engine"])
		}
		family, err := auroraParamFamily(cp["Engine"], cp["EngineVersion"])
		if err != nil {
			return AuroraPlan{}, fmt.Errorf(
				"encryption.inTransit=true: %v — pin the version in engine.protocol or "+
					"supply implementation.clusterParameterGroupName", err)
		}
		p.DeriveParamGroup = derivedParamGroupName(environment, capability)
		p.ParamFamily = family
		p.TLSParamName, p.TLSParamValue = name, value
		cp["DBClusterParameterGroupName"] = p.DeriveParamGroup
	}

	p.clusterParams = cp
	p.WriterID = auroraInstanceID(clusterID, "writer")
	if p.Regional {
		p.ReaderID = auroraInstanceID(clusterID, "reader")
	}
	return p, nil
}

// createClusterBody renders the CreateDBCluster query body.
func (p AuroraPlan) createClusterBody() string {
	return encodeForm(p.clusterParams)
}

// instanceBody renders a CreateDBInstance query body for one member. Every Aurora
// Serverless v2 member is DBInstanceClass=db.serverless, attached to the cluster;
// credentials and storage live on the CLUSTER, not the instance.
func (p AuroraPlan) instanceBody(instanceID string) string {
	params := map[string]string{
		"Action":               "CreateDBInstance",
		"Version":              rdsVersion,
		"DBInstanceIdentifier": instanceID,
		"DBInstanceClass":      "db.serverless",
		"Engine":               p.Engine,
		"DBClusterIdentifier":  p.ClusterID,
	}
	if p.publicSet {
		params["PubliclyAccessible"] = boolStr(p.publiclyAccessible)
	}
	return encodeForm(params)
}
