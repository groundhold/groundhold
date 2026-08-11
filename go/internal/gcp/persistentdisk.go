// Persistent Disk request building (D368): the semantic core of the GCP
// capability.storage.block driver — the SAME vocabulary AWS EBS fulfils.
//
// The capability/operand split is identical to the EBS twin, because it is a
// property of the VOCABULARY rather than of a cloud: the contract governs
// residency, zone survivability, encryption and key ownership; the size, the
// disk type, the zone and the snapshot to restore from are operator operands
// (D26).
//
// Where GCP genuinely DIFFERS from AWS, it differs here and is stated:
//
//   - `availability.class` is REAL on this cloud. A regional persistent disk is
//     synchronously replicated across two zones and survives losing one of them.
//     The EBS twin refuses `regional` because AWS does not sell it; this driver
//     honors it, and honoring it means a DIFFERENT API surface — regionDisks
//     rather than disks, scoped to `regions/<r>` rather than `zones/<z>`, with
//     `replicaZones` naming the two zones. This is the attribute earning its
//     place in the vocabulary: not a formality, a genuinely different resource
//     with a genuinely different durability guarantee, expressed the same way on
//     both clouds and verified the same way.
//   - Disks are ALWAYS encrypted at rest. Google encrypts every persistent disk
//     with no way to turn it off, so `encryption.atRest: false` is refused as
//     unhonorable rather than accepted and quietly ignored. The EBS twin honors
//     both values because EBS genuinely can be unencrypted.
//   - The name is the idempotency mechanism (D43): disks.insert takes no
//     idempotency key, so a deterministic name is what makes a lost create
//     recoverable instead of duplicated. EBS uses a ClientToken for the same job.
//
// The residency check the EBS twin needs (zone inside region) applies here in
// both shapes: a zonal disk's zone must sit inside `location.region`, and a
// regional disk's replica zones must BOTH sit inside it. Without it the create
// succeeds in the wrong jurisdiction with the contract reporting satisfied.
package gcp

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// pdTypeOK bounds a disk type token (pd-ssd, pd-balanced, hyperdisk-balanced).
	pdTypeOK = regexp.MustCompile(`^[a-z][a-z0-9-]{1,40}$`)
	// pdSnapshotOK bounds a source-snapshot reference: a full URL, a qualified
	// path, or a bare name in this project.
	pdSnapshotOK = regexp.MustCompile(`^(https://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+|projects/[a-z0-9-]+/global/snapshots/[a-z0-9-]+|global/snapshots/[a-z0-9-]+|[a-z][a-z0-9-]{0,61}[a-z0-9])$`)
	// pdRegionOK bounds a region name (no trailing zone letter).
	pdRegionOK = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]$`)
)

// PDPlan is the attribute-derived shape a create assembles.
type PDPlan struct {
	Name string // deterministic: the idempotency mechanism
	// Regional selects the API surface: regionDisks scoped to regions/<r> when
	// true, disks scoped to zones/<z> when false. This is a durability decision
	// the CONTRACT makes, not an operand.
	Regional       bool
	Zone           string   // zonal only — the operand that places the disk
	Region         string   // both — the scope for regional, derived for zonal
	ReplicaZones   []string // regional only — exactly two, both inside Region
	SizeGB         int      // operand; 0 only when restoring from a snapshot
	DiskType       string   // operand; "" leaves the service default
	SourceSnapshot string   // operand; "" = an empty disk
	KmsKeyName     string   // CMEK; "" = Google-managed platform encryption
}

// BuildPDCreate maps capability.storage.block attributes + impl to a disks.insert
// (or regionDisks.insert) plan. Every error is a preflight refusal, never a
// silent drop.
func BuildPDCreate(project, environment, capability string,
	attrs, impl map[string]any, generation int) (PDPlan, error) {

	if !projectOK.MatchString(project) {
		return PDPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	p := PDPlan{
		// disks.insert has no idempotency-key parameter: the deterministic NAME is
		// the mechanism (D43). Disk names allow 63 characters.
		Name: resourceName(project, environment, capability, generation, 63),
	}
	region := ""

	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			region, _ = raw.(string)
		case "availability.class":
			switch raw {
			case "zonal":
				p.Regional = false
			case "regional":
				p.Regional = true
			default:
				return PDPlan{}, fmt.Errorf(
					"availability.class %v has no persistent-disk mapping (zonal or regional)", raw)
			}
		case "encryption.atRest":
			b, ok := raw.(bool)
			if !ok {
				return PDPlan{}, fmt.Errorf("encryption.atRest must be a bool, got %T", raw)
			}
			if !b {
				// Refused rather than accepted-and-ignored: a contract that asks for an
				// unencrypted disk and gets an encrypted one was not honored, it was
				// overruled, and reporting satisfied would hide that.
				return PDPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored — Compute Engine encrypts " +
						"every persistent disk and offers no way to disable it (refusing rather " +
						"than accepting a value the platform will ignore)")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.KmsKeyName = strings.TrimSpace(implStr(impl, "kms_key_name"))
				if p.KmsKeyName == "" {
					return PDPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_name " +
							"(Google's default platform key is not customer-managed — the customer " +
							"cannot revoke it)")
				}
			}
		case "service.managed":
			if raw != true {
				return PDPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored — a disk groundhold does not " +
						"own is an adoption, not a create")
			}
		default:
			return PDPlan{}, fmt.Errorf(
				"attribute %s has no persistent-disk mapping — refusing rather than silently "+
					"dropping it (size, disk type and the zone are operands, not capability "+
					"semantics)", path)
		}
	}
	// --- OPERATOR operands (implementation block, D26) ---
	if p.Regional {
		zones, err := pdReplicaZones(impl)
		if err != nil {
			return PDPlan{}, err
		}
		p.ReplicaZones = zones
		p.Region = gceRegionOfZone(zones[0])
		if gceRegionOfZone(zones[1]) != p.Region {
			return PDPlan{}, fmt.Errorf(
				"implementation.replica_zones %v span two different regions (%s and %s) — "+
					"a regional disk is replicated across zones of ONE region",
				zones, p.Region, gceRegionOfZone(zones[1]))
		}
	} else {
		p.Zone = strings.TrimSpace(implStr(impl, "zone"))
		if p.Zone == "" {
			return PDPlan{}, fmt.Errorf(
				"implementation.zone is required — a zonal persistent disk is created in one " +
					"zone and the driver does not pick it (a guessed zone puts the data where " +
					"the machines that need it are not)")
		}
		if !gceZoneOK.MatchString(p.Zone) {
			return PDPlan{}, fmt.Errorf("implementation.zone %q is not a valid zone", p.Zone)
		}
		p.Region = gceRegionOfZone(p.Zone)
	}
	// The region is the residency surface the CONTRACT governs; the zones are
	// operands. Without this check the two can disagree and the create succeeds —
	// in the wrong jurisdiction, with the contract reporting satisfied.
	if region != "" && region != p.Region {
		where := "implementation.zone " + p.Zone
		if p.Regional {
			where = fmt.Sprintf("implementation.replica_zones %v", p.ReplicaZones)
		}
		return PDPlan{}, fmt.Errorf(
			"location.region %q contradicts %s (region %q) — refusing rather than storing "+
				"the data somewhere the contract did not ask for", region, where, p.Region)
	}

	if snap := strings.TrimSpace(implStr(impl, "source_snapshot")); snap != "" {
		if !pdSnapshotOK.MatchString(snap) {
			return PDPlan{}, fmt.Errorf(
				"implementation.source_snapshot %q is not a snapshot reference", snap)
		}
		p.SourceSnapshot = snap
	}
	if v, ok := impl["size_gb"]; ok {
		n, ok := gceIntOperand(v)
		if !ok || n <= 0 {
			return PDPlan{}, fmt.Errorf(
				"implementation.size_gb must be a positive whole number of GiB, got %v", v)
		}
		p.SizeGB = n
	} else if p.SourceSnapshot == "" {
		// A snapshot carries its own size, so it is the one case where the driver
		// legitimately has an answer it did not invent. Otherwise there is none.
		return PDPlan{}, fmt.Errorf(
			"implementation.size_gb is required — the driver does not choose a capacity " +
				"(supply a size, or implementation.source_snapshot to restore one that already has it)")
	}
	if dt := strings.TrimSpace(implStr(impl, "disk_type")); dt != "" {
		if !pdTypeOK.MatchString(dt) {
			return PDPlan{}, fmt.Errorf("implementation.disk_type %q is not a disk type", dt)
		}
		p.DiskType = dt
	}
	return p, nil
}

// pdReplicaZones reads the two zones a regional disk replicates across. Exactly
// two, because that is what the API accepts — and asking for a third silently
// dropped would misreport how many failures the disk survives.
func pdReplicaZones(impl map[string]any) ([]string, error) {
	raw, ok := impl["replica_zones"]
	if !ok {
		return nil, fmt.Errorf(
			"availability.class=regional requires implementation.replica_zones — a regional " +
				"disk is replicated across two named zones, and the driver does not choose them")
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("implementation.replica_zones must be a list, got %T", raw)
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("implementation.replica_zones must contain strings, got %T", e)
		}
		s = strings.TrimSpace(s)
		if !gceZoneOK.MatchString(s) {
			return nil, fmt.Errorf("implementation.replica_zones contains %q, which is not a zone", s)
		}
		out = append(out, s)
	}
	if len(out) != 2 {
		return nil, fmt.Errorf(
			"implementation.replica_zones must name exactly two zones, got %d — a regional "+
				"persistent disk replicates across two", len(out))
	}
	if out[0] == out[1] {
		return nil, fmt.Errorf(
			"implementation.replica_zones names %q twice — two copies in one zone survive "+
				"nothing a single copy does not", out[0])
	}
	return out, nil
}

// createBody is the disks.insert / regionDisks.insert body. Ownership is labels,
// so the 409 continuation can tell our disk from a stranger's.
func (p PDPlan) createBody(capability, environment string) map[string]any {
	body := map[string]any{
		"name": p.Name,
		"labels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
	}
	if p.SizeGB > 0 {
		body["sizeGb"] = fmt.Sprintf("%d", p.SizeGB)
	}
	if p.DiskType != "" {
		// The type is scope-qualified: a regional disk's type lives under the
		// region, a zonal disk's under the zone.
		if p.Regional {
			body["type"] = fmt.Sprintf("regions/%s/diskTypes/%s", p.Region, p.DiskType)
		} else {
			body["type"] = fmt.Sprintf("zones/%s/diskTypes/%s", p.Zone, p.DiskType)
		}
	}
	if p.SourceSnapshot != "" {
		body["sourceSnapshot"] = p.SourceSnapshot
	}
	if p.KmsKeyName != "" {
		body["diskEncryptionKey"] = map[string]any{"kmsKeyName": p.KmsKeyName}
	}
	if p.Regional {
		zones := make([]any, 0, len(p.ReplicaZones))
		for _, z := range p.ReplicaZones {
			zones = append(zones, fmt.Sprintf("zones/%s", z))
		}
		body["replicaZones"] = zones
	}
	return body
}

// classifyPDChange (D46): PURE — can a capability.storage.block transition be
// honored in place?
//
// disks.resize exists, but size is an OPERAND here. Every attribute this
// vocabulary governs is fixed when the disk is created — including
// availability.class, which is not a setting but a choice of which resource type
// to create. Because the type is stateful (D47), each of these becoming a
// replacement means it needs explicit consent rather than happening quietly,
// which is right: converting a zonal disk to a regional one means copying the
// data to a new disk.
func classifyPDChange(path string) (string, string) {
	switch path {
	case "location.region":
		return "immutable", "a disk is created in one region and cannot move — a region change is a new disk, and the data must be copied to it"
	case "availability.class":
		return "immutable", "zonal and regional disks are different resources (disks vs regionDisks), not two settings of one — changing the class means creating a new disk and copying the data"
	case "encryption.atRest":
		// D823: the twin of the Azure disk case. "Immutable" here destroys the disk to reach
		// a state the new disk will also have.
		return "unsupported", "Compute Engine encrypts every persistent disk and the setting " +
			"cannot be changed — nothing to patch (=false cannot be honored)"
	case "encryption.customerManagedKeys":
		return "immutable", "the key encrypting a disk is fixed when the disk is created — re-keying is a new disk"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	}
	return "", ""
}
