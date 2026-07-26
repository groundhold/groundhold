// EBS volume request building (D367): the semantic core of the AWS
// capability.storage.block driver — the SAME vocabulary a GCP persistent disk and
// an Azure managed disk fulfil.
//
// A volume IS the data (D361), which is why it is a capability of its own rather
// than an operand of the machine that mounts it: an operand cannot be gated, and
// the whole point of the separation is that retiring this resource destroys
// something. The type is stateful, so the delete_stateful autonomy gate binds it
// and a replacement needs explicit allow_replace_stateful consent.
//
// What the CONTRACT governs: where the bytes sit, whether they survive losing a
// zone, whether they are encrypted, and whether the key is one the customer can
// revoke. What the OPERATOR supplies (D26): size, volume type, IOPS, throughput,
// the snapshot to restore from, the zone. Every one of the latter is sizing or
// placement — implementation noise, however strongly anyone feels about IOPS.
//
// Two refusals are the interesting part, and both exist because the alternative is
// provisioning something nobody asked for:
//
//   - availability.class=regional is REFUSED. An EBS volume lives in exactly one
//     availability zone — there is no regional EBS. A contract that needs a volume
//     to survive a zone failure is asking for something AWS does not sell under
//     this service, and downgrading it silently to zonal would certify a
//     durability guarantee that does not exist. (GCP genuinely has regional
//     persistent disks, so the same attribute is honorable there — the vocabulary
//     is right to carry it, and this driver is right to say no.)
//
//   - the availability zone must lie INSIDE location.region. The region is the
//     residency surface the contract governs; the zone is an operand. Nothing
//     otherwise stops `location.region: eu-central-1` from being implemented in
//     `us-east-1a`, and the create would succeed — in the wrong jurisdiction, with
//     the contract reporting satisfied. This is the same class of check as the GCE
//     zone/region rule (D359).
package aws

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// ebsVolAZOK bounds an availability zone (region + a zone letter).
	ebsVolAZOK = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[0-9]+[a-z]$`)
	// ebsVolTypeOK bounds a volume-type token (gp3, io2, st1, sc1, standard...).
	ebsVolTypeOK = regexp.MustCompile(`^[a-z]{1,3}[0-9]?$`)
	// ebsVolSnapshotOK bounds a snapshot id.
	ebsVolSnapshotOK = regexp.MustCompile(`^snap-[0-9a-f]{8,17}$`)
)

// EBSVolumePlan is the attribute-derived shape a create assembles into the
// CreateVolume Query body.
type EBSVolumePlan struct {
	ClientToken      string // deterministic idempotency key
	AvailabilityZone string // operand — no default; must sit inside location.region
	SizeGB           int    // operand; 0 only when restoring from a snapshot
	VolumeType       string // operand; "" leaves the account/service default
	IOPS             int    // operand; 0 = not requested
	ThroughputMBps   int    // operand; 0 = not requested
	SnapshotID       string // operand; "" = an empty volume
	Encrypted        bool   // encryption.atRest
	KmsKeyID         string // CMEK; "" = the account's default EBS key
	Tags             map[string]string
}

// BuildEBSVolumeCreate maps capability.storage.block attributes + impl to a
// CreateVolume plan. Every error is a preflight refusal, never a silent drop.
func BuildEBSVolumeCreate(environment, capability string,
	attrs, impl map[string]any, generation int) (EBSVolumePlan, error) {

	p := EBSVolumePlan{
		ClientToken: "groundhold-" + letterHash(environment+"|"+capability+genSuffix(generation), 24),
		Encrypted:   true, // encrypted unless the contract explicitly says otherwise
		Tags: map[string]string{
			"groundhold-capability":  sanitizeTag(capability),
			"groundhold-environment": sanitizeTag(environment),
		},
	}
	cmk := false
	region := ""

	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			region, _ = raw.(string)
		case "availability.class":
			switch raw {
			case "zonal":
				// the operand zone places it; nothing goes in the body.
			case "regional":
				return EBSVolumePlan{}, fmt.Errorf(
					"availability.class=regional cannot be honored by an EBS volume " +
						"(an EBS volume lives in exactly one availability zone — there is no " +
						"regional EBS, and reporting zonal as regional would certify a " +
						"durability guarantee that does not exist)")
			default:
				return EBSVolumePlan{}, fmt.Errorf(
					"availability.class %v has no EBS mapping (zonal only)", raw)
			}
		case "encryption.atRest":
			b, ok := raw.(bool)
			if !ok {
				return EBSVolumePlan{}, fmt.Errorf("encryption.atRest must be a bool, got %T", raw)
			}
			p.Encrypted = b
		case "encryption.customerManagedKeys":
			if raw == true {
				cmk = true
				p.KmsKeyID = strings.TrimSpace(implString(impl, "kms_key_id"))
				if p.KmsKeyID == "" {
					return EBSVolumePlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_id " +
							"(the account's default EBS key is AWS-managed, not customer-managed)")
				}
			}
		case "service.managed":
			if raw != true {
				return EBSVolumePlan{}, fmt.Errorf(
					"service.managed=false cannot be honored — a volume groundhold does not " +
						"own is an adoption, not a create")
			}
		default:
			return EBSVolumePlan{}, fmt.Errorf(
				"attribute %s has no EBS mapping — refusing rather than silently dropping it "+
					"(size, volume type, IOPS, throughput and the zone are operands, not "+
					"capability semantics)", path)
		}
	}

	// A customer-managed key on an unencrypted volume is a contradiction, and
	// honoring either half silently would misreport the other.
	if cmk && !p.Encrypted {
		return EBSVolumePlan{}, fmt.Errorf(
			"encryption.customerManagedKeys=true with encryption.atRest=false is contradictory " +
				"— a key cannot encrypt a volume that is not encrypted")
	}

	// --- OPERATOR operands (implementation block, D26) ---
	p.AvailabilityZone = strings.TrimSpace(implString(impl, "availability_zone"))
	if p.AvailabilityZone == "" {
		return EBSVolumePlan{}, fmt.Errorf(
			"implementation.availability_zone is required — an EBS volume is created in one " +
				"zone and the driver does not pick it (a guessed zone puts the data where the " +
				"machines that need it are not)")
	}
	if !ebsVolAZOK.MatchString(p.AvailabilityZone) {
		return EBSVolumePlan{}, fmt.Errorf(
			"implementation.availability_zone %q is not an availability zone (want <region><letter>, e.g. eu-central-1a)",
			p.AvailabilityZone)
	}
	// The region is the residency surface the CONTRACT governs; the zone is an
	// operand. Without this check the two can disagree and the create succeeds —
	// in the wrong jurisdiction, with the contract reporting satisfied.
	if region != "" && !strings.HasPrefix(p.AvailabilityZone, region) {
		return EBSVolumePlan{}, fmt.Errorf(
			"location.region %q contradicts implementation.availability_zone %q — refusing "+
				"rather than storing the data somewhere the contract did not ask for",
			region, p.AvailabilityZone)
	}
	if sid := strings.TrimSpace(implString(impl, "snapshot_id")); sid != "" {
		if !ebsVolSnapshotOK.MatchString(sid) {
			return EBSVolumePlan{}, fmt.Errorf(
				"implementation.snapshot_id %q is not a snapshot id", sid)
		}
		p.SnapshotID = sid
	}
	if v, ok := impl["size_gb"]; ok {
		n, ok := intOperand(v)
		if !ok || n <= 0 {
			return EBSVolumePlan{}, fmt.Errorf(
				"implementation.size_gb must be a positive whole number of GiB, got %v", v)
		}
		p.SizeGB = n
	} else if p.SnapshotID == "" {
		// A snapshot carries its own size, so it is the one case where the driver
		// legitimately has an answer it did not invent. Otherwise there is none.
		return EBSVolumePlan{}, fmt.Errorf(
			"implementation.size_gb is required — the driver does not choose a capacity " +
				"(supply a size, or implementation.snapshot_id to restore one that already has it)")
	}
	if vt := strings.TrimSpace(implString(impl, "volume_type")); vt != "" {
		if !ebsVolTypeOK.MatchString(vt) {
			return EBSVolumePlan{}, fmt.Errorf(
				"implementation.volume_type %q is not an EBS volume type", vt)
		}
		p.VolumeType = vt
	}
	for _, k := range []string{"iops", "throughput"} {
		v, ok := impl[k]
		if !ok {
			continue
		}
		n, ok := intOperand(v)
		if !ok || n <= 0 {
			return EBSVolumePlan{}, fmt.Errorf(
				"implementation.%s must be a positive whole number, got %v", k, v)
		}
		if k == "iops" {
			p.IOPS = n
		} else {
			p.ThroughputMBps = n
		}
	}
	return p, nil
}

// createBody is the CreateVolume Query body. Ownership is tags, so
// groundholdTagsMatch holds on the volume the response names.
func (p EBSVolumePlan) createBody() string {
	extra := map[string]string{
		"AvailabilityZone": p.AvailabilityZone,
		"ClientToken":      p.ClientToken,
		"Encrypted":        boolParam(p.Encrypted),
	}
	if p.SizeGB > 0 {
		extra["Size"] = fmt.Sprintf("%d", p.SizeGB)
	}
	if p.VolumeType != "" {
		extra["VolumeType"] = p.VolumeType
	}
	if p.IOPS > 0 {
		extra["Iops"] = fmt.Sprintf("%d", p.IOPS)
	}
	if p.ThroughputMBps > 0 {
		extra["Throughput"] = fmt.Sprintf("%d", p.ThroughputMBps)
	}
	if p.SnapshotID != "" {
		extra["SnapshotId"] = p.SnapshotID
	}
	if p.KmsKeyID != "" {
		extra["KmsKeyId"] = p.KmsKeyID
	}
	return encodeForm(ec2ActionParams("CreateVolume", "volume", p.Tags, extra))
}

// classifyEBSVolumeChange (D46): PURE — can a capability.storage.block transition
// be honored in place?
//
// Nothing this vocabulary governs is patchable, and that is the honest answer
// rather than a gap. ModifyVolume exists, but it changes size, type, IOPS and
// throughput — every one of them an OPERAND here, none of them a capability
// attribute. The four attributes the contract does govern are all fixed when the
// volume is created. Because the type is stateful (D47), each of these becoming a
// replacement means it needs explicit consent instead of happening quietly, which
// is exactly right: re-keying a volume means copying the data to a new one.
func classifyEBSVolumeChange(path string) (string, string) {
	switch path {
	case "location.region":
		return "immutable", "a volume is created in one region and cannot move — a region change is a new volume, and the data must be copied to it"
	case "availability.class":
		return "immutable", "an EBS volume is always zonal and its zone is fixed at creation — there is nothing to change in place"
	case "encryption.atRest":
		return "immutable", "EBS encryption is a property of a volume at creation — an existing volume cannot be encrypted in place (the data must be copied through a snapshot)"
	case "encryption.customerManagedKeys":
		return "immutable", "the key encrypting a volume is fixed when the volume is created — re-keying is a new volume"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	}
	return "", ""
}
