// Compute Engine instance request building (D359): the semantic core of the GCP
// capability.compute.instance driver — the SAME vocabulary AWS EC2 fulfils.
//
// The capability/operand split is identical to the EC2 twin, because it is a
// property of the VOCABULARY rather than of a cloud: the contract governs
// residency, public exposure and disk encryption; the machine type, the image,
// the zone and the subnetwork are operator operands (D26). The driver invents
// none of them.
//
// Where GCP genuinely DIFFERS from AWS, it differs here and is stated:
//
//   - Disks are ALWAYS encrypted at rest. Google encrypts every persistent disk
//     with no way to turn it off, so `encryption.atRest: false` is refused as
//     unhonorable rather than accepted and quietly ignored. The EC2 twin honors
//     both values because EBS genuinely can be unencrypted.
//   - Public exposure is the PRESENCE of an accessConfig, not a boolean field.
//     A private instance omits the block entirely; there is no "false" to set.
//   - The name is the idempotency mechanism (D43): instances.insert takes no
//     idempotency key, so a deterministic name is what makes a lost create
//     recoverable instead of duplicated. EC2 uses a ClientToken for the same job.
//
// availability.class=regional is refused on both clouds for the same reason: an
// instance is placed in exactly one zone, and regional placement is a property of
// a managed instance GROUP — a different capability.
package gcp

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// gceZoneOK bounds a zone name (region + zone letter).
	gceZoneOK = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]-[a-z]$`)
	// gceMachineTypeOK bounds a machine type (family-cpus, or a custom form).
	gceMachineTypeOK = regexp.MustCompile(`^[a-z0-9]+-[a-z0-9-]+$`)
	// gceImageOK bounds a source image reference: a full URL, a specific image
	// projects/<p>/global/images/<image>, the canonical FAMILY form
	// projects/<p>/global/images/family/<family> (D891 — the old pattern put `/family/`
	// AFTER the image name, which is not how GCP writes a family ref, so the standard
	// projects/debian-cloud/global/images/family/debian-12 was rejected), or the
	// project-relative short family form global/images/family/<family>.
	gceImageOK = regexp.MustCompile(`^(https://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+|projects/[a-z0-9-]+/global/images/(family/)?[A-Za-z0-9-]+|global/images/family/[A-Za-z0-9-]+)$`)
	// gceSubnetOK bounds a subnetwork reference.
	gceSubnetOK = regexp.MustCompile(`^(https://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+|projects/[a-z0-9-]+/regions/[a-z0-9-]+/subnetworks/[a-z0-9-]+|regions/[a-z0-9-]+/subnetworks/[a-z0-9-]+)$`)
)

// GCEInstancePlan is the attribute-derived shape a create assembles.
type GCEInstancePlan struct {
	Name        string // deterministic: the idempotency mechanism
	Zone        string // operand — fixes the region and the availability zone
	MachineType string // operand — no default, ever
	SourceImage string // operand — no default, ever
	Subnetwork  string // optional operand
	PublicIP    bool   // network.publicExposure
	KmsKeyName  string // CMEK; "" = Google-managed key (still encrypted)
	DiskSizeGB  int    // optional; 0 = the image's default
	Region      string // derived from the zone, for the residency check
}

// implStr reads a string operand, tolerating its absence. The GCP package reads
// operands inline elsewhere; one named helper keeps this driver's many operands
// readable without changing that convention for anyone else.
func implStr(impl map[string]any, key string) string {
	s, _ := impl[key].(string)
	return s
}

// gceIntOperand accepts the whole-number shapes YAML produces, and refuses a
// float that is not whole rather than truncating it into a plausible lie.
func gceIntOperand(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		if n != float64(int(n)) {
			return 0, false
		}
		return int(n), true
	}
	return 0, false
}

// gceRegionOfZone strips the trailing zone letter: europe-west1-b -> europe-west1.
func gceRegionOfZone(zone string) string {
	i := strings.LastIndex(zone, "-")
	if i < 0 {
		return zone
	}
	return zone[:i]
}

// BuildGCEInstanceCreate maps capability.compute.instance attributes + impl to an
// instances.insert plan. Every error is a preflight refusal, never a silent drop.
func BuildGCEInstanceCreate(project, environment, capability string,
	attrs, impl map[string]any, generation int) (GCEInstancePlan, error) {

	if !projectOK.MatchString(project) {
		return GCEInstancePlan{}, fmt.Errorf("project %q is invalid", project)
	}
	p := GCEInstancePlan{
		// instances.insert has no idempotency-key parameter: the deterministic
		// NAME is the mechanism (D43). Instance names allow 63 characters.
		Name: resourceName(project, environment, capability, generation, 63),
	}

	// The zone is read first: the region attribute is checked AGAINST it, so a
	// contract that says eu and an operand that says us must not both "pass".
	p.Zone = strings.TrimSpace(implStr(impl, "zone"))
	if p.Zone == "" {
		return GCEInstancePlan{}, fmt.Errorf(
			"implementation.zone is required — a Compute Engine instance is zonal, and " +
				"the zone fixes both the region and the availability zone")
	}
	if !gceZoneOK.MatchString(p.Zone) {
		return GCEInstancePlan{}, fmt.Errorf("implementation.zone %q is not a valid zone", p.Zone)
	}
	p.Region = gceRegionOfZone(p.Zone)

	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			want, _ := raw.(string)
			if want != "" && want != p.Region {
				// Refusing beats provisioning in the operand's region and reporting
				// the contract's: that would make a residency verdict a lie.
				return GCEInstancePlan{}, fmt.Errorf(
					"location.region %q contradicts implementation.zone %q (region %q) — "+
						"refusing rather than provisioning somewhere the contract did not ask for",
					want, p.Zone, p.Region)
			}
		case "availability.class":
			switch raw {
			case "zonal":
				// the zone fixes placement; nothing else to place.
			case "regional":
				return GCEInstancePlan{}, fmt.Errorf(
					"availability.class=regional cannot be honored by a single Compute Engine " +
						"instance (an instance lives in exactly one zone — regional placement is a " +
						"property of a managed instance group, a different capability)")
			default:
				return GCEInstancePlan{}, fmt.Errorf(
					"availability.class %v has no Compute Engine mapping (zonal only for an instance)", raw)
			}
		case "network.publicExposure":
			b, ok := raw.(bool)
			if !ok {
				return GCEInstancePlan{}, fmt.Errorf("network.publicExposure must be a bool, got %T", raw)
			}
			p.PublicIP = b
		case "encryption.atRest":
			if raw != true {
				return GCEInstancePlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored by Compute Engine — Google encrypts " +
						"every persistent disk at rest and offers no way to disable it, so accepting " +
						"false would report a state the platform cannot produce")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.KmsKeyName = strings.TrimSpace(implStr(impl, "kms_key_name"))
				if p.KmsKeyName == "" {
					return GCEInstancePlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_name " +
							"(Google's default disk encryption is platform-managed, not customer-managed)")
				}
			}
		case "service.managed":
			if raw != true {
				return GCEInstancePlan{}, fmt.Errorf(
					"service.managed=false cannot be honored — an instance groundhold does not " +
						"own is an adoption, not a create")
			}
		default:
			return GCEInstancePlan{}, fmt.Errorf(
				"attribute %s has no Compute Engine mapping — refusing rather than silently "+
					"dropping it (machine type, image, zone and subnetwork are operands, not "+
					"capability semantics)", path)
		}
	}
	// --- OPERATOR operands (implementation block, D26) ---
	p.MachineType = strings.TrimSpace(implStr(impl, "machine_type"))
	if p.MachineType == "" {
		return GCEInstancePlan{}, fmt.Errorf(
			"implementation.machine_type is required — the driver does not choose a size " +
				"(a guessed machine type provisions capacity nobody asked for, and bills for it)")
	}
	if !gceMachineTypeOK.MatchString(p.MachineType) {
		return GCEInstancePlan{}, fmt.Errorf(
			"implementation.machine_type %q is not a valid machine type", p.MachineType)
	}
	p.SourceImage = strings.TrimSpace(implStr(impl, "source_image"))
	if p.SourceImage == "" {
		return GCEInstancePlan{}, fmt.Errorf(
			"implementation.source_image is required — the driver does not choose an image " +
				"(what runs on the machine is the operator's decision, never a default)")
	}
	if !gceImageOK.MatchString(p.SourceImage) {
		return GCEInstancePlan{}, fmt.Errorf(
			"implementation.source_image %q is not a valid image reference", p.SourceImage)
	}
	if sn := strings.TrimSpace(implStr(impl, "subnetwork")); sn != "" {
		if !gceSubnetOK.MatchString(sn) {
			return GCEInstancePlan{}, fmt.Errorf(
				"implementation.subnetwork %q is not a valid subnetwork reference", sn)
		}
		p.Subnetwork = sn
	}
	if v, ok := impl["disk_size_gb"]; ok {
		n, ok := gceIntOperand(v)
		if !ok || n <= 0 {
			return GCEInstancePlan{}, fmt.Errorf(
				"implementation.disk_size_gb must be a positive whole number of GB, got %v", v)
		}
		p.DiskSizeGB = n
	}
	return p, nil
}

// createBody is the instances.insert body. Ownership is labels.
func (p GCEInstancePlan) createBody(capability, environment string) map[string]any {
	boot := map[string]any{
		"boot":       true,
		"autoDelete": true,
		"initializeParams": map[string]any{
			"sourceImage": p.SourceImage,
		},
	}
	if p.DiskSizeGB > 0 {
		boot["initializeParams"].(map[string]any)["diskSizeGb"] = fmt.Sprintf("%d", p.DiskSizeGB)
	}
	if p.KmsKeyName != "" {
		boot["diskEncryptionKey"] = map[string]any{"kmsKeyName": p.KmsKeyName}
	}
	nic := map[string]any{}
	if p.Subnetwork != "" {
		nic["subnetwork"] = p.Subnetwork
	}
	// Public exposure is the PRESENCE of an accessConfig — a private instance has
	// no block at all, rather than a block set to false.
	if p.PublicIP {
		nic["accessConfigs"] = []any{
			map[string]any{"type": "ONE_TO_ONE_NAT", "name": "External NAT"},
		}
	}
	return map[string]any{
		"name":              p.Name,
		"machineType":       "zones/" + p.Zone + "/machineTypes/" + p.MachineType,
		"disks":             []any{boot},
		"networkInterfaces": []any{nic},
		"labels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
	}
}

// classifyGCEInstanceChange (D46): PURE — identical verdicts to the EC2 twin,
// because the reason is the same on both clouds: a machine's region, placement,
// public-address association and disk encryption are all fixed when it is
// created. Each change is a new machine, which means replacement — and the type
// is stateful (D357), so that replacement needs explicit consent.
func classifyGCEInstanceChange(path string) (string, string) {
	switch path {
	case "location.region":
		return "immutable", "an instance is created in one zone and cannot move — a region change is a new machine"
	case "availability.class":
		return "immutable", "placement is fixed by the zone the instance was created in — a change is a new machine"
	case "network.publicExposure":
		// D821: this said "a change is a new machine, not a toggle". Compute Engine has
		// three toggles: instances.addAccessConfig, deleteAccessConfig and
		// updateAccessConfig, all on an existing instance's network interface. Destroying a
		// machine to add or remove an external address loses local SSD data and the uptime,
		// for a change Google makes in one call.
		return "unsupported", "in-place exposure change is not wired for Compute Engine in " +
			"this slice — GCE does support it (instances.addAccessConfig / deleteAccessConfig " +
			"/ updateAccessConfig on the running interface), so this is a gap in groundhold, " +
			"not a property of the instance: do it directly rather than replace the machine"
	case "encryption.atRest":
		return "unsupported", "Compute Engine encrypts every persistent disk at rest and offers no way to disable it — there is nothing to patch"
	case "encryption.customerManagedKeys":
		// D829: the twin of the EC2 case, and the same false inference. A persistent disk's
		// key is fixed at creation, so re-keying is a new DISK — and Compute Engine has
		// instances.detachDisk and instances.attachDisk, so the machine keeps its id and
		// its addresses while the disk is swapped under it.
		return "unsupported", "in-place re-keying is not wired for Compute Engine in this " +
			"slice — the DISK must be recreated (a snapshot restored under the new key), but " +
			"the INSTANCE does not: instances.detachDisk and attachDisk swap it underneath a " +
			"machine that keeps its id, so this is a gap in groundhold rather than a reason " +
			"to replace the machine"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	}
	return "", ""
}
