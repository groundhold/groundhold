// Azure managed disk request building (D369): the semantic core of the Azure
// capability.storage.block driver — the SAME vocabulary EBS and Persistent Disk
// fulfil, and the third cloud for this capability.
//
// The capability/operand split belongs to the vocabulary and is unchanged: the
// contract governs residency, zone survivability, encryption and key ownership;
// the size, the SKU and the resource group are operator operands (D26).
//
// What is DIFFERENT about Azure, stated rather than smoothed over:
//
//   - `availability.class` lives in the SKU. AWS refuses `regional` (EBS is
//     always zonal); GCP honors it through a different API surface (regionDisks
//     with replicaZones); Azure honors it through a SUFFIX — `Premium_ZRS` is
//     zone-redundant, `Premium_LRS` is not. Three clouds, three mechanisms, one
//     attribute, and a contract that reads the same on all of them.
//   - Managed disks are always encrypted at rest with a platform key, so
//     `encryption.atRest: false` is REFUSED — the same call the Persistent Disk
//     driver makes, and for the same reason. Only EBS honors false.
//   - The SKU is a REQUIRED operand here, where the volume type is optional on
//     EBS. On EBS the type carries nothing the contract governs, so letting the
//     service default it costs nothing. On Azure the SKU decides whether the
//     disk survives losing a zone — a fact the contract DOES govern — and a
//     governed fact must never come from an unstated default.
//
// The resource group is an operand, never something groundhold creates: a
// resource group is an account-shaped container, like a subscription.
package azure

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	// azDiskSKUOK bounds a managed-disk SKU (Premium_LRS, StandardSSD_ZRS, ...).
	azDiskSKUOK = regexp.MustCompile(`^[A-Za-z0-9]+_(LRS|ZRS)$`)
	// azDiskZoneOK bounds a logical availability zone.
	azDiskZoneOK = regexp.MustCompile(`^[1-3]$`)
	// azResourceIDOK bounds an ARM resource id used as a copy source or a
	// disk-encryption set.
	azResourceIDOK = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/[A-Za-z0-9.]+/[A-Za-z0-9/._-]+$`)
)

// AzureDiskPlan is the attribute-derived shape a create assembles.
type AzureDiskPlan struct {
	Name string // deterministic: the idempotency mechanism
	// SKU carries the durability guarantee: a _ZRS suffix is zone-redundant.
	SKU                 string
	Regional            bool   // derived from the SKU, cross-checked against the contract
	Location            string // location.region — an ARM resource carries its own
	SizeGB              int    // operand; 0 only when copying an existing resource
	Zone                string // optional operand; forbidden on a zone-redundant SKU
	SourceResourceID    string // operand; "" = an empty disk
	DiskEncryptionSetID string // CMK; "" = the platform key
}

// azDiskSKUIsZoneRedundant reads the durability guarantee out of the SKU suffix.
func azDiskSKUIsZoneRedundant(sku string) bool {
	return strings.HasSuffix(sku, "_ZRS")
}

// BuildAzureDisk maps capability.storage.block attributes + impl to a
// disks.createOrUpdate plan. Every error is a preflight refusal, never a silent
// drop.
func BuildAzureDisk(environment, capability string,
	attrs, impl map[string]any, generation int) (AzureDiskPlan, error) {

	p := AzureDiskPlan{
		// disks.createOrUpdate is a PUT at a named path: the deterministic NAME is
		// the idempotency mechanism, as it is for every ARM resource.
		Name: azResourceName("pv-disk", environment, capability, generation),
	}
	declaredClass := ""

	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			s, ok := raw.(string)
			if !ok || strings.TrimSpace(s) == "" {
				return AzureDiskPlan{}, fmt.Errorf("location.region must be a non-empty string, got %v", raw)
			}
			p.Location = strings.TrimSpace(s)
		case "availability.class":
			switch raw {
			case "zonal", "regional":
				declaredClass, _ = raw.(string)
			default:
				return AzureDiskPlan{}, fmt.Errorf(
					"availability.class %v has no managed-disk mapping (zonal or regional)", raw)
			}
		case "encryption.atRest":
			b, ok := raw.(bool)
			if !ok {
				return AzureDiskPlan{}, fmt.Errorf("encryption.atRest must be a bool, got %T", raw)
			}
			if !b {
				// Refused rather than accepted-and-ignored: a contract that asks for an
				// unencrypted disk and gets an encrypted one was not honored, it was
				// overruled, and reporting satisfied would hide that.
				return AzureDiskPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored — an Azure managed disk is " +
						"always encrypted at rest with at least a platform key (refusing rather " +
						"than accepting a value the platform will ignore)")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.DiskEncryptionSetID = strings.TrimSpace(implStringAz(impl, "disk_encryption_set_id"))
				if p.DiskEncryptionSetID == "" {
					return AzureDiskPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.disk_encryption_set_id " +
							"(the platform key is Microsoft-managed, not customer-managed — the " +
							"customer cannot revoke it)")
				}
				if !azResourceIDOK.MatchString(p.DiskEncryptionSetID) {
					return AzureDiskPlan{}, fmt.Errorf(
						"implementation.disk_encryption_set_id %q is not an ARM resource id",
						p.DiskEncryptionSetID)
				}
			}
		case "service.managed":
			if raw != true {
				return AzureDiskPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored — a disk groundhold does not " +
						"own is an adoption, not a create")
			}
		default:
			return AzureDiskPlan{}, fmt.Errorf(
				"attribute %s has no managed-disk mapping — refusing rather than silently "+
					"dropping it (size, SKU and the resource group are operands, not capability "+
					"semantics)", path)
		}
	}
	if p.Location == "" {
		return AzureDiskPlan{}, fmt.Errorf(
			"location.region is required — an ARM resource carries its own location and " +
				"the driver does not choose one")
	}

	// --- OPERATOR operands (implementation block, D26) ---
	//
	// The SKU is required rather than defaulted, because it CARRIES a governed
	// fact: whether the disk survives losing a zone. Letting the service pick it
	// would make the contract's durability guarantee depend on an unstated
	// default — the EBS twin can default its volume type precisely because
	// nothing the contract governs rides on it.
	p.SKU = strings.TrimSpace(implStringAz(impl, "disk_sku"))
	if p.SKU == "" {
		return AzureDiskPlan{}, fmt.Errorf(
			"implementation.disk_sku is required — the SKU decides whether the disk is " +
				"zone-redundant, which the contract governs, so it must not come from a " +
				"service default (e.g. Premium_LRS, StandardSSD_ZRS)")
	}
	if !azDiskSKUOK.MatchString(p.SKU) {
		return AzureDiskPlan{}, fmt.Errorf(
			"implementation.disk_sku %q is not a managed-disk SKU (want <tier>_LRS or <tier>_ZRS)", p.SKU)
	}
	p.Regional = azDiskSKUIsZoneRedundant(p.SKU)

	// The cross-check, in BOTH directions. An over-claim certifies a durability
	// guarantee that does not exist; an under-claim leaves the observed class
	// disagreeing with the declared one, so a converge that should be a no-op
	// reports a violation forever. Either way declared and observed must match.
	if declaredClass != "" {
		if declaredClass == "regional" && !p.Regional {
			return AzureDiskPlan{}, fmt.Errorf(
				"availability.class=regional contradicts implementation.disk_sku %q — a _LRS "+
					"SKU is locally redundant and does not survive losing a zone (a "+
					"zone-redundant SKU ends in _ZRS)", p.SKU)
		}
		if declaredClass == "zonal" && p.Regional {
			return AzureDiskPlan{}, fmt.Errorf(
				"availability.class=zonal contradicts implementation.disk_sku %q — a _ZRS SKU "+
					"IS zone-redundant, so the disk observed back would be regional and the "+
					"contract would report a violation it can never resolve", p.SKU)
		}
	}

	if z := strings.TrimSpace(implStringAz(impl, "zone")); z != "" {
		if !azDiskZoneOK.MatchString(z) {
			return AzureDiskPlan{}, fmt.Errorf(
				"implementation.zone %q is not an Azure availability zone (1, 2 or 3)", z)
		}
		if p.Regional {
			return AzureDiskPlan{}, fmt.Errorf(
				"implementation.zone %q cannot be pinned on the zone-redundant SKU %q — a "+
					"ZRS disk spans zones and pinning one contradicts that", z, p.SKU)
		}
		p.Zone = z
	}
	if src := strings.TrimSpace(implStringAz(impl, "source_resource_id")); src != "" {
		if !azResourceIDOK.MatchString(src) {
			return AzureDiskPlan{}, fmt.Errorf(
				"implementation.source_resource_id %q is not an ARM resource id", src)
		}
		p.SourceResourceID = src
	}
	if v, ok := impl["size_gb"]; ok {
		n, ok := azIntOperand(v)
		if !ok || n <= 0 {
			return AzureDiskPlan{}, fmt.Errorf(
				"implementation.size_gb must be a positive whole number of GiB, got %v", v)
		}
		p.SizeGB = n
	} else if p.SourceResourceID == "" {
		// A copy source carries its own size, so it is the one case where the driver
		// legitimately has an answer it did not invent. Otherwise there is none.
		return AzureDiskPlan{}, fmt.Errorf(
			"implementation.size_gb is required — the driver does not choose a capacity " +
				"(supply a size, or implementation.source_resource_id to copy one that already has it)")
	}
	return p, nil
}

// createBody is the disks.createOrUpdate body.
func (p AzureDiskPlan) createBody(tags map[string]any) map[string]any {
	creation := map[string]any{"createOption": "Empty"}
	if p.SourceResourceID != "" {
		creation = map[string]any{"createOption": "Copy", "sourceResourceId": p.SourceResourceID}
	}
	props := map[string]any{"creationData": creation}
	if p.SizeGB > 0 {
		props["diskSizeGB"] = p.SizeGB
	}
	if p.DiskEncryptionSetID != "" {
		props["encryption"] = map[string]any{
			"type":                "EncryptionAtRestWithCustomerKey",
			"diskEncryptionSetId": p.DiskEncryptionSetID,
		}
	}
	body := map[string]any{
		"location":   p.Location,
		"sku":        map[string]any{"name": p.SKU},
		"tags":       tags,
		"properties": props,
	}
	if p.Zone != "" {
		body["zones"] = []any{p.Zone}
	}
	return body
}

// classifyAzureDiskChange (D46): PURE — can a capability.storage.block transition
// be honored in place?
//
// Azure genuinely allows some disk mutations (a resize, and a limited set of SKU
// conversions on a detached disk), but neither is what this vocabulary governs:
// the size is an operand, and a conversion between _LRS and _ZRS is not among the
// supported ones. Every governed attribute is fixed at creation. Because the type
// is stateful (D47), each becoming a replacement means it needs explicit consent
// rather than happening quietly — right, because it means copying the data.
func classifyAzureDiskChange(path string) (string, string) {
	switch path {
	case "location.region":
		return "immutable", "a managed disk is created in one region and cannot move — a region change is a new disk, and the data must be copied to it"
	case "availability.class":
		return "immutable", "zone redundancy is a property of the SKU at creation, and Azure does not convert between _LRS and _ZRS in place — changing the class means a new disk"
	case "encryption.atRest":
		// D823: this returned "immutable", which makes the plan destroy the disk — and the
		// replacement is encrypted too, so the request is not honoured and the data is gone
		// anyway. When an attribute cannot differ, the honest answer is that it cannot be
		// honoured, not that it needs a new resource.
		return "unsupported", "a managed disk is always encrypted at rest and the setting " +
			"cannot be turned off — nothing to patch (=false cannot be honored)"
	case "encryption.customerManagedKeys":
		// D823: this said the disk-encryption set is "bound when the disk is created".
		// Microsoft's own procedure is the opposite — stop the VM, open the disk, pick the
		// key vault and key under Customer-managed key, save, and "your disks finish
		// switching over to customer-managed keys". Rotating WHICH key is done on the
		// encryption set and reaches every disk referencing it, without touching a disk at
		// all. Destroying a managed disk to change this loses the data on it.
		return "unsupported", "in-place customer-managed-key change is not wired for managed " +
			"disks in this slice — Azure does support it (attach a disk encryption set to an " +
			"existing disk with the VM stopped; rotating the key itself is done on the " +
			"encryption set), so this is a gap in groundhold, not a reason to destroy a disk"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	}
	return "", ""
}
