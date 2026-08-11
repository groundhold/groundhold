// Azure virtual machine request building (D360): the semantic core of the Azure
// capability.compute.instance driver — the SAME vocabulary EC2 and GCE fulfil,
// and the third cloud for this capability.
//
// The capability/operand split is unchanged from both twins, because it belongs
// to the vocabulary: the contract governs residency, public exposure and disk
// encryption; the VM size, the image and the network interface are operator
// operands (D26). No default size, no default image, on any cloud.
//
// What is DIFFERENT about Azure, stated rather than smoothed over:
//
//   - Managed disks are always encrypted at rest with a platform key, so
//     `encryption.atRest: false` is REFUSED — the same call GCE makes, and for
//     the same reason. Only EC2 honors false, because EBS genuinely can be
//     unencrypted.
//   - Public exposure is NOT a property of the machine at all. An Azure VM
//     references a network interface, and the interface carries the public IP.
//     The pure core therefore cannot decide exposure alone: it records what the
//     contract asked for, and the shell reads the NIC to observe what is true.
//     Neither guesses.
//   - A VM needs an admin identity. `admin_username` and `ssh_public_key` are
//     required operands; a PASSWORD operand is refused outright. A candidate is a
//     reviewed, stored document — it is the wrong place for a credential, and
//     accepting one "just this once" is how secrets end up in git.
//
// The resource group is an operand, never something groundhold creates: a
// resource group is an account-shaped container, like a subscription.
package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// azIntOperand accepts the whole-number shapes YAML produces, and refuses a
// fraction rather than truncating it into a plausible lie.
func azIntOperand(v any) (int, bool) {
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

var (
	// azVMSizeOK bounds a VM size token (Standard_D2s_v5 and friends).
	azVMSizeOK = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
	// azNICIDOK bounds a network-interface resource id.
	azNICIDOK = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/networkInterfaces/[A-Za-z0-9._-]+$`)
	// azDESIDOK bounds a disk-encryption-set resource id (the CMK carrier).
	azDESIDOK = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Compute/diskEncryptionSets/[A-Za-z0-9._-]+$`)
	// azAdminOK bounds a Linux admin user name.
	azAdminOK = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	// azSSHKeyOK bounds an OpenSSH public key. Public by definition — a PRIVATE
	// key would not match, which is a cheap guard against the worst paste.
	azSSHKeyOK = regexp.MustCompile(`^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp[0-9]+) [A-Za-z0-9+/=]+( .*)?$`)
)

// AzureVMPlan is the attribute-derived shape a create assembles into the ARM body.
type AzureVMPlan struct {
	Name          string // deterministic: ARM PUT is idempotent by name
	Region        string
	VMSize        string // operand — no default, ever
	ImageRef      string // operand — publisher:offer:sku:version, or a resource id
	NICID         string // operand — the interface carries the public address
	DiskEncSetID  string // CMEK; "" = the platform-managed key (still encrypted)
	AdminUsername string // operand
	SSHPublicKey  string // operand — public by definition
	DiskSizeGB    int    // optional; 0 = the image's default
	WantPublic    bool   // what the CONTRACT asked for; the NIC decides what is true
}

// azureVMName derives deterministically. ARM PUT is idempotent by name, so the
// name is what makes a lost create recoverable rather than duplicated — the same
// role GCE's name plays and EC2's ClientToken plays.
func azureVMName(environment, capability string, generation int) string {
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "pv-vm-" + hex.EncodeToString(sum[:])[:12] // 6 + 12 = 18 chars, under the 64 limit
}

// BuildAzureVM maps capability.compute.instance attributes + impl to an ARM
// virtualMachines plan. Every error is a preflight refusal, never a silent drop.
func BuildAzureVM(environment, capability string,
	attrs, impl map[string]any, generation int) (AzureVMPlan, error) {

	p := AzureVMPlan{Name: azureVMName(environment, capability, generation)}

	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			s, _ := raw.(string)
			if strings.TrimSpace(s) == "" {
				return AzureVMPlan{}, fmt.Errorf("location.region must be a non-empty region name")
			}
			p.Region = s
		case "availability.class":
			switch raw {
			case "zonal":
				// a VM is placed in one zone; the zone itself is topology (operand).
			case "regional":
				return AzureVMPlan{}, fmt.Errorf(
					"availability.class=regional cannot be honored by a single Azure VM " +
						"(a machine lives in exactly one zone — regional placement is a property " +
						"of a scale set, a different capability)")
			default:
				return AzureVMPlan{}, fmt.Errorf(
					"availability.class %v has no Azure VM mapping (zonal only for a machine)", raw)
			}
		case "network.publicExposure":
			b, ok := raw.(bool)
			if !ok {
				return AzureVMPlan{}, fmt.Errorf("network.publicExposure must be a bool, got %T", raw)
			}
			// Recorded, not realized: the public address lives on the network
			// INTERFACE, which is a separate resource this driver does not own.
			p.WantPublic = b
		case "encryption.atRest":
			if raw != true {
				return AzureVMPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored by Azure — managed disks are always " +
						"encrypted at rest with a platform key and there is no way to disable it, so " +
						"accepting false would report a state the platform cannot produce")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.DiskEncSetID = strings.TrimSpace(implStringAz(impl, "disk_encryption_set_id"))
				if p.DiskEncSetID == "" {
					return AzureVMPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.disk_encryption_set_id " +
							"(the platform-managed disk key is Microsoft's, not the customer's)")
				}
				if !azDESIDOK.MatchString(p.DiskEncSetID) {
					return AzureVMPlan{}, fmt.Errorf(
						"implementation.disk_encryption_set_id %q is not a disk-encryption-set resource id",
						p.DiskEncSetID)
				}
			}
		case "service.managed":
			if raw != true {
				return AzureVMPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored — a machine groundhold does not " +
						"own is an adoption, not a create")
			}
		default:
			return AzureVMPlan{}, fmt.Errorf(
				"attribute %s has no Azure VM mapping — refusing rather than silently dropping "+
					"it (VM size, image and network interface are operands, not capability semantics)", path)
		}
	}
	if p.Region == "" {
		return AzureVMPlan{}, fmt.Errorf("location.region is required — a machine must be placed somewhere")
	}

	// --- OPERATOR operands (implementation block, D26) ---
	// A password operand is refused before anything else is read: the point is
	// that it must never be written down, so the refusal must not depend on the
	// rest of the document being valid.
	for _, forbidden := range []string{"admin_password", "password"} {
		if _, present := impl[forbidden]; present {
			return AzureVMPlan{}, fmt.Errorf(
				"implementation.%s is refused — a candidate is a reviewed, stored document and "+
					"is the wrong place for a credential; supply ssh_public_key instead", forbidden)
		}
	}
	p.VMSize = strings.TrimSpace(implStringAz(impl, "vm_size"))
	if p.VMSize == "" {
		return AzureVMPlan{}, fmt.Errorf(
			"implementation.vm_size is required — the driver does not choose a size " +
				"(a guessed size provisions capacity nobody asked for, and bills for it)")
	}
	if !azVMSizeOK.MatchString(p.VMSize) {
		return AzureVMPlan{}, fmt.Errorf("implementation.vm_size %q is not a valid VM size", p.VMSize)
	}
	p.ImageRef = strings.TrimSpace(implStringAz(impl, "image_reference"))
	if p.ImageRef == "" {
		return AzureVMPlan{}, fmt.Errorf(
			"implementation.image_reference is required — the driver does not choose an image " +
				"(what runs on the machine is the operator's decision, never a default)")
	}
	if strings.Count(p.ImageRef, ":") != 3 && !strings.HasPrefix(p.ImageRef, "/subscriptions/") {
		return AzureVMPlan{}, fmt.Errorf(
			"implementation.image_reference %q must be publisher:offer:sku:version or a resource id",
			p.ImageRef)
	}
	p.NICID = strings.TrimSpace(implStringAz(impl, "network_interface_id"))
	if p.NICID == "" {
		return AzureVMPlan{}, fmt.Errorf(
			"implementation.network_interface_id is required — on Azure the interface, not the " +
				"machine, carries the network identity, and groundhold does not create one implicitly")
	}
	if !azNICIDOK.MatchString(p.NICID) {
		return AzureVMPlan{}, fmt.Errorf(
			"implementation.network_interface_id %q is not a network-interface resource id", p.NICID)
	}
	p.AdminUsername = strings.TrimSpace(implStringAz(impl, "admin_username"))
	if !azAdminOK.MatchString(p.AdminUsername) {
		return AzureVMPlan{}, fmt.Errorf(
			"implementation.admin_username is required and must be a valid Linux user name")
	}
	p.SSHPublicKey = strings.TrimSpace(implStringAz(impl, "ssh_public_key"))
	if !azSSHKeyOK.MatchString(p.SSHPublicKey) {
		return AzureVMPlan{}, fmt.Errorf(
			"implementation.ssh_public_key is required and must be an OpenSSH PUBLIC key " +
				"(ssh-rsa/ssh-ed25519/ecdsa-sha2-*)")
	}
	if v, ok := impl["os_disk_size_gb"]; ok {
		n, ok := azIntOperand(v)
		if !ok || n <= 0 {
			return AzureVMPlan{}, fmt.Errorf(
				"implementation.os_disk_size_gb must be a positive whole number of GB, got %v", v)
		}
		p.DiskSizeGB = n
	}
	return p, nil
}

// createBody is the virtualMachines PUT body.
func (p AzureVMPlan) createBody(tags map[string]any) map[string]any {
	osDisk := map[string]any{
		"createOption": "FromImage",
		// D941: cascade the OS disk with the VM. The create implicitly provisions this
		// managed disk (createOption:FromImage), but Azure's default deleteOption is
		// Detach — so deleting the VM left the Premium_LRS OS disk standing and billing,
		// while observe read only the VM's 404 and reported the estate "gone". The NIC is
		// an operator operand (network_interface_id), so the disk is the ONLY
		// driver-created companion; deleteOption:Delete makes it cascade (D920 residue).
		"deleteOption": "Delete",
		"managedDisk":  map[string]any{"storageAccountType": "Premium_LRS"},
	}
	if p.DiskEncSetID != "" {
		osDisk["managedDisk"].(map[string]any)["diskEncryptionSet"] = map[string]any{"id": p.DiskEncSetID}
	}
	if p.DiskSizeGB > 0 {
		osDisk["diskSizeGB"] = p.DiskSizeGB
	}
	image := map[string]any{}
	if strings.HasPrefix(p.ImageRef, "/subscriptions/") {
		image["id"] = p.ImageRef
	} else {
		parts := strings.SplitN(p.ImageRef, ":", 4)
		image["publisher"], image["offer"], image["sku"], image["version"] = parts[0], parts[1], parts[2], parts[3]
	}
	return map[string]any{
		"location": p.Region,
		"tags":     tags,
		"properties": map[string]any{
			"hardwareProfile": map[string]any{"vmSize": p.VMSize},
			"storageProfile": map[string]any{
				"imageReference": image,
				"osDisk":         osDisk,
			},
			"osProfile": map[string]any{
				"computerName":  p.Name,
				"adminUsername": p.AdminUsername,
				"linuxConfiguration": map[string]any{
					// Password auth is disabled structurally, not by convention: the
					// driver refuses a password operand, so leaving this true would
					// permit a credential path nobody declared.
					"disablePasswordAuthentication": true,
					"ssh": map[string]any{"publicKeys": []any{map[string]any{
						"path":    "/home/" + p.AdminUsername + "/.ssh/authorized_keys",
						"keyData": p.SSHPublicKey,
					}}},
				},
			},
			"networkProfile": map[string]any{
				"networkInterfaces": []any{map[string]any{"id": p.NICID}},
			},
		},
	}
}

// classifyAzureVMChange (D46): the same verdicts as both twins where the reason is
// the same. Azure matches GCE on encryption.atRest (nothing to patch) and matches
// both on everything else: a machine's region, placement, network identity and
// disk key are fixed when it is created.
func classifyAzureVMChange(path string) (string, string) {
	switch path {
	case "location.region":
		return "immutable", "a VM is created in one region and cannot move — a region change is a new machine"
	case "availability.class":
		return "immutable", "zone placement is fixed at creation — a change is a new machine"
	case "network.publicExposure":
		return "unsupported", "on Azure the public address belongs to the network interface, a resource this driver does not own — changing it is an edit to the interface, not to the machine"
	case "encryption.atRest":
		return "unsupported", "Azure managed disks are always encrypted at rest with a platform key — there is nothing to patch"
	case "encryption.customerManagedKeys":
		// D825: the same sentence D823 disproved on the disk, with a heavier conclusion
		// drawn from it. Microsoft's own procedure attaches a disk encryption set to an
		// EXISTING disk — stop the VM, open the disk, pick the key vault and key, save —
		// and rotating WHICH key happens on the encryption set and reaches every disk
		// referencing it. Destroying a machine for this loses its instance data as well as
		// its uptime.
		return "unsupported", "in-place customer-managed-key change is not wired for Azure " +
			"VMs in this slice — Azure does support it (a disk encryption set attaches to an " +
			"existing disk with the VM stopped; rotating the key is done on the encryption " +
			"set), so this is a gap in groundhold, not a reason to replace the machine"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	}
	return "", ""
}
