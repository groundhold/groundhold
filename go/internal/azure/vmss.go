// Virtual machine scale set request building (D372): the Azure third of
// capability.compute.autoscaling — the SAME vocabulary an AWS Auto Scaling group
// and a GCP managed instance group fulfil, and the last companion around the
// machine on the last cloud.
//
// The interesting difference is what the group OWNS. On AWS and GCP the fleet's
// machine shape lives in a separate resource — a launch template, an instance
// template — that groundhold does not author, so `network.publicExposure` has to
// be VERIFIED by reading that resource and refusing when it contradicts the
// contract (D371). A scale set holds its VM profile INLINE. There is nothing to
// read and nothing to contradict: the driver simply builds the addressing the
// contract asked for. One governed attribute, three clouds, and on this one it is
// authored rather than checked.
//
// The other two differences are shared with a twin each:
//
//   - `availability.class` is DECLARED, in the `zones` array — explicit like a
//     GCP regional group, not emergent like an ASG's subnet spread. So it is
//     cross-checked against the operand in BOTH directions, exactly as the
//     managed disk's class is checked against its SKU (D369): an over-claim
//     certifies zone survivability that does not exist, and an under-claim leaves
//     observed and declared disagreeing forever.
//   - a fixed-size fleet has no envelope, only `sku.capacity` — the same
//     asymmetry a GCP MIG has (D371), so the same rule: without an autoscale
//     setting, `replicas.minimum` must equal `replicas.maximum`.
//
// A password operand is refused outright, as it is for a single VM (D360): a
// candidate is a reviewed, stored document and is the wrong place for a
// credential. On a fleet the blast radius is every machine the group ever
// creates, including the ones it creates next year.
package azure

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// azVMSSZoneOK bounds a logical availability zone.
var azVMSSZoneOK = regexp.MustCompile(`^[1-3]$`)

// VMSSPlan is the attribute-derived shape a create assembles.
type VMSSPlan struct {
	Name              string // deterministic: the idempotency mechanism
	Location          string
	Zones             []string // operand; the zone spread the contract governs
	Regional          bool     // declared, cross-checked against Zones
	MinCapacity       int      // replicas.minimum — the capacity FLOOR
	MaxCapacity       int      // replicas.maximum — the capacity CEILING
	AutoscalingWanted bool
	TargetCPUPercent  int    // operand; the autoscale setting's only tuning
	VMSize            string // operand — the machine shape
	ImageRef          string // operand
	SubnetID          string // operand
	AdminUsername     string // operand
	SSHPublicKey      string // operand
	WantPublic        bool   // AUTHORED here: the VM profile is inline
}

// BuildVMSS maps capability.compute.autoscaling attributes + impl to a
// virtualMachineScaleSets.createOrUpdate plan. Every error is a preflight
// refusal, never a silent drop.
func BuildVMSS(environment, capability string,
	attrs, impl map[string]any, generation int) (VMSSPlan, error) {

	p := VMSSPlan{
		// createOrUpdate is a PUT at a named path: the deterministic NAME is the
		// idempotency mechanism, as it is for every ARM resource.
		Name:        azResourceName("pv-vmss", environment, capability, generation),
		MinCapacity: -1,
		MaxCapacity: -1,
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
				return VMSSPlan{}, fmt.Errorf("location.region must be a non-empty string, got %v", raw)
			}
			p.Location = strings.TrimSpace(s)
		case "availability.class":
			switch raw {
			case "zonal", "regional":
				declaredClass, _ = raw.(string)
				p.Regional = raw == "regional"
			default:
				return VMSSPlan{}, fmt.Errorf(
					"availability.class %v has no scale-set mapping (zonal or regional)", raw)
			}
		case "replicas.minimum":
			n, ok := azIntOperand(raw)
			if !ok || n < 0 {
				return VMSSPlan{}, fmt.Errorf(
					"replicas.minimum must be a whole number of machines, got %v", raw)
			}
			p.MinCapacity = n
		case "replicas.maximum":
			n, ok := azIntOperand(raw)
			if !ok || n < 0 {
				return VMSSPlan{}, fmt.Errorf(
					"replicas.maximum must be a whole number of machines, got %v", raw)
			}
			p.MaxCapacity = n
		case "autoscaling.enabled":
			b, ok := raw.(bool)
			if !ok {
				return VMSSPlan{}, fmt.Errorf("autoscaling.enabled must be a bool, got %T", raw)
			}
			p.AutoscalingWanted = b
		case "network.publicExposure":
			b, ok := raw.(bool)
			if !ok {
				return VMSSPlan{}, fmt.Errorf("network.publicExposure must be a bool, got %T", raw)
			}
			p.WantPublic = b
		case "service.managed":
			if raw != true {
				return VMSSPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored — a fleet groundhold does not " +
						"own is an adoption, not a create")
			}
		default:
			return VMSSPlan{}, fmt.Errorf(
				"attribute %s has no scale-set mapping — refusing rather than silently "+
					"dropping it (the machine shape and the autoscale setting's tuning are "+
					"operands, not capability semantics)", path)
		}
	}
	if p.Location == "" {
		return VMSSPlan{}, fmt.Errorf(
			"location.region is required — an ARM resource carries its own location and " +
				"the driver does not choose one")
	}
	if p.MinCapacity < 0 || p.MaxCapacity < 0 {
		return VMSSPlan{}, fmt.Errorf(
			"replicas.minimum and replicas.maximum are both required — the floor is an " +
				"availability decision and the ceiling is a cost and blast-radius decision, " +
				"and the driver makes neither")
	}
	if p.MinCapacity > p.MaxCapacity {
		return VMSSPlan{}, fmt.Errorf(
			"replicas.minimum (%d) exceeds replicas.maximum (%d) — an envelope with no "+
				"interior cannot be satisfied by any fleet size", p.MinCapacity, p.MaxCapacity)
	}
	// Without an autoscale setting a scale set has one size (sku.capacity) and no
	// envelope — the same asymmetry a GCP managed instance group has.
	if !p.AutoscalingWanted && p.MinCapacity != p.MaxCapacity {
		return VMSSPlan{}, fmt.Errorf(
			"autoscaling.enabled=false needs replicas.minimum == replicas.maximum, got %d..%d "+
				"— a scale set with no autoscale setting has a single sku.capacity and no "+
				"envelope, so a range here could never be satisfied",
			p.MinCapacity, p.MaxCapacity)
	}

	// --- OPERATOR operands (implementation block, D26) ---
	// A password operand is refused before anything else is read: the point is
	// that it must never be written down, so the refusal must not depend on the
	// rest of the document being valid. On a fleet it would reach every machine
	// the group ever creates.
	for _, forbidden := range []string{"admin_password", "password"} {
		if _, present := impl[forbidden]; present {
			return VMSSPlan{}, fmt.Errorf(
				"implementation.%s is refused — a candidate is a reviewed, stored document and "+
					"is the wrong place for a credential, and on a fleet it would be baked into "+
					"every machine the group ever creates; supply ssh_public_key instead", forbidden)
		}
	}
	zones, err := azVMSSZones(impl)
	if err != nil {
		return VMSSPlan{}, err
	}
	p.Zones = zones

	// The cross-check, in BOTH directions — the same shape the managed disk uses
	// for its SKU (D369). An over-claim certifies survivability that does not
	// exist; an under-claim leaves the fleet observing back as regional, so a
	// converge that should be a no-op reports a violation it can never resolve.
	if declaredClass == "regional" && len(zones) < 2 {
		return VMSSPlan{}, fmt.Errorf(
			"availability.class=regional needs implementation.zones to name more than one zone, "+
				"got %v — a fleet confined to one zone does not survive losing it", zones)
	}
	if declaredClass == "zonal" && len(zones) > 1 {
		return VMSSPlan{}, fmt.Errorf(
			"availability.class=zonal contradicts implementation.zones %v — the fleet would "+
				"span those zones and observe back as regional, so the contract would report a "+
				"violation it can never resolve", zones)
	}

	p.VMSize = strings.TrimSpace(implStringAz(impl, "vm_size"))
	if p.VMSize == "" {
		return VMSSPlan{}, fmt.Errorf(
			"implementation.vm_size is required — the driver does not choose a size " +
				"(a guessed size provisions capacity nobody asked for, and bills for it on " +
				"every machine in the fleet)")
	}
	if !azVMSizeOK.MatchString(p.VMSize) {
		return VMSSPlan{}, fmt.Errorf("implementation.vm_size %q is not a valid VM size", p.VMSize)
	}
	p.ImageRef = strings.TrimSpace(implStringAz(impl, "image_reference"))
	if p.ImageRef == "" {
		return VMSSPlan{}, fmt.Errorf(
			"implementation.image_reference is required — the driver does not choose an image " +
				"(what runs on the machines is the operator's decision, never a default)")
	}
	if strings.Count(p.ImageRef, ":") != 3 && !strings.HasPrefix(p.ImageRef, "/subscriptions/") {
		return VMSSPlan{}, fmt.Errorf(
			"implementation.image_reference %q must be publisher:offer:sku:version or a resource id",
			p.ImageRef)
	}
	p.SubnetID = strings.TrimSpace(implStringAz(impl, "subnet_id"))
	if p.SubnetID == "" {
		return VMSSPlan{}, fmt.Errorf(
			"implementation.subnet_id is required — the subnet places the fleet, and " +
				"groundhold does not create one implicitly")
	}
	if !azResourceIDOK.MatchString(p.SubnetID) {
		return VMSSPlan{}, fmt.Errorf(
			"implementation.subnet_id %q is not an ARM resource id", p.SubnetID)
	}
	p.AdminUsername = strings.TrimSpace(implStringAz(impl, "admin_username"))
	if !azAdminOK.MatchString(p.AdminUsername) {
		return VMSSPlan{}, fmt.Errorf(
			"implementation.admin_username is required and must be a valid Linux user name")
	}
	p.SSHPublicKey = strings.TrimSpace(implStringAz(impl, "ssh_public_key"))
	if !azSSHKeyOK.MatchString(p.SSHPublicKey) {
		return VMSSPlan{}, fmt.Errorf(
			"implementation.ssh_public_key is required and must be an OpenSSH PUBLIC key " +
				"(ssh-rsa/ssh-ed25519/ecdsa-sha2-*)")
	}

	// An autoscale setting needs tuning the vocabulary deliberately excludes
	// (D363), so the operator supplies it.
	if p.AutoscalingWanted {
		v, ok := impl["target_cpu_utilization"]
		if !ok {
			return VMSSPlan{}, fmt.Errorf(
				"autoscaling.enabled=true requires implementation.target_cpu_utilization — the " +
					"contract governs THAT an autoscale setting exists, never its tuning (D363), " +
					"so the target comes from the operator and the driver does not invent one")
		}
		n, ok := azIntOperand(v)
		if !ok || n <= 0 || n > 100 {
			return VMSSPlan{}, fmt.Errorf(
				"implementation.target_cpu_utilization must be a percentage between 1 and 100, got %v", v)
		}
		p.TargetCPUPercent = n
	} else if _, ok := impl["target_cpu_utilization"]; ok {
		return VMSSPlan{}, fmt.Errorf(
			"implementation.target_cpu_utilization was supplied but autoscaling.enabled is not " +
				"true — the target would be ignored and the fleet would stay fixed-size")
	}
	return p, nil
}

// azVMSSZones reads the zones the fleet spreads across. Absent means "no zone
// pinning", which Azure treats as regional-without-zone-redundancy — and which
// this driver treats as zonal, because a fleet with no declared zones has no
// zone-failure guarantee to offer.
func azVMSSZones(impl map[string]any) ([]string, error) {
	raw, ok := impl["zones"]
	if !ok {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("implementation.zones must be a list, got %T", raw)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("implementation.zones must contain strings, got %T", e)
		}
		s = strings.TrimSpace(s)
		if !azVMSSZoneOK.MatchString(s) {
			return nil, fmt.Errorf(
				"implementation.zones contains %q, which is not an Azure availability zone (1, 2 or 3)", s)
		}
		if seen[s] {
			// Two copies of one zone is one zone, and a contract calling that
			// `regional` would claim a guarantee the fleet does not have.
			return nil, fmt.Errorf("implementation.zones names zone %q twice", s)
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}

// createBody is the virtualMachineScaleSets.createOrUpdate body. sku.capacity
// starts the fleet at its FLOOR: the contract's minimum is the capacity it
// declared it needs, and starting above it bills for machines nobody asked for.
func (p VMSSPlan) createBody(tags map[string]any) map[string]any {
	ipConfig := map[string]any{
		"name": "ipconfig",
		"properties": map[string]any{
			"subnet": map[string]any{"id": p.SubnetID},
		},
	}
	if p.WantPublic {
		// AUTHORED, not verified: the VM profile is inline, so the contract's
		// exposure decision is something this driver simply builds.
		ipConfig["properties"].(map[string]any)["publicIPAddressConfiguration"] =
			map[string]any{"name": "pip", "properties": map[string]any{"idleTimeoutInMinutes": 15}}
	}
	body := map[string]any{
		"location": p.Location,
		"tags":     tags,
		"sku": map[string]any{
			"name":     p.VMSize,
			"capacity": p.MinCapacity,
		},
		"properties": map[string]any{
			"overprovision": false,
			"upgradePolicy": map[string]any{"mode": "Manual"},
			"virtualMachineProfile": map[string]any{
				"osProfile": map[string]any{
					"computerNamePrefix": "pv",
					"adminUsername":      p.AdminUsername,
					"linuxConfiguration": map[string]any{
						// The driver refuses a password operand, so leaving this true
						// would advertise a login path nothing can use.
						"disablePasswordAuthentication": true,
						"ssh": map[string]any{"publicKeys": []any{map[string]any{
							"path":    "/home/" + p.AdminUsername + "/.ssh/authorized_keys",
							"keyData": p.SSHPublicKey,
						}}},
					},
				},
				"storageProfile": map[string]any{
					"imageReference": azImageReferenceBody(p.ImageRef),
				},
				"networkProfile": map[string]any{
					"networkInterfaceConfigurations": []any{map[string]any{
						"name": "nic",
						"properties": map[string]any{
							"primary":          true,
							"ipConfigurations": []any{ipConfig},
						},
					}},
				},
			},
		},
	}
	if len(p.Zones) > 0 {
		zones := make([]any, 0, len(p.Zones))
		for _, z := range p.Zones {
			zones = append(zones, z)
		}
		body["zones"] = zones
	}
	return body
}

// autoscaleBody is the Microsoft.Insights/autoscalesettings body — CPU-percentage
// scaling whose only configurable part is the target the operator supplied.
func (p VMSSPlan) autoscaleBody(targetResourceID string, tags map[string]any) map[string]any {
	rule := func(direction, operator string) map[string]any {
		return map[string]any{
			"metricTrigger": map[string]any{
				"metricName":        "Percentage CPU",
				"metricResourceUri": targetResourceID,
				"timeGrain":         "PT1M",
				"statistic":         "Average",
				"timeWindow":        "PT5M",
				"timeAggregation":   "Average",
				"operator":          operator,
				"threshold":         p.TargetCPUPercent,
			},
			"scaleAction": map[string]any{
				"direction": direction,
				"type":      "ChangeCount",
				"value":     "1",
				"cooldown":  "PT5M",
			},
		}
	}
	return map[string]any{
		"location": p.Location,
		"tags":     tags,
		"properties": map[string]any{
			"enabled":           true,
			"targetResourceUri": targetResourceID,
			"profiles": []any{map[string]any{
				"name": "cpu",
				"capacity": map[string]any{
					"minimum": fmt.Sprintf("%d", p.MinCapacity),
					"maximum": fmt.Sprintf("%d", p.MaxCapacity),
					"default": fmt.Sprintf("%d", p.MinCapacity),
				},
				"rules": []any{
					rule("Increase", "GreaterThan"),
					rule("Decrease", "LessThan"),
				},
			}},
		},
	}
}

// azImageReferenceBody renders an image operand as ARM expects it: a resource id
// becomes {id}, and the publisher:offer:sku:version form becomes its four fields.
func azImageReferenceBody(ref string) map[string]any {
	if strings.HasPrefix(ref, "/subscriptions/") {
		return map[string]any{"id": ref}
	}
	parts := strings.SplitN(ref, ":", 4)
	return map[string]any{
		"publisher": parts[0], "offer": parts[1], "sku": parts[2], "version": parts[3],
	}
}

// classifyVMSSChange (D46): PURE — the same answer as both twins, for the same
// reason. Resizing the envelope is what a fleet is FOR, so the bounds and the
// autoscale setting are mutable; where the fleet lives is fixed at creation.
//
// `network.publicExposure` differs from its twins here and the reason is worth
// stating: on AWS and GCP it is immutable because it lives in a template
// groundhold does not author. On Azure the VM profile is inline, so it CAN be
// patched — but patching it re-addresses machines the fleet is already running,
// which is a change of exposure on live capacity rather than a configuration
// edit. Caveated, not silently mutable.
func classifyVMSSChange(path string) (string, string) {
	switch path {
	case "replicas.minimum", "replicas.maximum":
		return "mutable", "sku.capacity and the autoscale profile are patchable in place — resizing is what a fleet is for"
	case "autoscaling.enabled":
		return "mutable", "an autoscale setting can be created or removed against a live scale set"
	case "network.publicExposure":
		return "caveated", "the VM profile is inline so exposure CAN be patched, but the change re-addresses machines the fleet is already running — new instances get the new profile and existing ones need a rolling upgrade"
	case "location.region":
		return "immutable", "a scale set is created in one region and cannot move — a region change is a new fleet"
	case "availability.class":
		// D822: this said the zone list is "fixed when the scale set is created". Microsoft
		// documents the opposite for the direction that matters: "You can modify a scale
		// set to expand the set of zones over which to spread VM instances", with the
		// limitation "You can't remove or replace zones, only add zones". So RAISING
		// availability is an in-place update and only lowering it is a replacement — and
		// the old sentence told an operator to destroy a fleet to make it safer.
		return "unsupported", "in-place zone change is not wired for scale sets in this " +
			"slice — Azure supports ADDING zones on a live scale set (the zones property is " +
			"updatable; removing or replacing zones is not), so widening availability is a " +
			"gap in groundhold rather than a reason to replace the fleet"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	}
	return "", ""
}
