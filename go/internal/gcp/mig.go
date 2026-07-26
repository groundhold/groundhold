// Managed instance group request building (D371): the GCP half of
// capability.compute.autoscaling — the SAME vocabulary an AWS Auto Scaling group
// fulfils.
//
// The capability/operand split belongs to the vocabulary and is unchanged: the
// contract governs where the fleet lives, whether it spreads across zones, the
// capacity envelope, and whether it scales at all; the machine SHAPE (the
// instance template) is an operand (D26).
//
// Where GCP differs from the ASG twin, it differs structurally rather than
// cosmetically, and each difference makes something the AWS driver must CHECK
// into something this driver simply DECLARES:
//
//   - `availability.class` is a different RESOURCE, not a consequence. A regional
//     MIG lives at /regions/<r>/instanceGroupManagers and spreads itself; a zonal
//     one lives at /zones/<z>/. The AWS twin has to resolve subnets to zones and
//     refuse when they collide, because an ASG's spread is emergent. Here the
//     choice is explicit, so there is nothing to catch — the API cannot produce a
//     "regional" group confined to one zone.
//   - `replicas.minimum` is TWO different fields depending on whether the group
//     scales. With an autoscaler it is the autoscaler's minNumReplicas; without
//     one there is no floor concept at all, only `targetSize`, so a fixed-size
//     group requires minimum == maximum and sets targetSize to it. Pretending a
//     range exists on a fixed group would report an envelope the resource cannot
//     hold.
//   - `network.publicExposure` lives in the INSTANCE TEMPLATE, an operand
//     groundhold does not author — the same shape as the ASG's launch template,
//     and handled the same way: the shell reads the template and refuses when it
//     contradicts the contract, because the group cannot override it.
//
// The group NAME is the idempotency mechanism (D43): insert takes no idempotency
// key, so a deterministic name is what makes a lost create recoverable instead of
// duplicated — and a duplicated FLEET is a duplicated bill that grows on its own.
package gcp

import (
	"fmt"
	"regexp"
	"strings"
)

// migTemplateOK bounds an instance-template reference: a full URL, a qualified
// path, or a bare name in this project.
var migTemplateOK = regexp.MustCompile(`^(https://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+|projects/[a-z0-9-]+/global/instanceTemplates/[a-z0-9-]+|global/instanceTemplates/[a-z0-9-]+|[a-z][a-z0-9-]{0,61}[a-z0-9])$`)

// MIGPlan is the attribute-derived shape a create assembles.
type MIGPlan struct {
	Name string // deterministic: the idempotency mechanism
	// Regional selects the API surface: regionInstanceGroupManagers scoped to
	// regions/<r> when true, instanceGroupManagers scoped to zones/<z> when false.
	Regional          bool
	Zone              string // zonal only
	Region            string // both — the scope for regional, derived for zonal
	MinReplicas       int    // replicas.minimum — the capacity FLOOR
	MaxReplicas       int    // replicas.maximum — the capacity CEILING
	AutoscalingWanted bool
	TargetCPU         float64 // operand; the autoscaler's only tuning
	InstanceTemplate  string  // operand — the machine shape
	WantPublic        bool    // declared; the template is what actually decides it
	PublicDeclared    bool
}

// BuildMIGCreate maps capability.compute.autoscaling attributes + impl to an
// instanceGroupManagers.insert plan. Every error is a preflight refusal, never a
// silent drop.
func BuildMIGCreate(project, environment, capability string,
	attrs, impl map[string]any, generation int) (MIGPlan, error) {

	if !projectOK.MatchString(project) {
		return MIGPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	p := MIGPlan{
		// insert has no idempotency-key parameter: the deterministic NAME is the
		// mechanism (D43). Group names allow 63 characters.
		Name:        resourceName(project, environment, capability, generation, 63),
		MinReplicas: -1,
		MaxReplicas: -1,
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
				return MIGPlan{}, fmt.Errorf(
					"availability.class %v has no managed-instance-group mapping (zonal or regional)", raw)
			}
		case "replicas.minimum":
			n, ok := gceIntOperand(raw)
			if !ok || n < 0 {
				return MIGPlan{}, fmt.Errorf(
					"replicas.minimum must be a whole number of machines, got %v", raw)
			}
			p.MinReplicas = n
		case "replicas.maximum":
			n, ok := gceIntOperand(raw)
			if !ok || n < 0 {
				return MIGPlan{}, fmt.Errorf(
					"replicas.maximum must be a whole number of machines, got %v", raw)
			}
			p.MaxReplicas = n
		case "autoscaling.enabled":
			b, ok := raw.(bool)
			if !ok {
				return MIGPlan{}, fmt.Errorf("autoscaling.enabled must be a bool, got %T", raw)
			}
			p.AutoscalingWanted = b
		case "network.publicExposure":
			b, ok := raw.(bool)
			if !ok {
				return MIGPlan{}, fmt.Errorf("network.publicExposure must be a bool, got %T", raw)
			}
			p.WantPublic, p.PublicDeclared = b, true
		case "service.managed":
			if raw != true {
				return MIGPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored — a group groundhold does not " +
						"own is an adoption, not a create")
			}
		default:
			return MIGPlan{}, fmt.Errorf(
				"attribute %s has no managed-instance-group mapping — refusing rather than "+
					"silently dropping it (the machine shape and the autoscaler's tuning are "+
					"operands, not capability semantics)", path)
		}
	}

	if p.MinReplicas < 0 || p.MaxReplicas < 0 {
		return MIGPlan{}, fmt.Errorf(
			"replicas.minimum and replicas.maximum are both required — the floor is an " +
				"availability decision and the ceiling is a cost and blast-radius decision, " +
				"and the driver makes neither")
	}
	if p.MinReplicas > p.MaxReplicas {
		return MIGPlan{}, fmt.Errorf(
			"replicas.minimum (%d) exceeds replicas.maximum (%d) — an envelope with no "+
				"interior cannot be satisfied by any fleet size", p.MinReplicas, p.MaxReplicas)
	}
	// Without an autoscaler a MIG has no floor/ceiling at all — only targetSize. A
	// declared range on a fixed group would be an envelope the resource cannot
	// hold, and observe would report the single size back against both bounds.
	if !p.AutoscalingWanted && p.MinReplicas != p.MaxReplicas {
		return MIGPlan{}, fmt.Errorf(
			"autoscaling.enabled=false needs replicas.minimum == replicas.maximum, got %d..%d "+
				"— a managed instance group with no autoscaler has a single targetSize and no "+
				"envelope, so a range here could never be satisfied",
			p.MinReplicas, p.MaxReplicas)
	}

	// --- OPERATOR operands (implementation block, D26) ---
	if p.Regional {
		p.Region = strings.TrimSpace(implStr(impl, "region"))
		if p.Region == "" {
			p.Region = region
		}
		if !pdRegionOK.MatchString(p.Region) {
			return MIGPlan{}, fmt.Errorf(
				"a regional managed instance group needs a region — location.region %q is not one "+
					"(supply implementation.region if the contract's is a multi-region)", region)
		}
	} else {
		p.Zone = strings.TrimSpace(implStr(impl, "zone"))
		if p.Zone == "" {
			return MIGPlan{}, fmt.Errorf(
				"implementation.zone is required for a zonal group — the zone places the fleet, " +
					"and the driver does not choose where machines run")
		}
		if !gceZoneOK.MatchString(p.Zone) {
			return MIGPlan{}, fmt.Errorf("implementation.zone %q is not a valid zone", p.Zone)
		}
		p.Region = gceRegionOfZone(p.Zone)
	}
	// The region is the residency surface the CONTRACT governs; the zone is an
	// operand. Without this check the two can disagree and the create succeeds —
	// in the wrong jurisdiction, with the contract reporting satisfied.
	if region != "" && region != p.Region {
		where := "implementation.zone " + p.Zone
		if p.Regional {
			where = "implementation.region " + p.Region
		}
		return MIGPlan{}, fmt.Errorf(
			"location.region %q contradicts %s (region %q) — refusing rather than running "+
				"the fleet somewhere the contract did not ask for", region, where, p.Region)
	}

	p.InstanceTemplate = strings.TrimSpace(implStr(impl, "instance_template"))
	if p.InstanceTemplate == "" {
		return MIGPlan{}, fmt.Errorf(
			"implementation.instance_template is required — the template is the machine " +
				"shape (type, image, addressing), which the driver does not choose")
	}
	if !migTemplateOK.MatchString(p.InstanceTemplate) {
		return MIGPlan{}, fmt.Errorf(
			"implementation.instance_template %q is not an instance-template reference", p.InstanceTemplate)
	}

	// An autoscaler needs tuning the vocabulary deliberately excludes (D363), so
	// the operator supplies it. Inventing a target would attach a control loop
	// nobody reviewed to a fleet the operator pays for.
	if p.AutoscalingWanted {
		v, ok := impl["target_cpu_utilization"]
		if !ok {
			return MIGPlan{}, fmt.Errorf(
				"autoscaling.enabled=true requires implementation.target_cpu_utilization — the " +
					"contract governs THAT an autoscaler exists, never its tuning (D363), so the " +
					"target comes from the operator and the driver does not invent one")
		}
		n, ok := gceIntOperand(v)
		if !ok || n <= 0 || n > 100 {
			return MIGPlan{}, fmt.Errorf(
				"implementation.target_cpu_utilization must be a percentage between 1 and 100, got %v", v)
		}
		p.TargetCPU = float64(n) / 100
	} else if _, ok := impl["target_cpu_utilization"]; ok {
		return MIGPlan{}, fmt.Errorf(
			"implementation.target_cpu_utilization was supplied but autoscaling.enabled is not " +
				"true — the target would be ignored and the fleet would stay fixed-size")
	}
	return p, nil
}

// createBody is the instanceGroupManagers.insert body. targetSize starts the
// group at its FLOOR: the contract's minimum is the capacity it declared it
// needs, and starting above it would provision machines nobody asked for.
//
// Ownership is the DESCRIPTION MARKER, the established pattern in this package
// for resources that carry no labels (vpc, cloudarmor, auditlogs). A managed
// instance group has no labels field, and ownership has to live somewhere a
// delete can read it — the alternative, deriving ownership from the name, means
// reconstructing a hash whose inputs the delete path does not have.
func (p MIGPlan) createBody(capability, environment string) map[string]any {
	return map[string]any{
		"name":             p.Name,
		"baseInstanceName": p.Name,
		"instanceTemplate": p.InstanceTemplate,
		"targetSize":       p.MinReplicas,
		"description":      vpcOwnerMarker(capability, environment),
	}
}

// autoscalerBody is the autoscalers.insert body — CPU-utilization scaling, whose
// only configurable part is the target the operator supplied. Everything else is
// the service's own control loop, which is what "an autoscaler exists" means here.
func (p MIGPlan) autoscalerBody(groupSelfLink string) map[string]any {
	return map[string]any{
		"name":   p.Name + "-cpu",
		"target": groupSelfLink,
		"autoscalingPolicy": map[string]any{
			"minNumReplicas":    p.MinReplicas,
			"maxNumReplicas":    p.MaxReplicas,
			"cpuUtilization":    map[string]any{"utilizationTarget": p.TargetCPU},
			"coolDownPeriodSec": 60,
		},
	}
}

// classifyMIGChange (D46): PURE — can a capability.compute.autoscaling transition
// be honored in place?
//
// The same answer as the ASG twin, for the same reason: resizing the envelope is
// what a group is FOR, so the bounds and the autoscaler are mutable, while where
// the fleet lives is fixed at creation. One difference is worth stating —
// `availability.class` is immutable here because zonal and regional groups are
// different RESOURCES at different scopes, not two settings of one.
func classifyMIGChange(path string) (string, string) {
	switch path {
	case "replicas.minimum", "replicas.maximum":
		return "mutable", "the autoscaler's bounds (or the group's targetSize) are patchable in place — resizing is what a group is for"
	case "autoscaling.enabled":
		return "mutable", "an autoscaler can be attached to or removed from a live group"
	case "location.region":
		return "immutable", "a group is created in one region and cannot move — a region change is a new group"
	case "availability.class":
		return "immutable", "zonal and regional groups are different resources at different scopes, not two settings of one — changing the class means a new group"
	case "network.publicExposure":
		return "immutable", "public addressing lives in the instance template, which groundhold does not author — change the template and replace the group, so the running fleet is not silently re-addressed"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	}
	return "", ""
}
