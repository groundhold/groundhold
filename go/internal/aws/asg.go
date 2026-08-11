// Auto Scaling group request building (D371): the semantic core of the AWS
// capability.compute.autoscaling driver — the SAME vocabulary a GCP managed
// instance group and an Azure scale set fulfil.
//
// A GROUP EXPRESSES CAPACITY; AN INSTANCE EXPRESSES A MACHINE (D363). That is why
// `replicas.minimum` lives here and was refused on the instance type — a floor of
// one machine is meaningless on a single machine — and why `availability.class`
// can be `regional` here and cannot there. Spreading across zones is something a
// group does and a machine cannot, which is most of the reason groups exist.
//
// Three attributes are NOT properties of the group resource, and each is handled
// by checking rather than by assuming. This is the shape that makes this driver
// different from its two companions in the family:
//
//   - `availability.class` is a CONSEQUENCE of the subnets. An ASG has no
//     zonal/regional switch: it spreads across whatever availability zones its
//     subnets sit in. The pure core can check the COUNT (regional needs more than
//     one subnet, zonal exactly one); only the network shell can check that the
//     zones are DISTINCT, because subnet-to-zone is a lookup. Both checks run
//     before anything is created — two subnets in one zone would certify zone
//     survivability that does not exist.
//
//   - `network.publicExposure` lives in the LAUNCH TEMPLATE, which is an operand
//     the operator supplies and groundhold does not author. The group cannot set
//     it. Accepting the declared value without looking would be the silent
//     ignoring this project refuses everywhere else, so the shell READS the
//     template and refuses when it contradicts the contract.
//
//   - `autoscaling.enabled` needs a POLICY, and the policy's tuning is
//     deliberately outside the vocabulary (D363: a control loop with its own
//     tuning is not capability semantics). The contract governs THAT a policy
//     exists; the operator supplies WHICH, through an operand. Without one the
//     driver refuses rather than inventing a target it would then bill for.
//
// The group NAME is the idempotency mechanism: CreateAutoScalingGroup takes no
// client token, and a deterministic name is what makes a lost create recoverable
// instead of duplicated.
package aws

import (
	"fmt"
	"regexp"
	"strings"
)

// asgVersion pins the Auto Scaling Query API this driver targets.
const asgVersion = "2011-01-01"

var (
	// asgLaunchTemplateOK bounds a launch-template id.
	asgLaunchTemplateOK = regexp.MustCompile(`^lt-[0-9a-f]{8,17}$`)
	// asgTemplateVersionOK bounds a launch-template version selector.
	asgTemplateVersionOK = regexp.MustCompile(`^([0-9]+|\$Latest|\$Default)$`)
)

// ASGPlan is the attribute-derived shape a create assembles.
type ASGPlan struct {
	Name              string // deterministic: the idempotency mechanism
	MinSize           int    // replicas.minimum — the capacity FLOOR
	MaxSize           int    // replicas.maximum — the capacity CEILING
	SubnetIDs         []string
	LaunchTemplateID  string
	TemplateVersion   string // "" leaves the template's default version
	Regional          bool   // declared; the subnets are what actually decide it
	WantPublic        bool   // declared; the launch template is what actually decides it
	PublicDeclared    bool   // whether the contract said anything at all about exposure
	AutoscalingWanted bool
	TargetCPUPercent  int // operand; the policy's only tuning, and only when wanted
	Tags              map[string]string
}

// BuildASGCreate maps capability.compute.autoscaling attributes + impl to a
// CreateAutoScalingGroup plan. Every error is a preflight refusal, never a silent
// drop.
func BuildASGCreate(environment, capability string,
	attrs, impl map[string]any, generation int) (ASGPlan, error) {

	p := ASGPlan{
		// CreateAutoScalingGroup takes no client token: the deterministic NAME is
		// the idempotency mechanism. ASG names allow 255 characters.
		Name: "groundhold-" + sanitizeTag(capability) + "-" + sanitizeTag(environment) +
			genSuffix(generation),
		MinSize: -1,
		MaxSize: -1,
		Tags: map[string]string{
			"groundhold-capability":  sanitizeTag(capability),
			"groundhold-environment": sanitizeTag(environment),
		},
	}
	declaredClass := ""

	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			// the region IS the driver scope (createScope); nothing goes in the body.
		case "availability.class":
			switch raw {
			case "zonal", "regional":
				declaredClass, _ = raw.(string)
				p.Regional = raw == "regional"
			default:
				return ASGPlan{}, fmt.Errorf(
					"availability.class %v has no Auto Scaling mapping (zonal or regional)", raw)
			}
		case "replicas.minimum":
			n, ok := intOperand(raw)
			if !ok || n < 0 {
				return ASGPlan{}, fmt.Errorf(
					"replicas.minimum must be a whole number of machines, got %v", raw)
			}
			p.MinSize = n
		case "replicas.maximum":
			n, ok := intOperand(raw)
			if !ok || n < 0 {
				return ASGPlan{}, fmt.Errorf(
					"replicas.maximum must be a whole number of machines, got %v", raw)
			}
			p.MaxSize = n
		case "autoscaling.enabled":
			b, ok := raw.(bool)
			if !ok {
				return ASGPlan{}, fmt.Errorf("autoscaling.enabled must be a bool, got %T", raw)
			}
			p.AutoscalingWanted = b
		case "network.publicExposure":
			b, ok := raw.(bool)
			if !ok {
				return ASGPlan{}, fmt.Errorf("network.publicExposure must be a bool, got %T", raw)
			}
			p.WantPublic, p.PublicDeclared = b, true
		case "service.managed":
			if raw != true {
				return ASGPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored — a group groundhold does not " +
						"own is an adoption, not a create")
			}
		default:
			return ASGPlan{}, fmt.Errorf(
				"attribute %s has no Auto Scaling mapping — refusing rather than silently "+
					"dropping it (the machine shape, the subnets and the scaling policy's "+
					"tuning are operands, not capability semantics)", path)
		}
	}
	// A group with no capacity envelope is not a group. Both bounds are required
	// because both are governed: the floor is availability, the ceiling is cost and
	// blast radius, and defaulting either would decide one of those for the operator.
	if p.MinSize < 0 || p.MaxSize < 0 {
		return ASGPlan{}, fmt.Errorf(
			"replicas.minimum and replicas.maximum are both required — the floor is an " +
				"availability decision and the ceiling is a cost and blast-radius decision, " +
				"and the driver makes neither")
	}
	if p.MinSize > p.MaxSize {
		return ASGPlan{}, fmt.Errorf(
			"replicas.minimum (%d) exceeds replicas.maximum (%d) — an envelope with no "+
				"interior cannot be satisfied by any fleet size", p.MinSize, p.MaxSize)
	}

	// --- OPERATOR operands (implementation block, D26) ---
	subnets, err := stringListOperand(impl, "subnet_ids")
	if err != nil {
		return ASGPlan{}, err
	}
	if len(subnets) == 0 {
		return ASGPlan{}, fmt.Errorf(
			"implementation.subnet_ids is required — the subnets place the fleet, and the " +
				"driver does not choose where machines run")
	}
	for _, s := range subnets {
		if !ec2SubnetOK.MatchString(s) {
			return ASGPlan{}, fmt.Errorf(
				"implementation.subnet_ids contains %q, which is not a subnet id", s)
		}
	}
	p.SubnetIDs = subnets

	// The class is a CONSEQUENCE of the subnets, so the two must agree. The count
	// is all the pure core can check; the shell checks that the zones are distinct,
	// which is the half that catches two subnets in one availability zone.
	switch declaredClass {
	case "regional":
		if len(subnets) < 2 {
			return ASGPlan{}, fmt.Errorf(
				"availability.class=regional needs subnets in more than one availability zone, "+
					"but implementation.subnet_ids names %d — a group spread over one zone does "+
					"not survive losing it", len(subnets))
		}
	case "zonal":
		if len(subnets) > 1 {
			return ASGPlan{}, fmt.Errorf(
				"availability.class=zonal contradicts %d subnets — the group would spread across "+
					"their zones and observe back as regional, so the contract would report a "+
					"violation it can never resolve", len(subnets))
		}
	}

	p.LaunchTemplateID = strings.TrimSpace(implString(impl, "launch_template_id"))
	if p.LaunchTemplateID == "" {
		return ASGPlan{}, fmt.Errorf(
			"implementation.launch_template_id is required — the template is the machine " +
				"shape (size, image, addressing), which the driver does not choose")
	}
	if !asgLaunchTemplateOK.MatchString(p.LaunchTemplateID) {
		return ASGPlan{}, fmt.Errorf(
			"implementation.launch_template_id %q is not a launch-template id", p.LaunchTemplateID)
	}
	if v := strings.TrimSpace(implString(impl, "launch_template_version")); v != "" {
		if !asgTemplateVersionOK.MatchString(v) {
			return ASGPlan{}, fmt.Errorf(
				"implementation.launch_template_version %q is not a version selector "+
					"(a number, $Latest or $Default)", v)
		}
		p.TemplateVersion = v
	}

	// A policy needs tuning the vocabulary deliberately excludes (D363), so the
	// operator supplies it. Inventing a target would attach a control loop nobody
	// reviewed to a fleet the operator pays for.
	if p.AutoscalingWanted {
		v, ok := impl["target_cpu_utilization"]
		if !ok {
			return ASGPlan{}, fmt.Errorf(
				"autoscaling.enabled=true requires implementation.target_cpu_utilization — the " +
					"contract governs THAT a scaling policy exists, never its tuning (D363), so " +
					"the target comes from the operator and the driver does not invent one")
		}
		n, ok := intOperand(v)
		if !ok || n <= 0 || n > 100 {
			return ASGPlan{}, fmt.Errorf(
				"implementation.target_cpu_utilization must be a percentage between 1 and 100, got %v", v)
		}
		p.TargetCPUPercent = n
	} else if _, ok := impl["target_cpu_utilization"]; ok {
		// A target with no policy to carry it is a request that will not happen, and
		// silence would leave the operator believing the fleet scales.
		return ASGPlan{}, fmt.Errorf(
			"implementation.target_cpu_utilization was supplied but autoscaling.enabled is not " +
				"true — the target would be ignored and the fleet would stay fixed-size")
	}
	return p, nil
}

// createBody is the CreateAutoScalingGroup Query body.
func (p ASGPlan) createBody() string {
	params := map[string]string{
		"Action":                          "CreateAutoScalingGroup",
		"Version":                         asgVersion,
		"AutoScalingGroupName":            p.Name,
		"MinSize":                         fmt.Sprintf("%d", p.MinSize),
		"MaxSize":                         fmt.Sprintf("%d", p.MaxSize),
		"VPCZoneIdentifier":               strings.Join(p.SubnetIDs, ","),
		"LaunchTemplate.LaunchTemplateId": p.LaunchTemplateID,
	}
	if p.TemplateVersion != "" {
		params["LaunchTemplate.Version"] = p.TemplateVersion
	}
	// DesiredCapacity is deliberately omitted: AWS starts the group at MinSize,
	// which is the floor the contract declared. Sending a desired size the contract
	// never mentioned would provision machines nobody asked for.
	i := 1
	for _, k := range sortedStringKeys(p.Tags) {
		params[fmt.Sprintf("Tags.member.%d.Key", i)] = k
		params[fmt.Sprintf("Tags.member.%d.Value", i)] = p.Tags[k]
		params[fmt.Sprintf("Tags.member.%d.PropagateAtLaunch", i)] = "true"
		i++
	}
	return encodeForm(params)
}

// policyBody is the PutScalingPolicy body — a target-tracking policy on average
// CPU. Only the TARGET is configurable, because only the target came from the
// operator; everything else about the policy is the service's default control
// loop, which is what "a policy exists" means here.
func (p ASGPlan) policyBody() string {
	return encodeForm(map[string]string{
		"Action":               "PutScalingPolicy",
		"Version":              asgVersion,
		"AutoScalingGroupName": p.Name,
		"PolicyName":           p.Name + "-cpu",
		"PolicyType":           "TargetTrackingScaling",
		"TargetTrackingConfiguration.PredefinedMetricSpecification.PredefinedMetricType": "ASGAverageCPUUtilization",
		"TargetTrackingConfiguration.TargetValue":                                        fmt.Sprintf("%d", p.TargetCPUPercent),
	})
}

// classifyASGChange (D46): PURE — can a capability.compute.autoscaling transition
// be honored in place?
//
// This is the first member of the compute family where most of the vocabulary IS
// mutable, and that is a real property of the resource rather than an oversight:
// resizing the envelope is what a group is FOR. UpdateAutoScalingGroup changes the
// bounds; a policy can be attached or removed at any time. What cannot change is
// where the fleet lives — the region is fixed, and the subnets (hence the zone
// spread) are set at creation.
func classifyASGChange(path string) (string, string) {
	switch path {
	case "replicas.minimum", "replicas.maximum":
		return "mutable", "UpdateAutoScalingGroup resizes the capacity envelope in place — resizing is what a group is for"
	case "autoscaling.enabled":
		return "mutable", "a scaling policy can be attached or removed on a live group"
	case "location.region":
		return "immutable", "a group is created in one region and cannot move — a region change is a new group"
	case "availability.class":
		// D822: this said the subnets are "fixed at creation". They are not —
		// UpdateAutoScalingGroup accepts VPCZoneIdentifier, AvailabilityZones and
		// AvailabilityZoneIds (botocore autoscaling/2011-01-01), and widening a group's
		// zone spread is an ordinary operation. Replacing the group to do it terminates
		// the running fleet for nothing.
		return "unsupported", "in-place zone-spread change is not wired for Auto Scaling " +
			"in this slice — AWS does support it (UpdateAutoScalingGroup takes " +
			"VPCZoneIdentifier / AvailabilityZones), so this is a gap in groundhold rather " +
			"than a reason to replace the group and its instances"
	case "network.publicExposure":
		// D822: the prose here is true — groundhold does not author launch templates — but
		// `immutable` means "no in-place change exists", and one does:
		// UpdateAutoScalingGroup takes a LaunchTemplate. A true sentence attached to a
		// verdict that destroys a running fleet is still a destroyed fleet.
		return "unsupported", "in-place exposure change is not wired for Auto Scaling in " +
			"this slice — public addressing lives in the launch template, which groundhold " +
			"does not author, and AWS does accept a new template version on a live group " +
			"(UpdateAutoScalingGroup): change the template rather than replace the group"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	}
	return "", ""
}
