// EC2 instance request building (D358): the semantic core of the AWS
// capability.compute.instance driver — the SAME vocabulary GCE instances and
// Azure VMs fulfil.
//
// A machine is the canonical "pet", so the split between capability and operand
// matters more here than anywhere else. What the CONTRACT governs: residency,
// whether a public path exists, whether the disks are encrypted with a
// customer-revocable key. What the OPERATOR supplies (D26): the instance type,
// the image, the subnet, the key pair, the security groups — sizing and topology,
// which are implementation noise no matter how strongly anyone feels about them.
// The driver INVENTS NONE of them: there is no default instance type and no
// default image, because guessing either would provision something nobody asked
// for and bill for it.
//
// availability.class=regional is REFUSED, not silently downgraded. A single
// instance is placed in exactly one availability zone (the subnet's); regional
// placement is a property of an autoscaling GROUP, a different capability. An
// attribute the driver cannot honor refuses at Validate, before any mutation.
//
// The InstanceId is SERVER-ASSIGNED, so the providerId is parsed from the
// response; a deterministic ClientToken is the idempotency key that lets a lost
// create be recovered rather than duplicated.
package aws

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// ec2AMIOK bounds an image id before it is placed in a request.
	ec2AMIOK = regexp.MustCompile(`^ami-[0-9a-f]{8,17}$`)
	// ec2SubnetOK bounds a subnet id (the subnet fixes both VPC and AZ).
	ec2SubnetOK = regexp.MustCompile(`^subnet-[0-9a-f]{8,17}$`)
	// ec2SGOK bounds a security-group id.
	ec2SGOK = regexp.MustCompile(`^sg-[0-9a-f]{8,17}$`)
	// ec2InstanceTypeOK bounds a type token (family.size).
	ec2InstanceTypeOK = regexp.MustCompile(`^[a-z][a-z0-9-]*\.[a-z0-9]+$`)
	// ec2KeyNameOK bounds a key-pair name.
	ec2KeyNameOK = regexp.MustCompile(`^[A-Za-z0-9_.@:/+=-]{1,255}$`)
)

// EC2InstancePlan is the attribute-derived shape a create assembles into the
// RunInstances Query body.
type EC2InstancePlan struct {
	ClientToken    string // deterministic idempotency key
	InstanceType   string // operand — no default, ever
	ImageID        string // operand — no default, ever
	SubnetID       string // operand — fixes the VPC and the availability zone
	PublicIP       bool   // network.publicExposure
	Encrypted      bool   // encryption.atRest on the root volume
	KmsKeyID       string // CMEK; "" = the account's default EBS key
	KeyName        string // optional key pair
	SecurityGroups []string
	RootVolumeGB   int // optional; 0 = the image's default size
	Tags           map[string]string
}

// BuildEC2InstanceCreate maps capability.compute.instance attributes + impl to a
// RunInstances plan. Every error is a preflight refusal, never a silent drop.
func BuildEC2InstanceCreate(environment, capability string,
	attrs, impl map[string]any, generation int) (EC2InstancePlan, error) {

	p := EC2InstancePlan{
		ClientToken: "groundhold-" + letterHash(environment+"|"+capability+genSuffix(generation), 24),
		Encrypted:   true, // encrypted unless the contract explicitly says otherwise
		Tags: map[string]string{
			"groundhold-capability":  sanitizeTag(capability),
			"groundhold-environment": sanitizeTag(environment),
		},
	}
	cmk := false

	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			// the region IS the driver scope (createScope); nothing goes in the body.
		case "availability.class":
			switch raw {
			case "zonal":
				// the subnet fixes the zone; nothing else to place.
			case "regional":
				return EC2InstancePlan{}, fmt.Errorf(
					"availability.class=regional cannot be honored by a single EC2 instance " +
						"(an instance lives in exactly one availability zone — regional placement " +
						"is a property of an autoscaling group, a different capability)")
			default:
				return EC2InstancePlan{}, fmt.Errorf(
					"availability.class %v has no EC2 mapping (zonal only for an instance)", raw)
			}
		case "network.publicExposure":
			b, ok := raw.(bool)
			if !ok {
				return EC2InstancePlan{}, fmt.Errorf("network.publicExposure must be a bool, got %T", raw)
			}
			p.PublicIP = b
		case "encryption.atRest":
			b, ok := raw.(bool)
			if !ok {
				return EC2InstancePlan{}, fmt.Errorf("encryption.atRest must be a bool, got %T", raw)
			}
			p.Encrypted = b
		case "encryption.customerManagedKeys":
			if raw == true {
				cmk = true
				p.KmsKeyID = strings.TrimSpace(implString(impl, "kms_key_id"))
				if p.KmsKeyID == "" {
					return EC2InstancePlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_id " +
							"(the account's default EBS key is AWS-managed, not customer-managed)")
				}
			}
		case "service.managed":
			if raw != true {
				return EC2InstancePlan{}, fmt.Errorf(
					"service.managed=false cannot be honored — an instance groundhold does not " +
						"own is an adoption, not a create")
			}
		default:
			return EC2InstancePlan{}, fmt.Errorf(
				"attribute %s has no EC2 mapping — refusing rather than silently dropping it "+
					"(instance type, image, subnet, key pair and security groups are operands, "+
					"not capability semantics)", path)
		}
	}

	// A customer-managed key on an unencrypted volume is a contradiction, and
	// honoring either half silently would misreport the other.
	if cmk && !p.Encrypted {
		return EC2InstancePlan{}, fmt.Errorf(
			"encryption.customerManagedKeys=true with encryption.atRest=false is contradictory " +
				"— a key cannot encrypt a volume that is not encrypted")
	}

	// --- OPERATOR operands (implementation block, D26) ---
	p.InstanceType = strings.TrimSpace(implString(impl, "instance_type"))
	if p.InstanceType == "" {
		return EC2InstancePlan{}, fmt.Errorf(
			"implementation.instance_type is required — the driver does not choose a size " +
				"(a guessed instance type provisions capacity nobody asked for, and bills for it)")
	}
	if !ec2InstanceTypeOK.MatchString(p.InstanceType) {
		return EC2InstancePlan{}, fmt.Errorf(
			"implementation.instance_type %q is not a valid EC2 instance type", p.InstanceType)
	}
	p.ImageID = strings.TrimSpace(implString(impl, "image_id"))
	if p.ImageID == "" {
		return EC2InstancePlan{}, fmt.Errorf(
			"implementation.image_id is required — the driver does not choose an image " +
				"(what runs on the machine is the operator's decision, never a default)")
	}
	if !ec2AMIOK.MatchString(p.ImageID) {
		return EC2InstancePlan{}, fmt.Errorf(
			"implementation.image_id %q is not a valid AMI id", p.ImageID)
	}
	p.SubnetID = strings.TrimSpace(implString(impl, "subnet_id"))
	if p.SubnetID == "" {
		return EC2InstancePlan{}, fmt.Errorf(
			"implementation.subnet_id is required — the subnet fixes both the VPC and the " +
				"availability zone, and neither may be inferred")
	}
	if !ec2SubnetOK.MatchString(p.SubnetID) {
		return EC2InstancePlan{}, fmt.Errorf(
			"implementation.subnet_id %q is not a valid subnet id", p.SubnetID)
	}
	if kn := strings.TrimSpace(implString(impl, "key_name")); kn != "" {
		if !ec2KeyNameOK.MatchString(kn) {
			return EC2InstancePlan{}, fmt.Errorf(
				"implementation.key_name %q is not a valid key-pair name", kn)
		}
		p.KeyName = kn
	}
	sgs, err := stringListOperand(impl, "security_group_ids")
	if err != nil {
		return EC2InstancePlan{}, err
	}
	for _, sg := range sgs {
		if !ec2SGOK.MatchString(sg) {
			return EC2InstancePlan{}, fmt.Errorf(
				"implementation.security_group_ids contains %q, which is not a security-group id", sg)
		}
	}
	p.SecurityGroups = sgs
	if v, ok := impl["root_volume_gb"]; ok {
		n, ok := intOperand(v)
		if !ok || n <= 0 {
			return EC2InstancePlan{}, fmt.Errorf(
				"implementation.root_volume_gb must be a positive whole number of GiB, got %v", v)
		}
		p.RootVolumeGB = n
	}
	return p, nil
}

// stringListOperand reads an optional list-of-strings operand, refusing a scalar
// or a non-string element rather than coercing it.
func stringListOperand(impl map[string]any, key string) ([]string, error) {
	raw, ok := impl[key]
	if !ok {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("implementation.%s must be a list, got %T", key, raw)
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("implementation.%s must contain strings, got %T", key, e)
		}
		out = append(out, strings.TrimSpace(s))
	}
	return out, nil
}

// createBody is the RunInstances Query body. Ownership is tags, so
// groundholdTagsMatch holds on the resource the response names.
func (p EC2InstancePlan) createBody() string {
	extra := map[string]string{
		"ImageId":      p.ImageID,
		"InstanceType": p.InstanceType,
		"MinCount":     "1",
		"MaxCount":     "1",
		"ClientToken":  p.ClientToken,
		// The subnet and the public-IP decision live on the primary network
		// interface: setting AssociatePublicIpAddress requires the interface form,
		// and mixing it with a top-level SubnetId is an API error.
		"NetworkInterface.1.DeviceIndex":               "0",
		"NetworkInterface.1.SubnetId":                  p.SubnetID,
		"NetworkInterface.1.AssociatePublicIpAddress":  boolParam(p.PublicIP),
		"NetworkInterface.1.DeleteOnTermination":       "true",
		"BlockDeviceMapping.1.DeviceName":              "/dev/xvda",
		"BlockDeviceMapping.1.Ebs.Encrypted":           boolParam(p.Encrypted),
		"BlockDeviceMapping.1.Ebs.DeleteOnTermination": "true",
	}
	if p.KmsKeyID != "" {
		extra["BlockDeviceMapping.1.Ebs.KmsKeyId"] = p.KmsKeyID
	}
	if p.RootVolumeGB > 0 {
		extra["BlockDeviceMapping.1.Ebs.VolumeSize"] = fmt.Sprintf("%d", p.RootVolumeGB)
	}
	if p.KeyName != "" {
		extra["KeyName"] = p.KeyName
	}
	for i, sg := range p.SecurityGroups {
		extra[fmt.Sprintf("NetworkInterface.1.SecurityGroupId.%d", i+1)] = sg
	}
	return encodeForm(ec2ActionParams("RunInstances", "instance", p.Tags, extra))
}

// boolParam renders a Query-API boolean.
func boolParam(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// classifyEC2InstanceChange (D46): PURE — can a capability.compute.instance
// transition be honored in place?
//
// Almost nothing about a machine is patchable, and saying so plainly is the
// honest answer rather than a limitation. A region is fixed at launch; the
// subnet fixes the availability zone; EBS encryption and its key are properties
// of a volume at CREATION, not settings. Each of these is a NEW machine, which
// means replacement — and because the type is stateful (D47), that replacement
// needs explicit consent instead of happening quietly.
func classifyEC2InstanceChange(path string) (string, string) {
	switch path {
	case "location.region":
		return "immutable", "an instance is created in one region and cannot move — a region change is a new machine"
	case "availability.class":
		return "immutable", "placement is fixed by the subnet the instance launched into — a change is a new machine"
	case "network.publicExposure":
		return "immutable", "the public-address association is made at launch on the primary interface — a change is a new machine, not a toggle"
	case "encryption.atRest":
		return "immutable", "EBS encryption is a property of a volume at creation — an existing volume cannot be encrypted in place"
	case "encryption.customerManagedKeys":
		return "immutable", "the key encrypting a volume is fixed when the volume is created — re-keying is a new volume, and so a new machine"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	}
	return "", ""
}
