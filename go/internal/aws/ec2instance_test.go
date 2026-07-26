package aws

import (
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// baseAttrs/baseImpl are the minimum a create needs: the contract's four
// governed facts, and the four operands the driver refuses to invent.
func ec2Attrs() map[string]any {
	return map[string]any{
		"location.region":                "eu-central-1",
		"availability.class":             "zonal",
		"network.publicExposure":         false,
		"encryption.atRest":              true,
		"encryption.customerManagedKeys": false,
		"service.managed":                true,
	}
}

func ec2Impl() map[string]any {
	return map[string]any{
		"instance_type": "m6i.large",
		"image_id":      "ami-0123456789abcdef0",
		"subnet_id":     "subnet-0abc123456789def0",
	}
}

// parseForm turns the encoded Query body back into params so a golden assertion
// reads as facts about the REQUEST rather than about string concatenation.
func ec2RunForm(t *testing.T, body string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(body)
	if err != nil {
		t.Fatalf("body is not a valid form encoding: %v", err)
	}
	return v
}

func TestBuildEC2InstanceCreateGolden(t *testing.T) {
	p, err := BuildEC2InstanceCreate("production", "web", ec2Attrs(), ec2Impl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got := ec2RunForm(t, p.createBody())

	want := map[string]string{
		"Action":                         "RunInstances",
		"ImageId":                        "ami-0123456789abcdef0",
		"InstanceType":                   "m6i.large",
		"MinCount":                       "1",
		"MaxCount":                       "1",
		"NetworkInterface.1.DeviceIndex": "0",
		"NetworkInterface.1.SubnetId":    "subnet-0abc123456789def0",
		"NetworkInterface.1.AssociatePublicIpAddress": "false",
		"BlockDeviceMapping.1.Ebs.Encrypted":          "true",
		"TagSpecification.1.ResourceType":             "instance",
	}
	for k, v := range want {
		if got.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, got.Get(k), v)
		}
	}
	// Ownership tags must be present, or a 409 continuation cannot tell our
	// instance from someone else's.
	tags := map[string]string{}
	for i := 1; i <= 4; i++ {
		k := got.Get("TagSpecification.1.Tag." + strconv.Itoa(i) + ".Key")
		if k == "" {
			break
		}
		tags[k] = got.Get("TagSpecification.1.Tag." + strconv.Itoa(i) + ".Value")
	}
	if tags["groundhold-capability"] != "web" || tags["groundhold-environment"] != "production" {
		t.Errorf("ownership tags missing or wrong: %v", tags)
	}
	// No key pair, no security groups, no explicit volume size were supplied, so
	// none may appear — a driver that invents them provisions what nobody asked for.
	for _, absent := range []string{"KeyName", "BlockDeviceMapping.1.Ebs.VolumeSize",
		"BlockDeviceMapping.1.Ebs.KmsKeyId", "NetworkInterface.1.SecurityGroupId.1"} {
		if got.Get(absent) != "" {
			t.Errorf("%s appeared uninvited: %q", absent, got.Get(absent))
		}
	}
}

// The ClientToken is the idempotency key: a lost create must be recoverable, so
// the same inputs must produce the same token, and a different generation must not.
func TestEC2InstanceClientTokenIsDeterministic(t *testing.T) {
	a, err := BuildEC2InstanceCreate("production", "web", ec2Attrs(), ec2Impl(), 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildEC2InstanceCreate("production", "web", ec2Attrs(), ec2Impl(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if a.ClientToken != b.ClientToken {
		t.Errorf("token is not deterministic: %q vs %q", a.ClientToken, b.ClientToken)
	}
	// The -gN discriminator starts at 2 by project convention (D48): generations 0
	// and 1 are the same original, so the token must differ from generation 2 on.
	c, err := BuildEC2InstanceCreate("production", "web", ec2Attrs(), ec2Impl(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if a.ClientToken == c.ClientToken {
		t.Error("generation 2 reused the original's token — a replacement would be " +
			"treated as a retry of the instance it replaces")
	}
}

func TestBuildEC2InstanceCreateRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(attrs, impl map[string]any)
		want   string
	}{
		{"regional placement", func(a, _ map[string]any) {
			a["availability.class"] = "regional"
		}, "availability.class=regional cannot be honored"},
		{"unknown availability class", func(a, _ map[string]any) {
			a["availability.class"] = "planet-scale"
		}, "has no EC2 mapping"},
		{"unmapped attribute", func(a, _ map[string]any) {
			a["replicas.minimum"] = 3
		}, "has no EC2 mapping"},
		{"cmk without a key", func(a, i map[string]any) {
			a["encryption.customerManagedKeys"] = true
			delete(i, "kms_key_id")
		}, "requires implementation.kms_key_id"},
		{"cmk on an unencrypted volume", func(a, i map[string]any) {
			a["encryption.customerManagedKeys"] = true
			a["encryption.atRest"] = false
			i["kms_key_id"] = "arn:aws:kms:eu-central-1:000000000000:key/abc"
		}, "contradictory"},
		{"self-operated", func(a, _ map[string]any) {
			a["service.managed"] = false
		}, "cannot be honored"},
		{"no instance type", func(_, i map[string]any) {
			delete(i, "instance_type")
		}, "instance_type is required"},
		{"bogus instance type", func(_, i map[string]any) {
			i["instance_type"] = "enormous"
		}, "not a valid EC2 instance type"},
		{"no image", func(_, i map[string]any) {
			delete(i, "image_id")
		}, "image_id is required"},
		{"bogus image", func(_, i map[string]any) {
			i["image_id"] = "ubuntu-latest"
		}, "not a valid AMI id"},
		{"no subnet", func(_, i map[string]any) {
			delete(i, "subnet_id")
		}, "subnet_id is required"},
		{"bogus subnet", func(_, i map[string]any) {
			i["subnet_id"] = "vpc-0123456789abcdef0"
		}, "not a valid subnet id"},
		{"bogus security group", func(_, i map[string]any) {
			i["security_group_ids"] = []any{"sg-0123456789abcdef0", "open-to-the-world"}
		}, "not a security-group id"},
		{"security groups not a list", func(_, i map[string]any) {
			i["security_group_ids"] = "sg-0123456789abcdef0"
		}, "must be a list"},
		{"negative volume", func(_, i map[string]any) {
			i["root_volume_gb"] = -8
		}, "positive whole number"},
		{"exposure is not a bool", func(a, _ map[string]any) {
			a["network.publicExposure"] = "yes"
		}, "must be a bool"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs, impl := ec2Attrs(), ec2Impl()
			tc.mutate(attrs, impl)
			_, err := BuildEC2InstanceCreate("production", "web", attrs, impl, 0)
			if err == nil {
				t.Fatalf("expected a refusal, got a plan — a silently dropped attribute " +
					"is the one unforgivable bug")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal does not explain itself:\n got: %v\nwant substring: %q", err, tc.want)
			}
		})
	}
}

// A public instance is one flag away from a private one, so the flag must reach
// the request verbatim in both directions.
func TestEC2InstancePublicExposureReachesTheRequest(t *testing.T) {
	for _, public := range []bool{true, false} {
		attrs := ec2Attrs()
		attrs["network.publicExposure"] = public
		p, err := BuildEC2InstanceCreate("production", "web", attrs, ec2Impl(), 0)
		if err != nil {
			t.Fatal(err)
		}
		got := ec2RunForm(t, p.createBody()).Get("NetworkInterface.1.AssociatePublicIpAddress")
		want := "false"
		if public {
			want = "true"
		}
		if got != want {
			t.Errorf("publicExposure=%v produced AssociatePublicIpAddress=%q, want %q",
				public, got, want)
		}
	}
}

// The optional operands appear only when supplied, and verbatim when they are.
func TestEC2InstanceOptionalOperands(t *testing.T) {
	attrs, impl := ec2Attrs(), ec2Impl()
	attrs["encryption.customerManagedKeys"] = true
	impl["kms_key_id"] = "arn:aws:kms:eu-central-1:000000000000:key/abc"
	impl["key_name"] = "ops-bastion"
	impl["root_volume_gb"] = 64
	impl["security_group_ids"] = []any{"sg-0123456789abcdef0", "sg-0fedcba9876543210"}

	p, err := BuildEC2InstanceCreate("production", "web", attrs, impl, 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got := ec2RunForm(t, p.createBody())
	for k, want := range map[string]string{
		"BlockDeviceMapping.1.Ebs.KmsKeyId":    "arn:aws:kms:eu-central-1:000000000000:key/abc",
		"BlockDeviceMapping.1.Ebs.VolumeSize":  "64",
		"KeyName":                              "ops-bastion",
		"NetworkInterface.1.SecurityGroupId.1": "sg-0123456789abcdef0",
		"NetworkInterface.1.SecurityGroupId.2": "sg-0fedcba9876543210",
	} {
		if got.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, got.Get(k), want)
		}
	}
}
