package aws

import "testing"

// D821. `immutable` is not an opinion about how fundamental an attribute feels. It tells
// the compiler an in-place change is impossible, so the plan carries a DESTROY AND
// RECREATE — and for these resources that means losing a machine, or a stateful search
// collection, to change a network toggle.
//
// Three of these claims said something about the CLOUD, and the cloud's own API contradicts
// it. The distinction matters, because the sibling claims are NOT defects: ASG and App
// Runner say public addressing lives in a launch template or an ingress groundhold does not
// author, which is a true statement about this tool's scope. Saying "a change is a new
// machine, not a toggle" is a different kind of sentence, and it is false.
//
// The fix is the smallest honest one under the freeze: stop claiming a replacement is
// REQUIRED. `unsupported` blocks the capability with a reason that names the operation the
// provider has, so a person is told what is true and what groundhold does not do — instead
// of being told to destroy a machine.
func TestNoDriverClaimsAReplacementTheProviderDoesNotRequire(t *testing.T) {
	for _, c := range []struct {
		name    string
		got     func() (string, string)
		because string
	}{
		{"ec2-instance", func() (string, string) {
			return classifyEC2InstanceChange("network.publicExposure")
		}, "EC2 ModifyNetworkInterfaceAttribute takes AssociatePublicIpAddress, and " +
			"AssociateAddress/DisassociateAddress attach and detach an elastic address on a " +
			"running instance (botocore ec2/2016-11-15)"},
		{"asg-zone-spread", func() (string, string) {
			return classifyASGChange("availability.class")
		}, "UpdateAutoScalingGroup accepts VPCZoneIdentifier, AvailabilityZones and " +
			"AvailabilityZoneIds, so a group's zone spread is an ordinary update " +
			"(botocore autoscaling/2011-01-01)"},
		{"ec2-rekeying", func() (string, string) {
			return classifyEC2InstanceChange("encryption.customerManagedKeys")
		}, "re-keying an EBS volume does need a NEW VOLUME (CreateSnapshot, CopySnapshot " +
			"with the new key), but DetachVolume and AttachVolume swap it under an instance " +
			"that keeps its id and its addresses (botocore ec2/2016-11-15)"},
		{"ec2-encrypt-at-rest", func() (string, string) {
			return classifyEC2InstanceChange("encryption.atRest")
		}, "an existing EBS volume cannot be encrypted in place, so the VOLUME is replaced " +
			"(snapshot, CopySnapshot with encryption, AttachVolume) — the instance is not"},
		{"elasticache-serverless-engine", func() (string, string) {
			return classifyElastiCacheServerlessChange("engine.protocol")
		}, "ModifyServerlessCache accepts Engine and MajorEngineVersion " +
			"(botocore elasticache/2015-02-02)"},
		{"apprunner-ingress", func() (string, string) {
			return classifyAppRunnerChange("network.publicExposure")
		}, "UpdateService accepts NetworkConfiguration, so App Runner's ingress is an " +
			"ordinary update (botocore apprunner/2020-05-15)"},
		{"opensearch-serverless", func() (string, string) {
			return classifyOpenSearchServerlessChange("network.publicExposure")
		}, "the exposure is read from the network POLICY document, and UpdateSecurityPolicy " +
			"replaces that document without touching the collection " +
			"(botocore opensearchserverless/2021-11-01)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			class, reason := c.got()
			if class == "immutable" {
				t.Fatalf("classified immutable (%q), so the plan destroys and recreates the "+
					"resource — but %s", reason, c.because)
			}
			if reason == "" {
				t.Fatal("a refusal with no reason sends nobody anywhere")
			}
		})
	}
}
