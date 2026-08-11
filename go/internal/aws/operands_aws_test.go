package aws

import (
	"sort"
	"testing"
)

// TestConsumedOperands_KnownServices pins the exact operand set for a sample of
// services spanning the naming traps called out in operands_aws.go: ecr's
// "kms_key" (not kms_key_id/kms_key_arn), and apprunner's BOTH
// "auto_scaling_configuration_arn" and "autoScalingConfigurationArn". A drift here
// silently reopens the SILENT-IGNORE GUARD this registry exists to close.
func TestConsumedOperands_KnownServices(t *testing.T) {
	d := NewDriver("eu-central-1")
	cases := map[string][]string{
		"aurora": {"clusterParameterGroupName", "deletion_protection", "kmsKeyArn",
			"manageMasterUserPassword", "masterPassword", "masterUsername", "serverlessMaxACU",
			"serverlessMinACU", "serverlessSecondsUntilAutoPause", "subnetGroupName", "subnetIds",
			"vpcSecurityGroupIds"},
		"lambda":         {"architectures", "environment", "image_uri", "invokers", "role_arn", "security_groups", "subnets", "url_auth"},
		"secretsmanager": {"kms_key_id"},
		"cwlogs":         {"kmsKeyArn", "log_group"},
		"ses-inbound": {"recipientDomain", "ruleName", "ruleSetName", "s3BucketName",
			"s3ObjectKeyPrefix", "snsTopicArn"},
		"ecr":       {"kms_key"},
		"apprunner": {"access_role_arn", "auto_scaling_configuration_arn", "autoScalingConfigurationArn", "cpu", "image", "image_repository_type", "memory", "port"},
		// naming trap: EBS sizes with size_gb while the same disk as an EC2 boot
		// operand is root_volume_gb, and the key is kms_key_id on both.
		"ebs": {"availability_zone", "iops", "kms_key_id", "size_gb", "snapshot_id", "throughput", "volume_type"},
		// zero-operand services declare the empty set, not nil-with-a-panic.
		"acm": {}, "kms": {}, "waf": {}, "vpngateway": {}, "custompolicy": {},
	}
	for svc, want := range cases {
		got := d.ConsumedOperands(svc)
		if len(got) != len(want) {
			t.Errorf("%s: ConsumedOperands = %v, want %v", svc, got, want)
			continue
		}
		gotSorted := append([]string(nil), got...)
		wantSorted := append([]string(nil), want...)
		sort.Strings(gotSorted)
		sort.Strings(wantSorted)
		for i := range gotSorted {
			if gotSorted[i] != wantSorted[i] {
				t.Errorf("%s: ConsumedOperands = %v, want %v", svc, got, want)
				break
			}
		}
	}
}

// TestConsumedOperands_UnknownServiceIsEmpty: a service token the registry does
// not recognize returns the empty set (nil), which the compiler's refusal guard
// (D307) treats as "consumes nothing" — any operand on it refuses. This is the
// fail-closed default, never a panic or a wildcard allow.
func TestConsumedOperands_UnknownServiceIsEmpty(t *testing.T) {
	d := NewDriver("eu-central-1")
	if got := d.ConsumedOperands("no-such-service"); len(got) != 0 {
		t.Fatalf("unknown service must consume nothing, got %v", got)
	}
}

// TestConsumedOperands_EveryListIsSortedAndUnique: the registry's own internal
// invariant — each operand list is maintained sorted with no duplicates, which is
// what makes the table scannable/diffable by hand. A violation here is a real
// authoring bug in the registry (a duplicate key or a mis-sorted addition).
func TestConsumedOperands_EveryListIsSortedAndUnique(t *testing.T) {
	d := NewDriver("eu-central-1")
	for _, svc := range []string{
		// apprunner is excluded: it deliberately carries BOTH
		// "auto_scaling_configuration_arn" and "autoScalingConfigurationArn" (a
		// naming trap, not a sort violation — ASCII orders '_' after 'S').
		"acm", "apigateway", "aurora", "backupplan", "backupvault", "bedrock",
		"budgets", "changefeed", "cloudfront", "cloudtrail", "cloudwatch", "cloudwatchdash",
		"custompolicy", "cwlogfilter", "cwlogs", "dynamodb", "ecr", "ecs", "efs", "eks",
		"eks-addon", "eks-podidentity", "elasticache", "elasticache-serverless",
		"eventbridgescheduler", "guardduty", "iam", "kinesis", "kms", "lambda", "loadbalancer",
		"msk", "opensearch", "opensearch-serverless", "rds", "redshiftserverless", "rolepolicy",
		"route53", "route53health", "route53record", "s3", "secretsmanager", "ses-inbound",
		"ses-sending", "sns", "sqs", "vpc", "vpngateway", "waf",
	} {
		ops := d.ConsumedOperands(svc)
		seen := map[string]bool{}
		for i, k := range ops {
			if seen[k] {
				t.Errorf("%s: duplicate operand key %q", svc, k)
			}
			seen[k] = true
			if i > 0 && ops[i-1] >= k {
				t.Errorf("%s: operand list not sorted: %q before %q", svc, ops[i-1], k)
			}
		}
	}
}

// TestConsumedOperands_ImplementsOperandConsumer guards the interface wiring
// itself: the compiler's SILENT-IGNORE GUARD type-asserts provider.OperandConsumer
// off the driver — a regression here would silently disable the whole guard for AWS.
func TestConsumedOperands_ImplementsOperandConsumer(t *testing.T) {
	var d any = NewDriver("eu-central-1")
	oc, ok := d.(interface{ ConsumedOperands(string) []string })
	if !ok {
		t.Fatal("*Driver must implement ConsumedOperands(string) []string")
	}
	if got := oc.ConsumedOperands("aurora"); len(got) == 0 {
		t.Fatal("aurora must declare a non-empty consumed-operand set")
	}
}
