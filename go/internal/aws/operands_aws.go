// The AWS half of the SILENT-IGNORE GUARD: per service, the exact set of
// candidate `implementation:` operand KEYS this driver reads. The block is
// free-form (D26), but an operand no driver consumes is refused at compile
// rather than silently dropped — the same fail-closed rule the per-attribute
// allowlists already enforce (BuildLambda's attribute switch ends in a
// `default:` refusal; the operand half lacked the twin, which this closes).
// Only TOP-LEVEL keys are declared: a map/list-valued operand (eks.nodeGroup,
// backupplan.selectionTags, vpc.baseline_sg_ingress, the *subnetIds lists, ...)
// is one key whose arbitrary subkeys/elements are read structurally, not by
// name. Keyed by the SERVICE token the candidate declares, parallel to
// awsOutputs/PermissionsFor: pure and table-driven.
package aws

import "groundhold/internal/provider"

// awsConsumedOperands: enumerated by reading every impl[...] read (inline and
// via the operand helpers implString/implStrings/implInt/acuOperand/intOperand/
// regionOperand/containerPortOperand) on the create, update and ClassifyChange
// paths of each of the 50 AWS service tokens. A service that reads no operand
// declares the empty set — any operand on it then refuses. Naming traps kept
// verbatim: ecr reads "kms_key" (not kms_key_id/kms_key_arn), and apprunner
// reads BOTH "auto_scaling_configuration_arn" and "autoScalingConfigurationArn".
var awsConsumedOperands = map[string][]string{
	"acm":            {},
	"apigateway":     {},
	"apprunner":      {"access_role_arn", "auto_scaling_configuration_arn", "autoScalingConfigurationArn", "cpu", "image", "image_repository_type", "memory", "port"},
	"aurora":         {"clusterParameterGroupName", "deletion_protection", "kmsKeyArn", "manageMasterUserPassword", "masterPassword", "masterUsername", "serverlessMaxACU", "serverlessMinACU", "serverlessSecondsUntilAutoPause", "subnetGroupName", "subnetIds", "vpcSecurityGroupIds"},
	"backupplan":     {"completionWindowMinutes", "copyDestinationVaultArn", "iamRoleArn", "scheduleExpression", "selectionResources", "selectionTags", "startWindowMinutes", "targetVaultName"},
	"backupvault":    {"kms_key_arn"},
	"bedrock":        {"inferenceProfileName", "modelSource"},
	"budgets":        {"notificationTopicArn"},
	"changefeed":     {"event_pattern"},
	"cloudfront":     {"aliases", "cache_policy", "certificate", "grant_invoke_lambda", "origin_access", "origin_domain"},
	"cloudtrail":     {"cloudWatchLogsGroupArn", "cloudWatchLogsRoleArn", "includeGlobalServiceEvents", "kmsKeyArn", "s3BucketName", "snsTopic", "trailName"},
	"cloudwatch":     {"notification_channel", "region"},
	"cloudwatchdash": {"region"},
	"custompolicy":   {},
	"cwlogfilter":    {"log_group", "region", "value_field"},
	"cwlogs":         {"kmsKeyArn", "log_group"},
	"dynamodb":       {"kms_key_id"},
	"ecr":            {"kms_key"},
	"ecs":            {"containerPort", "cpu", "execution_role_arn", "image", "memory", "security_groups", "subnets", "targetGroupArn"},
	"ec2":            {"image_id", "instance_type", "key_name", "kms_key_id", "root_volume_gb", "security_group_ids", "subnet_id"},
	"ebs":            {"availability_zone", "iops", "kms_key_id", "size_gb", "snapshot_id", "throughput", "volume_type"},
	// a witness has no operands: nothing is built, so there is nothing to configure
	"ami":                    {},
	"asg":                    {"launch_template_id", "launch_template_version", "subnet_ids", "target_cpu_utilization"},
	"efs":                    {"availability_zone", "kms_key_id"},
	"eks":                    {"clusterName", "clusterRoleArn", "kmsKeyArn", "nodeGroup", "nodeRoleArn", "securityGroupIds", "subnetIds"},
	"eks-addon":              {"clusterName", "region", "serviceRoleArn"},
	"eks-podidentity":        {"clusterName", "region", "roleArn"},
	"elasticache":            {"cache_subnet_group", "kms_key_id", "node_type", "subnetGroupName", "subnetIds"},
	"elasticache-serverless": {"kms_key_id", "securityGroupIds", "subnetIds"},
	"eventbridgescheduler":   {"role_arn", "schedule", "target_arn", "timezone"},
	"guardduty":              {"findingPublishingFrequency"},
	"iam":                    {"assume_role_policy", "roleName"},
	"kinesis":                {"kms_key_id"},
	"kms":                    {},
	"lambda":                 {"environment", "image_uri", "role_arn", "security_groups", "subnets", "url_auth"},
	"loadbalancer":           {"certificateArn", "healthCheckPath", "port", "region", "securityGroups", "subnets", "targetPort", "vpcId"},
	"msk":                    {"kms_key_id", "security_group_ids", "subnet_ids"},
	"opensearch":             {"engine_version", "instance_count", "kms_key_id", "security_group_ids", "subnet_ids"},
	"opensearch-serverless":  {"kms_key_arn", "kms_key_id", "vpc_endpoint_ids"},
	"rds":                    {"allocated_storage", "db_parameter_group", "db_subnet_group", "deletion_protection", "instance_class", "kms_key_id", "master_password", "master_username"},
	"redshiftserverless":     {"kms_key_id"},
	"rolepolicy":             {"principal"},
	"route53":                {"vpc_id", "vpc_region"},
	"route53health":          {"port"},
	"route53record":          {"record_name", "zone_id"},
	"s3":                     {"kms_key_id", "replication_destination_bucket_arn", "replication_role_arn"},
	"secretsmanager":         {"kms_key_id"},
	"ses-inbound":            {"recipientDomain", "ruleName", "ruleSetName", "s3BucketName", "s3ObjectKeyPrefix", "snsTopicArn"},
	"ses-sending":            {"bounceTopicArn", "configurationSetName", "domain"},
	"sns":                    {"kms_key_id"},
	"sqs":                    {"dead_letter_target_arn", "kms_key_id", "max_receive_count"},
	"vpc":                    {"availability_zones", "baseline_sg", "baseline_sg_ingress", "cidr", "flow_log_destination", "flow_log_role_arn", "public_subnet_cidr", "public_subnet_cidrs", "subnet_cidr", "subnet_cidrs", "vpc_endpoints"},
	"vpngateway":             {},
	"waf":                    {},
}

// ConsumedOperands implements provider.OperandConsumer (the operand twin of
// OutputsFor): the compiler refuses any implementation operand not in this set.
func (d *Driver) ConsumedOperands(service string) []string {
	return awsConsumedOperands[service]
}

var _ provider.OperandConsumer = (*Driver)(nil)
