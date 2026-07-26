// The AWS driver's provider.Provider implementation (D86): dispatch on the
// SERVICE token (s3 wired; rds/ecs pending), fail-closed on unknown — the same
// discipline as the GCP driver (D76). Only s3 is live; rds/ecs return an
// honest "not wired" until their slices land.
package aws

import (
	"fmt"

	"groundhold/internal/provider"
)

func (d *Driver) requireService(service string) error {
	switch service {
	case "s3", "rds", "ecs", "apprunner", "vpc", "sns", "sqs", "secretsmanager", "elasticache", "elasticache-serverless", "route53", "route53record", "rolepolicy", "custompolicy", "cloudwatch", "cloudwatchdash", "route53health", "cwlogfilter", "ecr", "efs", "dynamodb", "opensearch", "opensearch-serverless", "kinesis", "msk", "waf", "acm", "cloudfront", "apigateway", "iam", "redshiftserverless", "eventbridgescheduler", "kms", "vpngateway", "backupvault", "changefeed", "loadbalancer", "eks", "eks-addon", "eks-podidentity", "ses-sending", "ses-inbound", "aurora", "bedrock", "budgets", "cloudtrail", "backupplan", "guardduty", "cwlogs", "lambda", "ec2", "ebs", "ami":
		if d.Region != "" && !regionOK.MatchString(d.Region) {
			return fmt.Errorf("aws driver: pinned region %q is not valid", d.Region)
		}
		return nil
	default:
		return fmt.Errorf("aws driver: unknown service %q — refusing (no default)", service)
	}
}

// isGlobalService: AWS services with no regional endpoint OR whose region rides in the
// implementation block, not the vocab. Route 53 / IAM are global; cloudwatch alarms,
// cloudwatch dashboards, Route 53 health checks and CloudWatch Logs metric filters are
// region-free at the vocab gate (their region, if any, is an implementation detail), so
// the apply-time location.region gate must not demand one.
// (Shared across D103/D104/D105; cloudwatch D106, cloudwatchdash D107, route53health
// D108, cwlogfilter D109.)
func isGlobalService(service string) bool {
	return service == "route53" || service == "route53record" || service == "rolepolicy" ||
		service == "custompolicy" || service == "cloudwatch" ||
		service == "cloudwatchdash" || service == "route53health" ||
		service == "cwlogfilter" || service == "waf" || service == "cloudfront" ||
		service == "iam" || service == "changefeed" || service == "budgets" ||
		// D279: vocab-region-free capabilities (their vocab declares no
		// location.region, so a candidate CANNOT satisfy the attrs gate — the
		// region is an implementation operand, typically {$ref: eks.region} /
		// {$ref: <vpc>.region})
		service == "eks-addon" || service == "eks-podidentity" || service == "loadbalancer"
}

// resolveAccount caches the acting identity's account id (via STS). Used for the
// globally-unique bucket name; the account is also in the D82 squat defense that
// AWS answers directly via BucketAlreadyOwnedByYou.
func (d *Driver) resolveAccount() (string, error) {
	if d.Account != "" {
		return d.Account, nil
	}
	acct, _, err := d.CallerIdentity()
	if err != nil {
		return "", fmt.Errorf("resolve account: %v", err)
	}
	d.Account = acct
	return acct, nil
}

func (d *Driver) Validate(service, capability, environment string,
	attrs, impl map[string]any, generation int) error {
	if err := d.requireService(service); err != nil {
		return err
	}
	// A WITNESS service (D177/D370) is refused FIRST, before any operand check. The
	// reason a witness create is refused has nothing to do with the region, and an
	// operator told "location.region is missing" would go and add one — then hit the
	// real refusal on the next run. The first thing said should be the true thing.
	if !provider.CanAuthor("aws", service) {
		return errWitnessOnly(service, "this capability")
	}
	// refuse an invalid/missing region here (refuse-before-mutate) exactly as
	// createScope does at apply — the builders don't all enforce regionOK. Only for
	// services whose region rides in the vocab (location.region); global / vocab-region-free
	// services (incl. WAFv2 CLOUDFRONT-scope, CloudFront and IAM roles) are exempt.
	if !isGlobalService(service) {
		if r, _ := attrs["location.region"].(string); !regionOK.MatchString(r) {
			return fmt.Errorf("location.region %q is missing or not a valid AWS region", r)
		}
	}
	switch service {
	case "s3":
		// account only affects the bucket NAME, not attribute honorability —
		// build with a placeholder so Validate needs no network (D85: the
		// account belongs in the plan scope, resolved at create time).
		_, err := BuildS3Requests("validate", environment, capability, attrs, impl, generation)
		return err
	case "rds":
		_, _, err := BuildRDSCreate("validate", environment, capability, attrs, impl, generation)
		return err
	case "ecs":
		_, err := BuildECSRequests("validate", environment, capability, attrs, impl, generation)
		return err
	case "apprunner":
		_, err := BuildAppRunnerRequests("validate", environment, capability, attrs, impl, generation)
		return err
	case "vpc":
		_, err := BuildAWSVPC("validate", environment, capability, attrs, impl, generation)
		return err
	case "sns":
		_, err := BuildSNSCreate("validate", environment, capability, attrs, impl, generation)
		return err
	case "sqs":
		_, err := BuildSQSCreate("validate", environment, capability, attrs, impl, generation)
		return err
	case "secretsmanager":
		_, err := BuildSecretsManagerCreate(environment, capability, attrs, impl, generation)
		return err
	case "elasticache":
		_, err := BuildElastiCacheCreate("validate", environment, capability, attrs, impl, generation)
		return err
	case "elasticache-serverless":
		_, err := BuildElastiCacheServerlessCreate("validate", environment, capability, attrs, impl, generation)
		return err
	case "route53":
		_, err := BuildRoute53Zone(environment, capability, attrs, impl, generation)
		return err
	case "route53record":
		_, err := BuildRoute53Record(environment, capability, attrs, impl, generation)
		return err
	case "rolepolicy":
		_, err := BuildRolePolicyAttachment(environment, capability, attrs, impl, generation)
		return err
	case "custompolicy":
		_, err := BuildCustomPolicy(environment, capability, attrs, impl, generation)
		return err
	case "cloudwatch":
		_, err := BuildCloudWatchAlarm("validate", environment, capability, attrs, impl, generation)
		return err
	case "cloudwatchdash":
		_, err := BuildCWDashboard(environment, capability, attrs, impl, generation)
		return err
	case "route53health":
		_, err := BuildRoute53HealthCheck(environment, capability, attrs, impl, generation)
		return err
	case "cwlogfilter":
		_, err := BuildCWLogFilter(environment, capability, attrs, impl, generation)
		return err
	case "ecr":
		_, err := BuildECR(environment, capability, attrs, impl, generation)
		return err
	case "ec2":
		_, err := BuildEC2InstanceCreate(environment, capability, attrs, impl, generation)
		return err
	case "ebs":
		_, err := BuildEBSVolumeCreate(environment, capability, attrs, impl, generation)
		return err
	// "ami" needs no arm: the witness gate above refuses it before the switch, and a
	// second refusal here could only drift from the first.
	case "efs":
		_, err := BuildEFSCreate(environment, capability, attrs, impl, generation)
		return err
	case "dynamodb":
		_, err := BuildDynamoDB(environment, capability, attrs, impl, generation)
		return err
	case "opensearch":
		_, err := BuildOpenSearch(environment, capability, attrs, impl, generation)
		return err
	case "opensearch-serverless":
		_, err := BuildOpenSearchServerless(environment, capability, attrs, impl, generation)
		return err
	case "kinesis":
		_, err := BuildKinesis(environment, capability, attrs, impl, generation)
		return err
	case "msk":
		_, err := BuildMSK(environment, capability, attrs, impl, generation)
		return err
	case "waf":
		_, err := BuildWAF(environment, capability, attrs, impl, generation)
		return err
	case "acm":
		_, err := BuildACM(environment, capability, attrs, impl, generation)
		return err
	case "cloudfront":
		_, err := BuildCloudFront(environment, capability, attrs, impl, generation)
		return err
	case "apigateway":
		_, err := BuildApiGWv2(environment, capability, attrs, impl, generation)
		return err
	case "iam":
		_, err := BuildIAMRole("validate", environment, capability, attrs, impl, generation)
		return err
	case "redshiftserverless":
		_, err := BuildRedshiftServerless(environment, capability, attrs, impl, generation)
		return err
	case "eventbridgescheduler":
		_, err := BuildEventBridgeScheduler(environment, capability, attrs, impl, generation)
		return err

	case "kms":
		_, err := BuildAWSKMSKey(environment, capability, attrs, impl, generation)
		return err
	case "vpngateway":
		_, err := BuildVpnGateway(environment, capability, attrs, impl, generation)
		return err
	case "backupvault":
		_, err := BuildBackupVault(environment, capability, attrs, impl, generation)
		return err
	case "changefeed":
		// region rides in the feed.target ARN, not location.region (global at the
		// vocab gate); the builder derives + validates it.
		_, err := BuildChangeFeed(environment, capability, attrs, impl, generation)
		return err

	case "loadbalancer":
		// refuse-before-mutate: a missing required operand (subnets<2, no vpcId, or
		// inTransit=true with no certificateArn) is caught here, before any ELBv2 call.
		_, err := BuildLoadBalancer(environment, capability, attrs, impl, generation)
		return err
	case "eks":
		// refuse-before-mutate: an unmapped attribute or a missing required operand
		// (clusterRoleArn, subnetIds<2, nodeRoleArn, nodeGroup, kmsKeyArn iff
		// encryption.secrets) is caught here, before any EKS mutation.
		_, err := BuildEKS(environment, capability, attrs, impl, generation)
		return err
	case "eks-addon":
		// refuse-before-mutate: an unmapped attribute or a missing required
		// attribute/operand (addon.name, addon.version, clusterName) is caught here,
		// before any EKS mutation.
		_, err := BuildEKSAddon(environment, capability, attrs, impl, generation)
		return err
	case "eks-podidentity":
		// refuse-before-mutate: an unmapped attribute or a missing required
		// attribute/operand (workload.namespace, workload.serviceAccount, clusterName,
		// roleArn) is caught here, before any EKS mutation.
		_, err := BuildEKSPodIdentity(environment, capability, attrs, impl, generation)
		return err
	case "ses-sending":
		// refuse-before-mutate: an unmapped attribute or a missing required operand
		// (domain, or bounceTopicArn iff bounce.tracked) is caught here, before any SES call.
		_, err := BuildSESSending(environment, capability, attrs, impl, generation)
		return err
	case "ses-inbound":
		// refuse-before-mutate: an unmapped attribute or a missing required operand
		// (recipientDomain, or s3BucketName iff delivery.sink) is caught here.
		_, err := BuildSESInbound(environment, capability, attrs, impl, generation)
		return err
	case "aurora":
		// account only affects the cluster identity, not attribute honorability —
		// validate with a placeholder (network-free, D85).
		_, err := BuildAurora("", environment, capability, attrs, impl, generation)
		return err
	case "bedrock":
		_, err := BuildBedrock(environment, capability, attrs, impl, generation)
		return err
	case "budgets":
		_, err := BuildBudget(environment, capability, attrs, impl, generation)
		return err
	case "cloudtrail":
		// refuse-before-mutate: an unmapped attribute or a missing required operand
		// (s3BucketName, or kmsKeyArn iff CMK, or cloudWatchLogsRoleArn iff a log group)
		// is caught here, before any CloudTrail mutation.
		_, err := BuildCloudTrail(environment, capability, attrs, impl, generation)
		return err
	case "backupplan":
		_, err := BuildBackupPlan(environment, capability, attrs, impl, generation)
		return err
	case "guardduty":
		_, err := BuildGuardDuty(environment, capability, attrs, impl, generation)
		return err
	case "cwlogs":
		_, err := BuildCWLogs(environment, capability, attrs, impl, generation)
		return err
	case "lambda":
		// account only affects the providerId, not attribute honorability — validate
		// with a placeholder (network-free); the region gate above already ran.
		_, err := BuildLambda("validate", environment, capability, attrs, impl, generation)
		return err

	default:
		return fmt.Errorf("aws service %q is not wired yet", service)
	}
}

// createScope resolves the region a create must target from the candidate's
// location.region (NOT the driver's env-pinned region) so a contract requesting
// us-west-2 never lands in the operator's shell default — and the account, once,
// via STS. A missing/invalid region or an STS failure returns a terminal result.
// regionOperand resolves the region for a vocab-region-free capability (D279):
// the implementation.region operand first (typically a $ref to the producer's
// region output), then a location.region attribute if a future vocab adds one.
// Never the driver's ambient region — an operand is declared, ambient is not.
func regionOperand(attrs, impl map[string]any) string {
	if r, _ := impl["region"].(string); r != "" {
		return r
	}
	r, _ := attrs["location.region"].(string)
	return r
}

func (d *Driver) createScope(attrs map[string]any) (region, account string, res *provider.CreateResult) {
	region, _ = attrs["location.region"].(string)
	if !regionOK.MatchString(region) {
		r := provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("location.region %q is missing or not a valid AWS region — "+
				"refusing rather than defaulting to the driver's region", region)}
		return "", "", &r
	}
	acct, err := d.resolveAccount()
	if err != nil {
		r := provider.CreateResult{Status: "unknown", Reason: err.Error()}
		return "", "", &r
	}
	return region, acct, nil
}

// Create dispatches the per-service create and, for services declaring typed
// outputs (D226/D275), attaches them to a succeeded result — derived from the
// provider id (plus one read for vpc subnets), so every succeeded path,
// including create-adoption (D253), receipts the same truthful set.
func (d *Driver) Create(service, capability, environment string,
	attrs, impl map[string]any, key string, generation int) provider.CreateResult {
	// D309: the credentials this action carries are remembered for the duration of
	// the mutation and scrubbed out of its Reason on the way back — the Reason is
	// persisted in the ledger and signed into capsules, so a provider that echoes
	// a value we sent must not publish it.
	defer d.forgetSecrets()
	d.rememberSecrets(impl)
	cr := d.createService(service, capability, environment, attrs, impl, key, generation)
	d.attachOutputs(service, &cr)
	cr.Reason = d.scrub(cr.Reason)
	return cr
}

func (d *Driver) createService(service, capability, environment string,
	attrs, impl map[string]any, key string, generation int) provider.CreateResult {
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !d.hasCreds() {
		return provider.CreateResult{Status: "failed",
			Reason: "no AWS credentials — refusing before any mutation"}
	}
	switch service {
	case "s3":
		account, err := d.resolveAccount()
		if err != nil {
			return provider.CreateResult{Status: "unknown", Reason: err.Error()}
		}
		return d.createS3(account, environment, capability, attrs, impl, generation)
	case "rds":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createRDS(region, account, environment, capability, attrs, impl, generation)
	case "ecs":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createECS(region, account, environment, capability, attrs, impl, generation)
	case "apprunner":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createAppRunner(region, account, environment, capability, attrs, impl, generation)
	case "vpc":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createAWSVPC(region, account, environment, capability, attrs, impl, generation)
	case "sns":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createSNS(region, account, environment, capability, attrs, impl, generation)
	case "sqs":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createSQS(region, account, environment, capability, attrs, impl, generation)
	case "secretsmanager":
		// a secret create needs no account lookup — Secrets Manager is regional
		// and the name is the idempotency key; validate the region and go.
		region, _ := attrs["location.region"].(string)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("location.region %q is missing or not a valid AWS region", region)}
		}
		return d.createASM(region, environment, capability, attrs, impl, generation)
	case "elasticache":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createElastiCache(region, account, environment, capability, attrs, impl, generation)
	case "elasticache-serverless":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createElastiCacheServerless(region, account, environment, capability, attrs, impl, generation)
	case "ecr":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createECR(region, account, environment, capability, attrs, impl, generation)
	case "route53":
		// Route 53 is a GLOBAL service — no region/account scope needed.
		return d.createRoute53(environment, capability, attrs, impl, generation)
	case "route53record":
		// Route 53 is a GLOBAL service — no region/account scope needed.
		return d.createRoute53Record(environment, capability, attrs, impl, generation)
	case "rolepolicy":
		// IAM is a GLOBAL service — no region/account scope needed.
		return d.createRolePolicyAttachment(environment, capability, attrs, impl, generation)
	case "custompolicy":
		// IAM is a GLOBAL service — the driver resolves the account for the Arn.
		return d.createCustomPolicy(environment, capability, attrs, impl, generation)
	case "cloudwatch":
		// the alarm's region is an implementation detail (the alert vocab is
		// region-free); the account is resolved for the alarm ARN.
		region, _ := impl["region"].(string)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("cloudwatch requires implementation.region (a valid AWS region), got %q", region)}
		}
		account, err := d.resolveAccount()
		if err != nil {
			return provider.CreateResult{Status: "unknown", Reason: err.Error()}
		}
		return d.createCloudWatchAlarm(region, account, environment, capability, attrs, impl, generation)
	case "cloudwatchdash":
		// CloudWatch dashboards are GLOBAL — no region/account scope needed.
		return d.createCWDashboard(environment, capability, attrs, impl, generation)
	case "route53health":
		return d.createRoute53HealthCheck(environment, capability, attrs, impl, generation)
	case "cwlogfilter":
		// the metric filter's region is an implementation detail (vocab is region-free).
		return d.createCWLogFilter(environment, capability, attrs, impl, generation)
	case "acm":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createACM(region, account, environment, capability, attrs, impl, generation)
	case "ec2":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createEC2Instance(region, account, environment, capability, attrs, impl, generation)
	case "ebs":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createEBSVolume(region, account, environment, capability, attrs, impl, generation)
	case "ami":
		return provider.CreateResult{Status: "failed",
			Reason: errWitnessOnly("ami", "capability.compute.image").Error()}
	case "efs":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createEFS(region, account, environment, capability, attrs, impl, generation)
	case "dynamodb":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createDynamoDB(region, account, environment, capability, attrs, impl, generation)
	case "opensearch":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createOpenSearch(region, account, environment, capability, attrs, impl, generation)
	case "opensearch-serverless":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createOpenSearchServerless(region, account, environment, capability, attrs, impl, generation)
	case "kinesis":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createKinesis(region, account, environment, capability, attrs, impl, generation)
	case "msk":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createMSK(region, account, environment, capability, attrs, impl, generation)
	case "waf":
		// CLOUDFRONT-scope WAFv2 is global (us-east-1 endpoint) — only the account
		// is needed for the pid/ARN; no location.region.
		account, err := d.resolveAccount()
		if err != nil {
			return provider.CreateResult{Status: "unknown", Reason: err.Error()}
		}
		return d.createWAF(account, environment, capability, attrs, impl, generation)
	case "cloudfront":
		// CloudFront is GLOBAL — only the account is needed for the pid; no region.
		account, err := d.resolveAccount()
		if err != nil {
			return provider.CreateResult{Status: "unknown", Reason: err.Error()}
		}
		return d.createCloudFront(account, environment, capability, attrs, impl, generation)
	case "apigateway":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createApiGWv2(region, account, environment, capability, attrs, impl, generation)
	case "iam":
		// IAM is a GLOBAL service — only the account is needed for the role ARN/pid.
		account, err := d.resolveAccount()
		if err != nil {
			return provider.CreateResult{Status: "unknown", Reason: err.Error()}
		}
		return d.createIAMRole(account, environment, capability, attrs, impl, generation)
	case "redshiftserverless":
		region, _ := attrs["location.region"].(string)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("location.region %q is missing or not a valid AWS region", region)}
		}
		return d.createRedshiftServerless(region, environment, capability, attrs, impl, generation)
	case "eventbridgescheduler":
		region, _ := attrs["location.region"].(string)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("location.region %q is missing or not a valid AWS region", region)}
		}
		return d.createEventBridgeScheduler(region, environment, capability, attrs, impl, generation)

	case "kms":
		region, _ := attrs["location.region"].(string)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("location.region %q is missing or not a valid AWS region", region)}
		}
		return d.createAWSKMS(region, environment, capability, attrs, impl, generation)
	case "vpngateway":
		region, _ := attrs["location.region"].(string)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("location.region %q is missing or not a valid AWS region", region)}
		}
		return d.createVpnGateway(region, environment, capability, attrs, impl, generation)
	case "backupvault":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createBackupVault(region, account, environment, capability, attrs, impl, generation)
	case "changefeed":
		// the rule's region is DERIVED from the feed.target ARN by the builder
		// (the capability carries no location.region), so no createScope here.
		return d.createChangeFeed(environment, capability, attrs, impl, generation)
	case "loadbalancer":
		// D279: the loadbalancer vocab is region-free — the region is an
		// implementation operand (typically {$ref: <vpc-cap>, output: region}).
		region := regionOperand(attrs, impl)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("loadbalancer requires implementation.region (a valid AWS region, e.g. {$ref: {capability: <vpc-cap>, output: region}}), got %q", region)}
		}
		return d.createLoadBalancer(region, environment, capability, attrs, impl, generation)
	case "eks":
		// EKS is regional; the create needs no account lookup (the roles/subnets/KMS
		// key are operands). Validate the region and go.
		region, _ := attrs["location.region"].(string)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("location.region %q is missing or not a valid AWS region", region)}
		}
		return d.createEKS(region, environment, capability, attrs, impl, generation)
	case "eks-addon":
		// the addon is a sub-resource of a cluster (the clusterName operand); its
		// vocab is region-free (D279) — the region is an implementation operand,
		// typically {$ref: <eks-cap>, output: region}.
		region := regionOperand(attrs, impl)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("eks-addon requires implementation.region (a valid AWS region, e.g. {$ref: {capability: <eks-cap>, output: region}}), got %q", region)}
		}
		return d.createEKSAddon(region, environment, capability, attrs, impl, generation)
	case "eks-podidentity":
		// a sub-resource of a cluster; vocab region-free (D279) — the region is an
		// implementation operand, typically {$ref: <eks-cap>, output: region}.
		region := regionOperand(attrs, impl)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("eks-podidentity requires implementation.region (a valid AWS region, e.g. {$ref: {capability: <eks-cap>, output: region}}), got %q", region)}
		}
		return d.createEKSPodIdentity(region, environment, capability, attrs, impl, generation)
	case "ses-sending":
		// SES is regional; the create needs no account lookup (the domain + bounce
		// topic are operands). Validate the region and go.
		region, _ := attrs["location.region"].(string)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("location.region %q is missing or not a valid AWS region", region)}
		}
		return d.createSESSending(region, environment, capability, attrs, impl, generation)
	case "ses-inbound":
		// SES receiving is regional; recipient/bucket/topic are operands, no account lookup.
		region, _ := attrs["location.region"].(string)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("location.region %q is missing or not a valid AWS region", region)}
		}
		return d.createSESInbound(region, environment, capability, attrs, impl, generation)
	case "aurora":
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createAurora(region, account, environment, capability, attrs, impl, generation)
	case "bedrock":
		// regional; the profile + tags are the resource, no account lookup needed.
		region, _ := attrs["location.region"].(string)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("location.region %q is missing or not a valid AWS region", region)}
		}
		return d.createBedrock(region, environment, capability, attrs, impl, generation)
	case "budgets":
		// global/account-scoped; no region.
		account, err := d.resolveAccount()
		if err != nil {
			return provider.CreateResult{Status: "unknown", Reason: err.Error()}
		}
		return d.createBudget(account, environment, capability, attrs, impl, generation)
	case "cloudtrail":
		// CloudTrail is regional; the create needs no account lookup (the destination
		// bucket, KMS key, SNS topic and CloudWatch Logs group are operands).
		region, _ := attrs["location.region"].(string)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("location.region %q is missing or not a valid AWS region", region)}
		}
		return d.createCloudTrail(region, environment, capability, attrs, impl, generation)
	case "backupplan":
		// regional; the target vault + IAM role are operands, no account lookup needed.
		region, _ := attrs["location.region"].(string)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("location.region %q is missing or not a valid AWS region", region)}
		}
		return d.createBackupPlan(region, environment, capability, attrs, impl, generation)
	case "guardduty":
		region, _ := attrs["location.region"].(string)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("location.region %q is missing or not a valid AWS region", region)}
		}
		return d.createGuardDuty(region, environment, capability, attrs, impl, generation)
	case "cwlogs":
		region, _ := attrs["location.region"].(string)
		if !regionOK.MatchString(region) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("location.region %q is missing or not a valid AWS region", region)}
		}
		return d.createCWLogs(region, environment, capability, attrs, impl, generation)
	case "lambda":
		// Lambda is regional; the account is part of the providerId + the function
		// name, so resolve the full create scope (region + account via STS).
		region, account, r := d.createScope(attrs)
		if r != nil {
			return *r
		}
		return d.createLambda(region, account, environment, capability, attrs, impl, generation)

	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("aws service %q create is not wired yet", service)}
	}
}

func (d *Driver) Observe(service, capability, providerID string) ([]provider.Observation, []string, error) {
	if err := d.requireService(service); err != nil {
		return nil, nil, err
	}
	switch service {
	case "s3":
		return d.observeS3(capability, providerID)
	case "rds":
		return d.observeRDS(capability, providerID)
	case "ecs":
		return d.observeECS(capability, providerID)
	case "apprunner":
		return d.observeAppRunner(capability, providerID)
	case "eks":
		return d.observeEKS(capability, providerID)
	case "eks-addon":
		return d.observeEKSAddon(capability, providerID)
	case "eks-podidentity":
		return d.observeEKSPodIdentity(capability, providerID)
	case "vpc":
		return d.observeAWSVPC(capability, providerID)
	case "sns":
		return d.observeSNS(capability, providerID)
	case "sqs":
		return d.observeSQS(capability, providerID)
	case "secretsmanager":
		return d.observeASM(capability, providerID)
	case "elasticache":
		return d.observeElastiCache(capability, providerID)
	case "elasticache-serverless":
		return d.observeElastiCacheServerless(capability, providerID)
	case "route53":
		return d.observeRoute53(capability, providerID)
	case "route53record":
		return d.observeRoute53Record(capability, providerID)
	case "rolepolicy":
		return d.observeRolePolicyAttachment(capability, providerID)
	case "custompolicy":
		return d.observeCustomPolicy(capability, providerID)
	case "cloudwatch":
		return d.observeCloudWatchAlarm(capability, providerID)
	case "cloudwatchdash":
		return d.observeCWDashboard(capability, providerID)
	case "route53health":
		return d.observeRoute53HealthCheck(capability, providerID)
	case "cwlogfilter":
		return d.observeCWLogFilter(capability, providerID)
	case "ecr":
		return d.observeECR(capability, providerID)
	case "ec2":
		return d.observeEC2Instance(capability, providerID)
	case "ebs":
		return d.observeEBSVolume(capability, providerID)
	case "ami":
		return d.observeAMI(capability, providerID)
	case "efs":
		return d.observeEFS(capability, providerID)
	case "dynamodb":
		return d.observeDynamoDB(capability, providerID)
	case "opensearch":
		return d.observeOpenSearch(capability, providerID)
	case "opensearch-serverless":
		return d.observeOpenSearchServerless(capability, providerID)
	case "kinesis":
		return d.observeKinesis(capability, providerID)
	case "msk":
		return d.observeMSK(capability, providerID)
	case "waf":
		return d.observeWAF(capability, providerID)
	case "acm":
		return d.observeACM(capability, providerID)
	case "cloudfront":
		return d.observeCloudFront(capability, providerID)
	case "apigateway":
		return d.observeApiGWv2(capability, providerID)
	case "iam":
		return d.observeIAMRole(capability, providerID)
	case "redshiftserverless":
		return d.observeRedshiftServerless(capability, providerID)
	case "eventbridgescheduler":
		return d.observeEventBridgeScheduler(capability, providerID)

	case "kms":
		return d.observeAWSKMS(capability, providerID)
	case "vpngateway":
		return d.observeVpnGateway(capability, providerID)
	case "backupvault":
		return d.observeBackupVault(capability, providerID)
	case "changefeed":
		return d.observeChangeFeed(capability, providerID)
	case "loadbalancer":
		return d.observeLoadBalancer(capability, providerID)
	case "ses-sending":
		return d.observeSESSending(capability, providerID)
	case "ses-inbound":
		return d.observeSESInbound(capability, providerID)
	case "aurora":
		return d.observeAurora(capability, providerID)
	case "bedrock":
		return d.observeBedrock(capability, providerID)
	case "budgets":
		return d.observeBudget(capability, providerID)
	case "cloudtrail":
		return d.observeCloudTrail(capability, providerID)
	case "backupplan":
		return d.observeBackupPlan(capability, providerID)
	case "guardduty":
		return d.observeGuardDuty(capability, providerID)
	case "cwlogs":
		return d.observeCWLogs(capability, providerID)
	case "lambda":
		return d.observeLambda(capability, providerID)

	default:
		return nil, nil, fmt.Errorf("aws service %q observe is not wired yet", service)
	}
}

func (d *Driver) Delete(service, capability, environment, providerID, key string) provider.CreateResult {
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !d.hasCreds() {
		return provider.CreateResult{Status: "failed",
			Reason: "no AWS credentials — refusing before any mutation"}
	}
	switch service {
	case "s3":
		return d.deleteS3(capability, environment, providerID)
	case "rds":
		return d.deleteRDS(capability, environment, providerID)
	case "ecs":
		return d.deleteECS(capability, environment, providerID)
	case "apprunner":
		return d.deleteAppRunner(capability, environment, providerID)
	case "vpc":
		return d.deleteAWSVPC(capability, environment, providerID)
	case "sns":
		return d.deleteSNS(capability, environment, providerID)
	case "sqs":
		return d.deleteSQS(capability, environment, providerID)
	case "secretsmanager":
		return d.deleteASM(capability, environment, providerID)
	case "elasticache":
		return d.deleteElastiCache(capability, environment, providerID)
	case "elasticache-serverless":
		return d.deleteElastiCacheServerless(capability, environment, providerID)
	case "route53":
		return d.deleteRoute53(capability, environment, providerID)
	case "route53record":
		return d.deleteRoute53Record(capability, environment, providerID)
	case "rolepolicy":
		return d.deleteRolePolicyAttachment(capability, environment, providerID)
	case "custompolicy":
		return d.deleteCustomPolicy(capability, environment, providerID)
	case "cloudwatch":
		return d.deleteCloudWatchAlarm(capability, environment, providerID)
	case "cloudwatchdash":
		return d.deleteCWDashboard(capability, environment, providerID)
	case "route53health":
		return d.deleteRoute53HealthCheck(capability, environment, providerID)
	case "cwlogfilter":
		return d.deleteCWLogFilter(capability, environment, providerID)
	case "ecr":
		return d.deleteECR(capability, environment, providerID)
	case "ec2":
		return d.deleteEC2Instance(capability, environment, providerID)
	case "ebs":
		return d.deleteEBSVolume(capability, environment, providerID)
	case "ami":
		// Deleting an image groundhold never created would destroy something a
		// pipeline owns, on the strength of a record we only ever read.
		return provider.CreateResult{Status: "failed",
			Reason: errWitnessOnly("ami", "capability.compute.image").Error()}
	case "efs":
		return d.deleteEFS(capability, environment, providerID)
	case "dynamodb":
		return d.deleteDynamoDB(capability, environment, providerID)
	case "opensearch":
		return d.deleteOpenSearch(capability, environment, providerID)
	case "opensearch-serverless":
		return d.deleteOpenSearchServerless(capability, environment, providerID)
	case "kinesis":
		return d.deleteKinesis(capability, environment, providerID)
	case "msk":
		return d.deleteMSK(capability, environment, providerID)
	case "waf":
		return d.deleteWAF(capability, environment, providerID)
	case "acm":
		return d.deleteACM(capability, environment, providerID)
	case "cloudfront":
		return d.deleteCloudFront(capability, environment, providerID)
	case "apigateway":
		return d.deleteApiGWv2(capability, environment, providerID)
	case "iam":
		return d.deleteIAMRole(capability, environment, providerID)
	case "redshiftserverless":
		return d.deleteRedshiftServerless(capability, environment, providerID)
	case "eventbridgescheduler":
		return d.deleteEventBridgeScheduler(capability, environment, providerID)

	case "kms":
		return d.deleteAWSKMS(capability, environment, providerID)
	case "vpngateway":
		return d.deleteVpnGateway(capability, environment, providerID)
	case "backupvault":
		return d.deleteBackupVault(capability, environment, providerID)
	case "changefeed":
		return d.deleteChangeFeed(capability, environment, providerID)
	case "loadbalancer":
		return d.deleteLoadBalancer(capability, environment, providerID)
	case "eks":
		return d.deleteEKS(capability, environment, providerID)
	case "eks-addon":
		return d.deleteEKSAddon(capability, environment, providerID)
	case "eks-podidentity":
		return d.deleteEKSPodIdentity(capability, environment, providerID)
	case "ses-sending":
		return d.deleteSESSending(d.Region, capability, environment, providerID)
	case "ses-inbound":
		return d.deleteSESInbound(capability, environment, providerID)
	case "aurora":
		return d.deleteAurora(capability, environment, providerID)
	case "bedrock":
		return d.deleteBedrock(capability, environment, providerID)
	case "budgets":
		return d.deleteBudget(capability, environment, providerID)
	case "cloudtrail":
		return d.deleteCloudTrail(capability, environment, providerID)
	case "backupplan":
		return d.deleteBackupPlan(capability, environment, providerID)
	case "guardduty":
		return d.deleteGuardDuty(capability, environment, providerID)
	case "cwlogs":
		return d.deleteCWLogs(capability, environment, providerID)
	case "lambda":
		return d.deleteLambda(capability, environment, providerID)

	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("aws service %q delete is not wired yet", service)}
	}
}

// ClassifyChange dispatches on the SERVICE token (D46), mirroring Create/
// Observe/Delete: can this transition be honored IN PLACE? PURE provider
// knowledge — no network. Each service returns one of
// mutable | immutable | unsupported | caveated with a note. An attribute a
// service cannot patch in place is immutable/unsupported with a clear reason,
// never a silent "mutable" (the classification gates the compiler's plan:
// immutable/caveated become an update, immutable a replacement, unsupported a
// refusal). ecs/vpc are deliberately NOT wired (mostly-immutable resources).
func (d *Driver) ClassifyChange(service, path string, current, desired any,
	impl map[string]any) (string, string) {
	switch service {
	case "ec2":
		return classifyEC2InstanceChange(path)
	case "ebs":
		return classifyEBSVolumeChange(path)
	case "ami":
		return classifyAMIChange(path)
	case "s3":
		return classifyS3Change(path, desired, impl)
	case "apprunner":
		return classifyAppRunnerChange(path)
	case "elasticache-serverless":
		return classifyElastiCacheServerlessChange(path)
	case "opensearch-serverless":
		return classifyOpenSearchServerlessChange(path)
	case "route53record":
		return classifyRoute53RecordChange(path, desired, impl)
	case "sns":
		return classifySNSChange(path, desired, impl)
	case "sqs":
		return classifySQSChange(path, desired, impl)
	case "rds":
		return classifyRDSChange(path, desired, impl)
	case "secretsmanager":
		return classifyASMChange(path, desired, impl)
	case "loadbalancer":
		return classifyLBChange(path, desired, impl)
	case "eks":
		return classifyEKSChange(path)
	case "eks-addon":
		return classifyEKSAddonChange(path)
	case "eks-podidentity":
		return classifyEKSPodIdentityChange(path)
	case "ses-sending":
		return classifySESSendingChange(path)
	case "ses-inbound":
		return classifySESInboundChange(path)
	case "ecr":
		return classifyECRChange(path)
	case "aurora":
		return classifyAuroraChange(path, desired, impl)
	case "bedrock":
		return classifyBedrockChange(path)
	case "budgets":
		return classifyBudgetChange(path)
	case "cloudtrail":
		return classifyCloudTrailChange(path)
	case "backupplan":
		return classifyBackupPlanChange(path, desired, impl)
	case "guardduty":
		return classifyGuardDutyChange(path)
	case "cwlogs":
		return classifyCWLogsChange(path)
	case "acm":
		return classifyACMChange(path)
	case "lambda":
		return classifyLambdaChange(path)
	default:
		// D215: a create service with no explicit ClassifyChange has no in-place
		// update path, so reconciling a drift is honestly a REPLACEMENT
		// (consent-gated when stateful, D48) — never a silent FREEZE (the old
		// "unsupported" blocked classifyBound, so one partial apply stalled every
		// incremental apply, F15). Explicit wiring refines a genuinely-mutable path.
		return "immutable", fmt.Sprintf(
			"aws service %q has no in-place update path — reconciling a drift is a replacement", service)
	}
}

// Update dispatches on the SERVICE token (D46), mirroring Create/Observe/Delete.
// Every wired service re-checks ownership (tags) BEFORE patching and then
// re-issues ONLY the changed paths (the values sourced from the hash-pinned
// candidate attrs). Honesty per D29/D87: an ambiguous patch outcome (transport
// error / 5xx) is unknown WITH the providerId; a 4xx/3xx is failed (never a
// silent success); a garbled ownership read refuses.
func (d *Driver) Update(service, capability, environment, providerID string,
	attrs, impl map[string]any, changes []string, key string) provider.CreateResult {
	defer d.forgetSecrets()
	d.rememberSecrets(impl)
	cr := d.update(service, capability, environment, providerID, attrs, impl, changes, key)
	cr.Reason = d.scrub(cr.Reason)
	return cr
}

func (d *Driver) update(service, capability, environment, providerID string,
	attrs, impl map[string]any, changes []string, key string) provider.CreateResult {
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !d.hasCreds() {
		return provider.CreateResult{Status: "failed",
			Reason: "no AWS credentials — refusing before any mutation"}
	}
	switch service {
	case "acm":
		return d.updateACM(capability, environment, providerID, changes)
	case "apprunner":
		return d.updateAppRunner(capability, environment, providerID, attrs, impl, changes)
	case "s3":
		return d.updateS3(capability, environment, providerID, attrs, impl, changes)
	case "route53record":
		// D262: REPOINT a record set in place (dns.target) via UPSERT — a
		// create-or-replace, so no delete+recreate DNS resolution gap.
		return d.updateRoute53Record(capability, environment, providerID, attrs, impl, changes)
	case "sns":
		return d.updateSNS(capability, environment, providerID, attrs, impl, changes)
	case "sqs":
		return d.updateSQS(capability, environment, providerID, attrs, impl, changes)
	case "rds":
		return d.updateRDS(capability, environment, providerID, attrs, impl, changes)
	case "secretsmanager":
		return d.updateASM(capability, environment, providerID, attrs, impl, changes)
	case "loadbalancer":
		// read-only slice — refuse-closed honestly (never a silent no-op).
		return d.updateLoadBalancer()
	case "eks":
		// D147 slice 3: in-place cluster update (version / apiExposure), each an LRO.
		return d.updateEKS(capability, environment, providerID, attrs, changes)
	case "eks-addon":
		// D149: in-place managed-addon version bump (addon.version via UpdateAddon).
		return d.updateEKSAddon(capability, environment, providerID, attrs, impl, changes)
	case "ses-sending":
		// D148: in-place sender patch (authentication.dkim / bounce.tracked), both single-call.
		return d.updateSESSending(capability, environment, providerID, attrs, impl, changes)
	case "ses-inbound":
		// in-place receiving patch (spam.filtered / delivery.sink), UpdateReceiptRule + re-activate.
		return d.updateSESInbound(capability, environment, providerID, attrs, impl, changes)
	case "ecr":
		// D4: in-place scan-on-push / tag-mutability patch (PutImageScanningConfiguration).
		return d.updateECR(capability, environment, providerID, attrs, impl, changes)
	case "aurora":
		// D152: in-place cluster patch (engine.version / serverless ACU floor+ceiling)
		// via ModifyDBCluster.
		return d.updateAurora(capability, environment, providerID, attrs, impl, changes)
	case "budgets":
		// D151: in-place budget patch (budget.limit / alert.threshold) via ModifyBudget.
		return d.updateBudget(capability, environment, providerID, attrs, impl, changes)
	case "cloudtrail":
		// in-place trail patch (scope.multiRegion / integrity.logValidation / CMK via
		// UpdateTrail; delivery.assured via StartLogging/StopLogging).
		return d.updateCloudTrail(capability, environment, providerID, attrs, impl, changes)
	case "backupplan":
		// D153: in-place plan patch (schedule.frequency / retention.duration / cross-region copy).
		return d.updateBackupPlan(capability, environment, providerID, attrs, impl, changes)
	case "guardduty":
		// in-place detector patch (detection.enabled / protection.kubernetes / protection.malware).
		return d.updateGuardDuty(capability, environment, providerID, attrs, impl, changes)
	case "cwlogs":
		// in-place log-group patch (retention.days / CMK) via PutRetentionPolicy / Associate KMS.
		return d.updateCWLogs(capability, environment, providerID, attrs, impl, changes)
	case "lambda":
		// in-place config patch (timeout.maximum re-pushes Role/Timeout/VpcConfig/
		// Environment via UpdateFunctionConfiguration; network.publicExposure toggles
		// the Function URL).
		return d.updateLambda(capability, environment, providerID, attrs, impl, changes)
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("aws service %q in-place update is not wired yet", service)}
	}
}
