package aws

import (
	"testing"

	"groundhold/internal/provider"
)

// awsCertifyServices is the authoritative set of SERVICE tokens the AWS driver
// observes/provisions — the same set both certification gates run over.
var awsCertifyServices = []string{"loadbalancer", "changefeed", "s3", "rds", "ecs", "apprunner", "eks", "eks-addon", "eks-podidentity", "ses-sending", "aurora", "bedrock", "budgets", "vpc", "sns", "sqs", "secretsmanager", "elasticache", "elasticache-serverless", "route53", "route53record", "rolepolicy", "custompolicy", "cloudwatch", "cloudwatchdash", "route53health", "cwlogfilter", "ecr", "efs", "dynamodb", "opensearch", "opensearch-serverless", "kinesis", "msk", "waf", "acm", "cloudfront", "apigateway", "iam", "redshiftserverless", "eventbridgescheduler", "kms", "vpngateway", "backupvault", "cloudtrail", "backupplan", "ses-inbound", "guardduty", "cwlogs", "lambda"}

// The AWS driver passes the same network-free certification battery every driver
// must (fail-closed dispatch, well-formed permission tables).
func TestCertifyAWSDriver(t *testing.T) {
	provider.CertifyDriver(t, NewDriver("eu-central-1"), awsCertifyServices)
}

// TestAWSDiscoverabilityComplete enforces the driver standard's core requirement
// (spec/drivers.md §2): every observable AWS service is either covered by a List
// sweep or declared a non-listable sub-resource/feed. A new Observe (a new token
// in awsCertifyServices) fails this until it gets a discoverer — so nothing ships
// invisible to the proactive posture.
func TestAWSDiscoverabilityComplete(t *testing.T) {
	provider.CertifyDiscoverability(t, NewDriver("eu-central-1"), awsCertifyServices)
}

// TestAWSParityComplete enforces spec/drivers.md §8: every certified AWS service
// declares the capability TYPE it fulfils (ServiceCapabilities), so the cross-cloud
// parity matrix is proven, not guessed.
func TestAWSParityComplete(t *testing.T) {
	provider.CertifyParity(t, NewDriver("eu-central-1"), awsCertifyServices)
}

// compile-time assertion that the driver satisfies the provider interface.
var _ provider.Provider = (*Driver)(nil)
