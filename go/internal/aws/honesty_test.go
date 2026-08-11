package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func isReadAction(action string) bool {
	return strings.HasPrefix(action, "Describe") ||
		strings.HasPrefix(action, "List") || strings.HasPrefix(action, "Get")
}

func queryAction(body []byte) string {
	for _, kv := range strings.Split(string(body), "&") {
		if strings.HasPrefix(kv, "Action=") {
			return strings.TrimPrefix(kv, "Action=")
		}
	}
	return ""
}

// restXMLRole classifies AWS REST-XML (S3) requests: GET/HEAD read, every other
// method is an opaque mutation (S3 PUTs succeed on status, body not consumed).
func restXMLRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// queryXMLRole classifies AWS Query-protocol (RDS/EC2) by Action. Create* that
// yield an id the driver consumes are parsed; the rest are opaque.
func queryXMLRole(_ *http.Request, body []byte) certifynet.Role {
	action := queryAction(body)
	switch {
	case isReadAction(action):
		return certifynet.RoleRead
	case action == "CreateVpc":
		return certifynet.RoleMutateParsed // vpcId becomes the providerId
	case action == "RunInstances":
		return certifynet.RoleMutateParsed // instanceId becomes the providerId (D358)
	case action == "CreateVolume":
		return certifynet.RoleMutateParsed // volumeId becomes the providerId (D367)
	case action == "CreateAutoScalingGroup", action == "PutScalingPolicy":
		// the group NAME is deterministic, so nothing is parsed out of the response
		return certifynet.RoleMutateOpaque
	default:
		// CreateSubnet's id is NOT consumed at create time (delete re-enumerates
		// via DescribeSubnets), so it is an opaque status-only mutation.
		return certifynet.RoleMutateOpaque
	}
}

// jsonTargetRole classifies AWS JSON (ECS) by X-Amz-Target. RegisterTaskDefinition
// is parsed for its taskDefinitionArn; the rest are opaque.
func jsonTargetRole(req *http.Request, _ []byte) certifynet.Role {
	target := req.Header.Get("X-Amz-Target")
	act := target[strings.LastIndex(target, ".")+1:]
	switch {
	case isReadAction(act):
		return certifynet.RoleRead
	case act == "RegisterTaskDefinition":
		return certifynet.RoleMutateParsed
	default:
		return certifynet.RoleMutateOpaque
	}
}

// newHonestyDriver builds a Driver pointed at the happy server with the scripted
// transport, all BaseURLs overridden so any protocol routes through it.
func newHonestyDriver(happyURL string, rt http.RoundTripper) *Driver {
	d := NewDriver("eu-central-1")
	d.HTTP = &http.Client{Transport: rt}
	d.Account = "000000000000"
	d.S3BaseURL = happyURL
	d.RDSBaseURL = happyURL
	d.ECSBaseURL = happyURL
	d.EC2BaseURL = happyURL
	d.STSBaseURL = happyURL
	d.SNSBaseURL = happyURL
	d.SQSBaseURL = happyURL
	d.SecretsManagerBaseURL = happyURL
	d.Route53BaseURL = happyURL
	d.OpenSearchBaseURL = happyURL
	d.KinesisBaseURL = happyURL
	d.MSKBaseURL = happyURL
	d.WAFBaseURL = happyURL
	d.ACMBaseURL = happyURL
	d.CloudFrontBaseURL = happyURL
	d.APIGatewayBaseURL = happyURL
	d.RedshiftServerlessBaseURL = happyURL
	d.SchedulerBaseURL = happyURL
	d.KMSBaseURL = happyURL
	d.BackupBaseURL = happyURL
	d.ElastiCacheBaseURL = happyURL
	d.IAMBaseURL = happyURL
	d.CloudWatchBaseURL = happyURL
	d.CloudWatchDashBaseURL = happyURL
	d.LogsBaseURL = happyURL
	d.ECRBaseURL = happyURL
	d.EFSBaseURL = happyURL
	d.DynamoDBBaseURL = happyURL
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

// s3HappyDelete reports OUR ownership tags on GET tagging (no prior PUT needed) so
// the baseline delete succeeds; 204 on DELETE.
func s3HappyDelete(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && r.URL.RawQuery == "tagging" {
				_, _ = w.Write([]byte(`<Tagging><TagSet>` +
					`<Tag><Key>groundhold-capability</Key><Value>assets</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
					`</TagSet></Tagging>`))
				return
			}
			if r.Method == "DELETE" {
				w.WriteHeader(204)
				return
			}
			w.WriteHeader(404)
		}))
}

func TestHonestyHarnessS3(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "s3:eu-central-1:pv-assets-abcd1234"
	p := &certifynet.Probe{
		Name:            "aws/s3",
		Classify:        restXMLRole,
		OwnerTagValue:   "assets",
		AssertTransient: true, // D237: create/delete route through provider.MutationResult
		// F-LC3 (D520): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("s3", "assets", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return s3Server(t, 200, "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("s3", "assets", "prod", s3Attrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return s3HappyDelete(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("s3", "assets", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessRDS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "rds:eu-central-1:db-abcd1234"
	p := &certifynet.Probe{
		Name:            "aws/rds",
		AssertTransient: true, // D237
		Classify:        queryXMLRole,
		OwnerTagValue:   "db",
		DeterministicID: true, // the DB instance identifier is a chosen name
		// F-LC3 (D520): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("rds", "db", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return rdsServer(t, "", "false") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("rds", "db", "prod", rdsAttrs(), rdsImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return rdsServer(t, "", "false") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("rds", "db", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessECS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "ecs:eu-central-1:app-abcd1234"
	p := &certifynet.Probe{
		Name:            "aws/ecs",
		AssertTransient: true, // D237 sweep
		Classify:        jsonTargetRole,
		OwnerTagValue:   "app",
		DeterministicID: true, // cluster/service names are chosen
		// F-LC3 (D522): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("ecs", "app", pid)
		},
		GoneCode: "ClusterNotFound", // this service's own not-found code (D522)
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return ecsServer(t, "app") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("ecs", "app", "prod", ecsAttrs(), ecsImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return ecsServer(t, "app") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("ecs", "app", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessElastiCache(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "ecredis:eu-central-1:000000000000:x"
	p := &certifynet.Probe{
		Name:            "aws/elasticache",
		AssertTransient: true,         // D237 sweep
		Classify:        queryXMLRole, // create/delete opaque; describe/list reads
		OwnerTagValue:   "sessions",
		DeterministicID: true,                            // the replication group id is chosen
		GoneCode:        "ReplicationGroupNotFoundFault", // this service's own not-found code (D522)
		// F-LC3 (D523): hand-wired — the providerId comes from the delete op.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("elasticache", "sessions", pid)
		},
		GoneEmptyList: true, // the read is a collection query (D523)
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return ecServer(t, "sessions", "true", "true", "enabled", "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("elasticache", "sessions", "prod", ecAttrs(), ecImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return ecServer(t, "sessions", "true", "true", "enabled", "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("elasticache", "sessions", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessASM(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "asm:eu-central-1:dbcreds-abcd1234"
	p := &certifynet.Probe{
		Name:            "aws/secretsmanager",
		AssertTransient: true,           // D237 sweep
		Classify:        jsonTargetRole, // create/delete opaque, Describe/Get reads
		OwnerTagValue:   "dbcreds",
		DeterministicID: true, // the secret name is the idempotency key
		// F-LC3 (D520): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("secretsmanager", "dbcreds", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return asmServer(t, "dbcreds", "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("secretsmanager", "dbcreds", "prod", asmAttrs(), asmImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return asmServer(t, "dbcreds", "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("secretsmanager", "dbcreds", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessSNS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "sns:eu-central-1:000000000000:events-prod-abcd1234"
	// public + encrypted so create issues both SetTopicAttributes mutations.
	attrs := map[string]any{
		"location.region":        "eu-central-1",
		"network.publicExposure": true,
		"encryption.atRest":      true,
		"service.managed":        true,
	}
	p := &certifynet.Probe{
		Name:            "aws/sns",
		AssertTransient: true, // D237 sweep
		Classify:        queryXMLRole,
		OwnerTagValue:   "events",
		DeterministicID: true, // the topic ARN is deterministic (region+account+name)
		// F-LC3 (D521): protocol-aware gone estate.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("sns", "events", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return snsServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("sns", "events", "prod", attrs, nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return snsServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("sns", "events", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessSQS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "sqs:eu-central-1:000000000000:orders-prod-abcd1234"
	// public + encrypted so create sets a Policy + SSE attribute at CreateQueue.
	attrs := map[string]any{
		"location.region":        "eu-central-1",
		"network.publicExposure": true,
		"encryption.atRest":      true,
		"service.managed":        true,
	}
	p := &certifynet.Probe{
		Name:            "aws/sqs",
		AssertTransient: true,         // D237 sweep
		Classify:        queryXMLRole, // CreateQueue is status-only (the URL is deterministic)
		OwnerTagValue:   "orders",
		DeterministicID: true, // the queue URL is deterministic (region+account+name)
		// F-LC3 (D522): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("sqs", "orders", pid)
		},
		GoneCode: "NonExistentQueue", // this service's own not-found code (D522)
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return sqsServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("sqs", "orders", "prod", attrs, nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return sqsServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("sqs", "orders", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessVPC(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "vpc:eu-central-1:vpc-0abc123"
	p := &certifynet.Probe{
		Name:            "aws/vpc",
		AssertTransient: true, // D237 sweep
		Classify:        queryXMLRole,
		OwnerTagValue:   "net",
		DeterministicID: false, // vpc-xxx / subnet-xxx are server-assigned
		// F-LC3 (D521): protocol-aware gone estate.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("vpc", "net", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return awsVpcServer(t, "net") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("vpc", "net", "prod", awsVpcAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return awsVpcServer(t, "net") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("vpc", "net", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// route53Role classifies Route 53 REST-XML for the honesty harness. CreateHostedZone
// PARSES the server-assigned zone id from its response; tagging and delete are
// opaque status-only mutations; GET is a read.
func route53Role(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	if req.Method == http.MethodPost && req.URL.Path == "/2013-04-01/hostedzone" {
		return certifynet.RoleMutateParsed
	}
	return certifynet.RoleMutateOpaque
}

// openSearchRole classifies OpenSearch REST-JSON for the honesty harness. GET is
// a read; CreateDomain (POST) and DeleteDomain (DELETE) are opaque status-only
// mutations (the domain name is deterministic, never parsed from the response).
func openSearchRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

func TestHonestyHarnessOpenSearch(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := openSearchProviderID("eu-central-1", "000000000000", OpenSearchDomainName("prod", "catalog", 1))
	p := &certifynet.Probe{
		Name:            "aws/opensearch",
		AssertTransient: true, // D237 sweep
		Classify:        openSearchRole,
		OwnerTagValue:   "catalog",
		DeterministicID: true, // the domain name is chosen
		// F-LC3 (D520): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("opensearch", "catalog", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return osServer(t, "catalog", true, true) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("opensearch", "catalog", "prod", osAttrs(), osImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return osServer(t, "catalog", true, true) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("opensearch", "catalog", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessRoute53(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "r53:Z123ABC"
	p := &certifynet.Probe{
		Name:            "aws/route53",
		AssertTransient: true, // D237 sweep
		Classify:        route53Role,
		OwnerTagValue:   "apex",
		DeterministicID: false, // the hosted-zone id is server-assigned
		// F-LC3 (D520): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("route53", "apex", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return r53Server(t, "apex", "false") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("route53", "apex", "prod", r53Attrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return r53Server(t, "apex", "false") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("route53", "apex", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessRolePolicy(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "aauth:app-runner:arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
	p := &certifynet.Probe{
		Name:            "aws/rolepolicy",
		AssertTransient: true,         // D237 sweep
		Classify:        queryXMLRole, // ListAttachedRolePolicies read; Attach/Detach opaque
		OwnerTagValue:   "reader",     // content-addressed: no tag to poison (foreign-tag n/a)
		DeterministicID: true,         // the pid is (roleName, policyArn)
		// F-LC3 (D522): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("rolepolicy", "reader", pid)
		},
		GoneCode: "NoSuchEntity", // this service's own not-found code (D522)
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return rolePolicyServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("rolepolicy", "reader", "prod", awsAuthzAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return rolePolicyServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("rolepolicy", "reader", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessCustomPolicy(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := customPolicyProviderID(customPolicyArn("000000000000", awsPolicyName("prod", "viewer", 1)))
	p := &certifynet.Probe{
		Name:            "aws/custompolicy",
		AssertTransient: true,         // D237 sweep
		Classify:        queryXMLRole, // GetPolicy/GetPolicyVersion read; Create/Delete opaque
		OwnerTagValue:   "viewer",     // content-addressed by Arn (foreign-tag n/a)
		DeterministicID: true,
		// F-LC3 (D522): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("custompolicy", "viewer", pid)
		},
		GoneCode: "NoSuchEntity", // this service's own not-found code (D522)
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return customPolicyServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("custompolicy", "viewer", "prod", awsRoleAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return customPolicyServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("custompolicy", "viewer", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessCloudWatchAlarm(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := cwAlarmProviderID("eu-central-1", "000000000000", alarmName("prod", "cpu", 1))
	p := &certifynet.Probe{
		Name:            "aws/cloudwatch",
		AssertTransient: true,         // D237 sweep
		Classify:        queryXMLRole, // Describe/ListTags read; Put/Delete opaque
		OwnerTagValue:   "cpu",
		DeterministicID: true, // the alarm name is deterministic
		// F-LC3 (D521): protocol-aware gone estate.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("cloudwatch", "cpu", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return cwAlarmOwnedServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("cloudwatch", "cpu", "prod", cwAlertAttrs(), cwAlertImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return cwAlarmOwnedServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("cloudwatch", "cpu", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessCWDashboard(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := cwDashProviderID(cwDashName("prod", "golden", 1))
	p := &certifynet.Probe{
		Name:            "aws/cloudwatchdash",
		AssertTransient: true,         // D237 sweep
		Classify:        queryXMLRole, // GetDashboard read; Put/Delete opaque
		OwnerTagValue:   "golden",     // content-addressed by deterministic name (foreign-tag n/a)
		DeterministicID: true,
		// F-LC3 (D521): protocol-aware gone estate.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("cloudwatchdash", "golden", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return cwDashServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("cloudwatchdash", "golden", "prod", awsDashAttrs(), awsDashImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return cwDashServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("cloudwatchdash", "golden", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// r53hcRole classifies Route 53 health check REST-XML. CreateHealthCheck PARSES the
// server-assigned Id from its response; tagging and delete are opaque; GET is a read.
func r53hcRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	if req.Method == http.MethodPost && req.URL.Path == "/2013-04-01/healthcheck" {
		return certifynet.RoleMutateParsed
	}
	return certifynet.RoleMutateOpaque
}

func TestHonestyHarnessRoute53HealthCheck(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "r53hc:hc-123"
	p := &certifynet.Probe{
		Name:            "aws/route53health",
		AssertTransient: true, // D237 sweep
		Classify:        r53hcRole,
		OwnerTagValue:   "api",
		DeterministicID: false, // the health check Id is server-assigned
		// F-LC3 (D520): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("route53health", "api", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return r53hcServer(t, "api") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("route53health", "api", "prod", hcAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return r53hcServer(t, "api") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("route53health", "api", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessCWLogFilter(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := cwLogFilterProviderID("eu-central-1", "/aws/lambda/app", logFilterName("prod", "errors", 1))
	p := &certifynet.Probe{
		Name:            "aws/cwlogfilter",
		AssertTransient: true,           // D237 sweep
		Classify:        jsonTargetRole, // DescribeMetricFilters read; Put/Delete opaque
		OwnerTagValue:   "errors",       // content-addressed by (logGroup, filterName)
		DeterministicID: true,
		// F-LC3 (D522): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("cwlogfilter", "errors", pid)
		},
		GoneCode: "ResourceNotFound", // this service's own not-found code (D522)
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return cwLogFilterServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("cwlogfilter", "errors", "prod", cwLogFilterAttrs(), cwLogFilterImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return cwLogFilterServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("cwlogfilter", "errors", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessECR(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := ecrProviderID("eu-central-1", "000000000000", ecrRepoName("prod", "images", 1))
	p := &certifynet.Probe{
		Name:            "aws/ecr",
		AssertTransient: true,           // D237 sweep
		Classify:        jsonTargetRole, // Describe/ListTags read; Create/Delete opaque
		OwnerTagValue:   "images",
		DeterministicID: true, // the repository name is deterministic
		// F-LC3 (D522): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("ecr", "images", pid)
		},
		GoneCode: "RepositoryNotFound", // this service's own not-found code (D522)
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return ecrServer(t, "images") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("ecr", "images", "prod", ecrAttrs(), ecrImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return ecrServer(t, "images") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("ecr", "images", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// efsRole classifies EFS REST-JSON for the honesty harness. CreateFileSystem
// (POST /file-systems) PARSES the server-assigned FileSystemId from its response;
// tagging and delete are opaque status-only mutations; GET is a read.
func efsRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	if req.Method == http.MethodPost && req.URL.Path == efsPath+"/file-systems" {
		return certifynet.RoleMutateParsed
	}
	return certifynet.RoleMutateOpaque
}

func TestHonestyHarnessEFS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "efs:eu-central-1:000000000000:fs-0123456789abcdef0"
	p := &certifynet.Probe{
		Name:            "aws/efs",
		AssertTransient: true, // D237 sweep
		Classify:        efsRole,
		OwnerTagValue:   "shared",
		DeterministicID: false, // the file-system id is server-assigned
		// F-LC3 (D522): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("efs", "shared", pid)
		},
		GoneCode: "FileSystemNotFound", // this service's own not-found code (D522)
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return efsServer(t, "shared", "", "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("efs", "shared", "prod", efsAttrs(), efsImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return efsServer(t, "shared", "", "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("efs", "shared", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// DeleteTable / UpdateContinuousBackups are opaque JSON mutations (jsonTargetRole),
// the table name is deterministic, so an ambiguous fault at any mutation must be
// unknown WITH the deterministic providerId.
func TestHonestyHarnessDynamoDB(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := dynamoProviderID("eu-central-1", "000000000000", DynamoTableName("prod", "sessions", 1))
	p := &certifynet.Probe{
		Name:            "aws/dynamodb",
		AssertTransient: true, // D237 sweep
		Classify:        jsonTargetRole,
		OwnerTagValue:   "sessions",
		DeterministicID: true, // the table name is chosen
		// F-LC3 (D521): protocol-aware gone estate.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("dynamodb", "sessions", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return dynamoServer(t, "sessions", true, false, true) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("dynamodb", "sessions", "prod", dynamoAttrs(), dynamoImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return dynamoServer(t, "sessions", true, false, true) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("dynamodb", "sessions", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// TestHonestyHarnessKinesis certifies the Kinesis driver (D114): CreateStream,
// AddTagsToStream, IncreaseStreamRetentionPeriod, StartStreamEncryption and
// DeleteStream are opaque JSON mutations (jsonTargetRole); the stream name is
// deterministic, so an ambiguous fault at any mutation is unknown WITH the pid.
func TestHonestyHarnessKinesis(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := kinesisProviderID("eu-central-1", "000000000000", KinesisStreamName("prod", "events", 1))
	p := &certifynet.Probe{
		Name:            "aws/kinesis",
		AssertTransient: true, // D237 sweep
		Classify:        jsonTargetRole,
		OwnerTagValue:   "events",
		DeterministicID: true, // the stream name is chosen
		// F-LC3 (D521): protocol-aware gone estate.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("kinesis", "events", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return kinesisServer(t, "events", 168, true) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("kinesis", "events", "prod", kinesisAttrs(), kinesisImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return kinesisServer(t, "events", 168, true) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("kinesis", "events", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// TestHonestyHarnessMSK certifies the MSK driver (D115): CreateClusterV2 (POST)
// and DeleteCluster (DELETE) are opaque mutations, ListClustersV2 (GET) is a read
// (method-based restXMLRole fits the REST-JSON control plane). The cluster name is
// deterministic, so an ambiguous fault at any mutation is unknown WITH the pid.
func TestHonestyHarnessMSK(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := mskProviderID("eu-central-1", "000000000000", MSKClusterName("prod", "bus", 1))
	p := &certifynet.Probe{
		Name:            "aws/msk",
		AssertTransient: true,        // D237 sweep
		Classify:        restXMLRole, // method-based: GET read, POST/DELETE opaque
		OwnerTagValue:   "bus",
		DeterministicID: true,       // the cluster name is chosen
		GoneCode:        "NotFound", // this service's own not-found code (D522)
		// F-LC3 (D523): hand-wired — the providerId comes from the delete op.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("msk", "bus", pid)
		},
		GoneEmptyList: true, // the read is a collection query (D523)
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return mskServer(t, "bus", "3.5.1", true) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("msk", "bus", "prod", mskAttrs(), mskImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return mskServer(t, "bus", "3.5.1", true) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("msk", "bus", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// TestHonestyHarnessWAF certifies the WAFv2 driver (D116): CreateWebACL /
// DeleteWebACL are opaque JSON mutations (jsonTargetRole), ListWebACLs / GetWebACL /
// ListTagsForResource are reads. The WebACL name is deterministic, so an ambiguous
// fault at any mutation is unknown WITH the pid.
func TestHonestyHarnessWAF(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := wafProviderID("000000000000", WAFACLName("prod", "edge", 1))
	p := &certifynet.Probe{
		Name:            "aws/waf",
		AssertTransient: true, // D237 sweep
		Classify:        jsonTargetRole,
		OwnerTagValue:   "edge",
		DeterministicID: true,                          // the WebACL name is chosen
		GoneCode:        "WAFNonexistentItemException", // this service's own not-found code (D522)
		// F-LC3 (D523): hand-wired — the providerId comes from the delete op.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("waf", "edge", pid)
		},
		GoneEmptyList: true, // the read is a collection query (D523)
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := newHonestyDriver(happyURL, rt)
			return d
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return wafServer(t, "edge", true, true, true) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("waf", "edge", "prod", wafAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return wafServer(t, "edge", true, true, true) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("waf", "edge", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// acmRole classifies AWS ACM JSON by X-Amz-Target. RequestCertificate is PARSED
// for the server-assigned CertificateArn the driver consumes; Describe/List are
// reads; DeleteCertificate is opaque.
func acmRole(req *http.Request, _ []byte) certifynet.Role {
	target := req.Header.Get("X-Amz-Target")
	act := target[strings.LastIndex(target, ".")+1:]
	switch {
	case isReadAction(act):
		return certifynet.RoleRead
	case act == "RequestCertificate":
		return certifynet.RoleMutateParsed
	default:
		return certifynet.RoleMutateOpaque
	}
}

func TestHonestyHarnessACM(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := acmProviderID("us-east-1", "000000000000", "12345678-1234-1234-1234-123456789012")
	p := &certifynet.Probe{
		Name:            "aws/acm",
		AssertTransient: true, // D237 sweep
		Classify:        acmRole,
		OwnerTagValue:   "web",
		DeterministicID: false, // the CertificateArn is server-assigned
		// F-LC3 (D521): protocol-aware gone estate.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("acm", "web", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := newHonestyDriver(happyURL, rt)
			d.Region = "us-east-1"
			return d
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return acmServer(t, "web", "app.example.com", "ELIGIBLE") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("acm", "web", "prod", acmAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return acmServer(t, "web", "app.example.com", "ELIGIBLE") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("acm", "web", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// TestHonestyHarnessCloudFront certifies the CloudFront driver (D118): REST-XML,
// method-based (restXMLRole — GET read, POST create / DELETE opaque). The
// distribution Id is server-assigned (DeterministicID=false), so an ambiguous create
// is unknown WITHOUT a pid (the id is not yet known); a delete carries the input pid.
func TestHonestyHarnessCloudFront(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := cfProviderID("000000000000", "E1234567890ABC")
	p := &certifynet.Probe{
		Name:            "aws/cloudfront",
		AssertTransient: true, // D237 sweep
		Classify:        restXMLRole,
		OwnerTagValue:   "edge",
		DeterministicID: false, // the distribution id is server-assigned
		// F-LC3 (D520): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("cloudfront", "edge", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := newHonestyDriver(happyURL, rt)
			d.Region = "us-east-1"
			return d
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return cfServer(t, "edge", "origin.example.com", "https-only", false) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("cloudfront", "edge", "prod", cfAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return cfServer(t, "edge", "origin.example.com", "https-only", false) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("cloudfront", "edge", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// TestHonestyHarnessApiGWv2 certifies the API Gateway v2 driver (D119): REST-JSON,
// method-based (restXMLRole — GET read, POST create / DELETE opaque). The ApiId is
// server-assigned (DeterministicID=false), so an ambiguous create is unknown WITHOUT
// a pid; a delete carries the input pid.
func TestHonestyHarnessApiGWv2(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := apigwProviderID("eu-central-1", "000000000000", "a1b2c3d4e5")
	p := &certifynet.Probe{
		Name:            "aws/apigateway",
		AssertTransient: true, // D237 sweep
		Classify:        restXMLRole,
		OwnerTagValue:   "front",
		DeterministicID: false, // the ApiId is server-assigned
		// F-LC3 (D520): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("apigateway", "front", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return apigwServer(t, "front", "HTTP") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("apigateway", "front", "prod", apigwAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return apigwServer(t, "front", "HTTP") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("apigateway", "front", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// kmsAWSRole classifies AWS KMS (JSON X-Amz-Target): CreateKey PARSES the
// server-assigned KeyId; Describe/Get/List are reads; EnableKeyRotation and
// ScheduleKeyDeletion are opaque status-only mutations.
func kmsAWSRole(req *http.Request, _ []byte) certifynet.Role {
	target := req.Header.Get("X-Amz-Target")
	act := target[strings.LastIndex(target, ".")+1:]
	switch {
	case isReadAction(act):
		return certifynet.RoleRead
	case act == "CreateKey":
		return certifynet.RoleMutateParsed
	default:
		return certifynet.RoleMutateOpaque
	}
}

func TestHonestyHarnessAWSKMS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "akms:eu-central-1:12345678-90ab-cdef-1234-567890abcdef"
	p := &certifynet.Probe{
		Name:            "aws/kms",
		AssertTransient: true, // D237 sweep
		Classify:        kmsAWSRole,
		OwnerTagValue:   "datakey",
		DeterministicID: false, // the KeyId is a server-assigned UUID
		// F-LC3 (D521): protocol-aware gone estate.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("kms", "datakey", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return awsKMSServer(t, "datakey", true, 90) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("kms", "datakey", "prod", awsKMSAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return awsKMSServer(t, "datakey", true, 90) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("kms", "datakey", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// ebsHonestyServer answers the happy path for the EBS probe: a create that names
// the volume, a describe that reports it available and owned, a delete that works.
// certifynet then injects transport faults, 5xx, garbled and empty bodies into
// each mutating call and checks the driver never converts an unknown outcome into
// a definite one.
func ebsHonestyServer(t *testing.T) *httptest.Server {
	t.Helper()
	deleted := false
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch actionOf(string(body)) {
		case "CreateVolume":
			_, _ = w.Write([]byte(ebsCreateOKXML))
		case "DescribeVolumes":
			if deleted {
				// the volume has finished deleting — the delete's poll-to-absence (D978)
				// confirms gone on the happy path.
				_, _ = w.Write([]byte(ebsEmptyXML))
				return
			}
			_, _ = w.Write([]byte(ebsAvailableXML))
		case "DeleteVolume":
			deleted = true
			_, _ = w.Write([]byte(`<DeleteVolumeResponse><return>true</return></DeleteVolumeResponse>`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

// The adversarial honesty pass for the first STATEFUL member of the compute
// family (D367). The rule it enforces matters more here than on a stateless
// resource: a create wrongly reported `failed` invites a retry, and a retry that
// is not deduplicated leaves the data split across two volumes — a failure the
// operator discovers later, from the half that is missing writes.
func TestHonestyHarnessEBS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "ebs:eu-central-1:000000000000:vol-0123456789abcdef0"
	p := &certifynet.Probe{
		Name:            "aws/ebs",
		AssertTransient: true, // D237 sweep
		Classify:        queryXMLRole,
		OwnerTagValue:   "orders-data",
		DeterministicID: false, // vol-xxx is server-assigned
		// F-LC3 (D521): protocol-aware gone estate.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("ebs", "orders-data", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return ebsHonestyServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("ebs", "orders-data", "production", ebsVolAttrs(), ebsVolImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return ebsHonestyServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("ebs", "orders-data", "production", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// asgHonestyServer answers the happy path for the fleet probe: the two
// preflights, the group create, the policy, the read-back and the delete.
func asgHonestyServer(t *testing.T) *httptest.Server {
	t.Helper()
	deleted := false
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch actionOf(string(body)) {
		case "DescribeSubnets":
			_, _ = w.Write([]byte(asgTwoZonesXML))
		case "DescribeLaunchTemplateVersions":
			_, _ = w.Write([]byte(asgPrivateTemplateXML))
		case "DescribeAutoScalingGroups":
			if deleted {
				// the group has finished deleting — the delete's poll-to-absence (D977)
				// confirms gone on the happy path.
				_, _ = w.Write([]byte(`<DescribeAutoScalingGroupsResponse><DescribeAutoScalingGroupsResult><AutoScalingGroups/></DescribeAutoScalingGroupsResult></DescribeAutoScalingGroupsResponse>`))
				return
			}
			_, _ = w.Write([]byte(asgGroupXML))
		case "DescribePolicies":
			_, _ = w.Write([]byte(asgHasPolicyXML))
		case "CreateAutoScalingGroup":
			_, _ = w.Write([]byte(`<CreateAutoScalingGroupResponse/>`))
		case "PutScalingPolicy":
			_, _ = w.Write([]byte(`<PutScalingPolicyResponse/>`))
		case "DeleteAutoScalingGroup":
			deleted = true
			_, _ = w.Write([]byte(`<DeleteAutoScalingGroupResponse/>`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

// The adversarial honesty pass for a fleet (D371). The stake here is neither
// data nor a single machine: it is a BILL. A create wrongly reported `failed`
// invites a retry, and a second fleet does not sit idle — it scales, and it keeps
// scaling until somebody notices.
func TestHonestyHarnessASG(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "asg:eu-central-1:000000000000:groundhold-web-fleet-production"
	p := &certifynet.Probe{
		Name:            "aws/asg",
		AssertTransient: true, // D237 sweep
		Classify:        queryXMLRole,
		OwnerTagValue:   "web-fleet",
		DeterministicID: true, // the group name is a chosen slug
		// F-LC3 (D521): protocol-aware gone estate.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("asg", "web-fleet", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := newHonestyDriver(happyURL, rt)
			d.AutoScalingBaseURL = happyURL
			return d
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return asgHonestyServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("asg", "web-fleet", "production", asgAttrs(), asgImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return asgHonestyServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("asg", "web-fleet", "production", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}
