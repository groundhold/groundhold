package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"groundhold/internal/provider"
)

// capture records, per httptest request, the operation token (the JSON X-Amz-
// Target, or the Query-protocol Action=) and whether the request was SigV4-
// signed — so a discovery test can assert the LIST call was made, was signed,
// and that a forbidden operation (GetSecretValue, D53) never was.
type capture struct {
	mu     sync.Mutex
	ops    map[string]int
	unsign int
}

func newCapture() *capture { return &capture{ops: map[string]int{}} }

func (c *capture) record(r *http.Request, body string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
		c.unsign++
	}
	if t := r.Header.Get("X-Amz-Target"); t != "" {
		if i := strings.LastIndex(t, "."); i >= 0 {
			t = t[i+1:]
		}
		c.ops[t]++
		return
	}
	if a := formAction(body); a != "" {
		c.ops[a]++
	}
}

func (c *capture) saw(op string) bool { c.mu.Lock(); defer c.mu.Unlock(); return c.ops[op] > 0 }

func formAction(body string) string {
	i := strings.Index(body, "Action=")
	if i < 0 {
		return ""
	}
	s := body[i+len("Action="):]
	if j := strings.IndexByte(s, '&'); j >= 0 {
		s = s[:j]
	}
	return s
}

// discoverServer answers every swept service — the original six (S3, RDS,
// DynamoDB, ElastiCache, SNS, SQS) plus the D86-stack additions (ECS, VPC, IAM
// roles + grants, Secrets Manager, CloudWatch alarms, ECR) — so a single List()
// sweep can be asserted end to end. Every response is a valid, minimal fixture:
// each new sweep surfaces exactly one resource.
func discoverServer(t *testing.T, rec *capture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.RawQuery
			path := r.URL.Path
			target := r.Header.Get("X-Amz-Target")
			var body string
			if r.Method == http.MethodPost {
				b, _ := io.ReadAll(r.Body)
				body = string(b)
			}
			if rec != nil {
				rec.record(r, body)
			}
			switch {
			// ---- DynamoDB (JSON protocol, keyed by X-Amz-Target) ----
			case strings.HasSuffix(target, ".ListTables"):
				_, _ = w.Write([]byte(`{"TableNames":["sessions"]}`))
			case strings.HasSuffix(target, ".DescribeTable"):
				_, _ = w.Write([]byte(`{"Table":{"TableStatus":"ACTIVE",` +
					`"TableArn":"arn:aws:dynamodb:eu-central-1:000000000000:table/sessions",` +
					`"SSEDescription":{"Status":"ENABLED","SSEType":"KMS","KMSMasterKeyArn":"arn:aws:kms:eu-central-1:000000000000:key/abc"}}}`))
			case strings.HasSuffix(target, ".DescribeContinuousBackups"):
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))

			// ---- ECS (JSON protocol) ----
			case strings.HasSuffix(target, ".ListClusters"):
				_, _ = w.Write([]byte(`{"clusterArns":["arn:aws:ecs:eu-central-1:000000000000:cluster/broker"]}`))
			case strings.HasSuffix(target, ".ListServices"):
				_, _ = w.Write([]byte(`{"serviceArns":["arn:aws:ecs:eu-central-1:000000000000:service/broker/broker"]}`))
			case strings.HasSuffix(target, ".DescribeServices"):
				_, _ = w.Write([]byte(`{"services":[{"status":"ACTIVE","runningCount":2,"desiredCount":2,` +
					`"launchType":"FARGATE","networkConfiguration":{"awsvpcConfiguration":{"assignPublicIp":"DISABLED"}},` +
					`"deployments":[{"rolloutState":"COMPLETED"}],` +
					`"tags":[{"key":"groundhold-capability","value":"vendor-broker"},{"key":"groundhold-environment","value":"prod"}]}]}`))

			// ---- ECR (JSON protocol; serves both DescribeRepositories forms) ----
			case strings.HasSuffix(target, ".DescribeRepositories"):
				_, _ = w.Write([]byte(`{"repositories":[{"repositoryName":"vendor-broker",` +
					`"imageTagMutability":"IMMUTABLE","encryptionConfiguration":{"encryptionType":"KMS"}}]}`))

			// ---- Secrets Manager (JSON protocol). GetSecretValue is NEVER wired
			// (D53): if a discoverer ever asked for it, the request would 501. ----
			case strings.HasSuffix(target, ".ListSecrets"):
				_, _ = w.Write([]byte(`{"SecretList":[{"Name":"vendor-broker-db","ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:vendor-broker-db-AbCdEf"}]}`))
			case strings.HasSuffix(target, ".DescribeSecret"):
				_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:vendor-broker-db-AbCdEf",` +
					`"Name":"vendor-broker-db","KmsKeyId":"alias/aws/secretsmanager",` +
					`"Tags":[{"Key":"groundhold-capability","Value":"vendor-broker"}]}`))
			case strings.HasSuffix(target, ".GetResourcePolicy"):
				_, _ = w.Write([]byte(`{"ResourcePolicy":""}`))
			case strings.HasSuffix(target, ".GetSecretValue"):
				w.WriteHeader(http.StatusNotImplemented) // D53 tripwire — must never fire

			// ---- RDS (Query protocol) ----
			case r.Method == http.MethodPost && strings.Contains(body, "DescribeDBInstances"):
				_, _ = w.Write([]byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances>` +
					`<DBInstance><DBInstanceIdentifier>prod-db</DBInstanceIdentifier>` +
					`<DBInstanceStatus>available</DBInstanceStatus><Engine>postgres</Engine>` +
					`<StorageEncrypted>true</StorageEncrypted><PubliclyAccessible>false</PubliclyAccessible>` +
					`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
			// ---- ElastiCache ----
			case r.Method == http.MethodPost && strings.Contains(body, "DescribeReplicationGroups"):
				_, _ = w.Write([]byte(`<DescribeReplicationGroupsResponse><DescribeReplicationGroupsResult><ReplicationGroups>` +
					`<ReplicationGroup><ReplicationGroupId>cache-1</ReplicationGroupId><Status>available</Status>` +
					`<AtRestEncryptionEnabled>true</AtRestEncryptionEnabled><TransitEncryptionEnabled>true</TransitEncryptionEnabled>` +
					`</ReplicationGroup></ReplicationGroups></DescribeReplicationGroupsResult></DescribeReplicationGroupsResponse>`))
			// ---- SNS ----
			case r.Method == http.MethodPost && strings.Contains(body, "ListTopics"):
				_, _ = w.Write([]byte(`<ListTopicsResponse><ListTopicsResult><Topics>` +
					`<member><TopicArn>arn:aws:sns:eu-central-1:000000000000:alerts</TopicArn></member>` +
					`</Topics></ListTopicsResult></ListTopicsResponse>`))
			case r.Method == http.MethodPost && strings.Contains(body, "GetTopicAttributes"):
				_, _ = w.Write([]byte(`<GetTopicAttributesResponse><GetTopicAttributesResult><Attributes>` +
					`<entry><key>TopicArn</key><value>arn:aws:sns:eu-central-1:000000000000:alerts</value></entry>` +
					`</Attributes></GetTopicAttributesResult></GetTopicAttributesResponse>`))
			// ---- SQS ----
			case r.Method == http.MethodPost && strings.Contains(body, "ListQueues"):
				_, _ = w.Write([]byte(`<ListQueuesResponse><ListQueuesResult>` +
					`<QueueUrl>https://sqs.eu-central-1.amazonaws.com/000000000000/jobs</QueueUrl>` +
					`</ListQueuesResult></ListQueuesResponse>`))
			case r.Method == http.MethodPost && strings.Contains(body, "GetQueueAttributes"):
				_, _ = w.Write([]byte(`<GetQueueAttributesResponse><GetQueueAttributesResult>` +
					`<Attribute><Name>QueueArn</Name><Value>arn:aws:sqs:eu-central-1:000000000000:jobs</Value></Attribute>` +
					`</GetQueueAttributesResult></GetQueueAttributesResponse>`))

			// ---- VPC / EC2 (Query protocol; DescribeVpcs serves list + observe) ----
			case r.Method == http.MethodPost && strings.Contains(body, "DescribeVpcs"):
				_, _ = w.Write([]byte(`<DescribeVpcsResponse><vpcSet><item>` +
					`<vpcId>vpc-0abc123</vpcId>` +
					`<tagSet><item><key>groundhold-capability</key><value>vendor-broker</value></item></tagSet>` +
					`</item></vpcSet></DescribeVpcsResponse>`))
			case r.Method == http.MethodPost && strings.Contains(body, "DescribeInternetGateways"):
				_, _ = w.Write([]byte(`<DescribeInternetGatewaysResponse><internetGatewaySet></internetGatewaySet></DescribeInternetGatewaysResponse>`))
			case r.Method == http.MethodPost && strings.Contains(body, "DescribeFlowLogs"):
				_, _ = w.Write([]byte(`<DescribeFlowLogsResponse><flowLogSet></flowLogSet></DescribeFlowLogsResponse>`))

			// ---- IAM (Query protocol, global) ----
			case r.Method == http.MethodPost && strings.Contains(body, "ListRoles"):
				_, _ = w.Write([]byte(`<ListRolesResponse><ListRolesResult><Roles>` +
					`<member><RoleName>pv-broker-abcd1234</RoleName>` +
					`<Arn>arn:aws:iam::000000000000:role/pv-broker-abcd1234</Arn>` +
					`<Description>vendor broker task role</Description></member>` +
					`</Roles></ListRolesResult></ListRolesResponse>`))
			case r.Method == http.MethodPost && strings.Contains(body, "GetRole"):
				_, _ = w.Write([]byte(`<GetRoleResponse><GetRoleResult><Role>` +
					`<RoleName>pv-broker-abcd1234</RoleName>` +
					`<Arn>arn:aws:iam::000000000000:role/pv-broker-abcd1234</Arn>` +
					`<Description>vendor broker task role</Description>` +
					`<Tags><member><Key>groundhold-capability</Key><Value>vendor-broker</Value></member></Tags>` +
					`</Role></GetRoleResult></GetRoleResponse>`))
			case r.Method == http.MethodPost && strings.Contains(body, "ListAttachedRolePolicies"):
				_, _ = w.Write([]byte(`<ListAttachedRolePoliciesResponse><ListAttachedRolePoliciesResult><AttachedPolicies>` +
					`<member><PolicyArn>arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy</PolicyArn></member>` +
					`</AttachedPolicies></ListAttachedRolePoliciesResult></ListAttachedRolePoliciesResponse>`))

			// ---- ELBv2 (Query protocol; DescribeLoadBalancers -> per-LB DescribeListeners) ----
			case r.Method == http.MethodPost && strings.Contains(body, "DescribeLoadBalancers"):
				_, _ = w.Write([]byte(`<DescribeLoadBalancersResponse><DescribeLoadBalancersResult><LoadBalancers><member>` +
					`<LoadBalancerArn>arn:aws:elasticloadbalancing:eu-central-1:000000000000:loadbalancer/app/broker-alb/50dc6c495c0c9188</LoadBalancerArn>` +
					`<LoadBalancerName>broker-alb</LoadBalancerName><Scheme>internet-facing</Scheme>` +
					`<Type>application</Type><VpcId>vpc-0abc123</VpcId><State><Code>active</Code></State>` +
					`</member></LoadBalancers></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>`))
			case r.Method == http.MethodPost && strings.Contains(body, "DescribeListeners"):
				_, _ = w.Write([]byte(`<DescribeListenersResponse><DescribeListenersResult><Listeners><member>` +
					`<Protocol>HTTPS</Protocol><Port>443</Port>` +
					`<ListenerArn>arn:aws:elasticloadbalancing:eu-central-1:000000000000:listener/app/broker-alb/50dc6c495c0c9188/f2f7dc8efc522ab2</ListenerArn>` +
					`</member></Listeners></DescribeListenersResult></DescribeListenersResponse>`))

			// ---- CloudWatch (Query protocol; DescribeAlarms serves list + observe) ----
			case r.Method == http.MethodPost && strings.Contains(body, "DescribeAlarms"):
				_, _ = w.Write([]byte(`<DescribeAlarmsResponse><DescribeAlarmsResult><MetricAlarms>` +
					`<member><AlarmName>broker-cpu</AlarmName><Namespace>AWS/ECS</Namespace>` +
					`<MetricName>CPUUtilization</MetricName><Threshold>80.0</Threshold>` +
					`<ComparisonOperator>GreaterThanThreshold</ComparisonOperator>` +
					`<AlarmActions><member>arn:aws:sns:eu-central-1:000000000000:alerts</member></AlarmActions>` +
					`</member></MetricAlarms></DescribeAlarmsResult></DescribeAlarmsResponse>`))

			// ---- S3 ----
			case path == "/" && q == "":
				_, _ = w.Write([]byte(`<ListAllMyBucketsResult><Buckets>` +
					`<Bucket><Name>here-bucket</Name></Bucket>` +
					`<Bucket><Name>far-bucket</Name></Bucket>` +
					`</Buckets></ListAllMyBucketsResult>`))
			case q == "location" && strings.Contains(path, "here-bucket"):
				_, _ = w.Write([]byte(`<LocationConstraint>eu-central-1</LocationConstraint>`))
			case q == "location" && strings.Contains(path, "far-bucket"):
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`<Error><Code>AuthorizationHeaderMalformed</Code></Error>`))
			case q == "versioning":
				_, _ = w.Write([]byte(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`))
			case q == "policyStatus":
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`<Error><Code>NoSuchBucketPolicy</Code></Error>`))
			case q == "tagging":
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`<Error><Code>NoSuchTagSet</Code></Error>`))
			default:
				w.WriteHeader(http.StatusOK)
			}
		}))
}

func discoverDriver(t *testing.T, srv *httptest.Server) *Driver {
	d := s3TestDriver(t, srv) // sets S3BaseURL, creds, Account (skips STS)
	d.RDSBaseURL = srv.URL
	d.DynamoDBBaseURL = srv.URL
	d.ElastiCacheBaseURL = srv.URL
	d.SNSBaseURL = srv.URL
	d.SQSBaseURL = srv.URL
	// D86-stack additions
	d.ECSBaseURL = srv.URL
	d.EC2BaseURL = srv.URL
	d.IAMBaseURL = srv.URL
	d.SecretsManagerBaseURL = srv.URL
	d.CloudWatchBaseURL = srv.URL
	d.ECRBaseURL = srv.URL
	d.ELBv2BaseURL = srv.URL
	d.EKSBaseURL = srv.URL // D149 eks-podidentity discovery — else it dials real AWS and hangs CI
	return d
}

func TestListDiscoversAcrossServices(t *testing.T) {
	rec := newCapture()
	srv := discoverServer(t, rec)
	defer srv.Close()
	d := discoverDriver(t, srv)

	found, diags, err := d.List("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	byType := map[string]provider.Discovered{}
	for _, f := range found {
		byType[f.ResourceType] = f
	}
	wantID := map[string]string{
		"capability.storage.object":          "s3:eu-central-1:here-bucket",
		"capability.database.relational":     "rds:eu-central-1:prod-db",
		"capability.database.nosql":          "dynamodb:eu-central-1:000000000000:sessions",
		"capability.cache.keyvalue":          "ecredis:eu-central-1:000000000000:cache-1",
		"capability.messaging.topic":         "sns:eu-central-1:000000000000:alerts",
		"capability.messaging.queue":         "sqs:eu-central-1:000000000000:jobs",
		"capability.workload.container":      "ecs:eu-central-1:broker",
		"capability.network.private":         "vpc:eu-central-1:vpc-0abc123",
		"capability.identity.serviceaccount": "iamrole:000000000000:pv-broker-abcd1234",
		"capability.authorization.grant":     "aauth:pv-broker-abcd1234:arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
		"capability.secret":                  "asm:eu-central-1:vendor-broker-db",
		"capability.monitoring.alert":        "awsalert:eu-central-1:000000000000:broker-cpu",
		"capability.registry.image":          "ecr:eu-central-1:000000000000:vendor-broker",
		"capability.network.loadbalancer":    "elbv2:eu-central-1:broker-alb",
	}
	if len(found) != len(wantID) {
		t.Fatalf("want %d resources across the swept services, got %d: %+v (diags %v)",
			len(wantID), len(found), found, diags)
	}
	for typ, id := range wantID {
		if got := byType[typ].ProviderID; got != id {
			t.Fatalf("%s providerId = %q, want %q", typ, got, id)
		}
	}

	// each carries the SAME reverse-mapped observations observe would record.
	rds := obsMap(byType["capability.database.relational"])
	if rds["encryption.atRest"] != true || rds["network.publicExposure"] != false {
		t.Fatalf("rds observations = %+v", rds)
	}
	ecs := obsMap(byType["capability.workload.container"])
	if ecs["network.publicExposure"] != false || ecs["replicas.minimum"] != float64(2) {
		t.Fatalf("ecs observations = %+v", ecs)
	}
	vpc := obsMap(byType["capability.network.private"])
	if vpc["ingress.public"] != false || vpc["flowLogs.enabled"] != false {
		t.Fatalf("vpc observations = %+v", vpc)
	}
	ecr := obsMap(byType["capability.registry.image"])
	if ecr["immutable.tags"] != true || ecr["encryption.customerManagedKeys"] != true {
		t.Fatalf("ecr observations = %+v", ecr)
	}
	sec := obsMap(byType["capability.secret"])
	if sec["encryption.atRest"] != true || sec["network.publicExposure"] != false {
		t.Fatalf("secret observations = %+v", sec)
	}
	alarm := obsMap(byType["capability.monitoring.alert"])
	if alarm["alert.threshold"] != float64(80) || alarm["alert.comparison"] != "greater-than" {
		t.Fatalf("alarm observations = %+v", alarm)
	}
	grant := obsMap(byType["capability.authorization.grant"])
	if grant["grant.principal"] != "pv-broker-abcd1234" {
		t.Fatalf("grant observations = %+v", grant)
	}
	lb := obsMap(byType["capability.network.loadbalancer"])
	if lb["network.publicExposure"] != true || lb["encryption.inTransit"] != true {
		t.Fatalf("the public HTTPS ALB must reverse-map to public+inTransit, got %+v", lb)
	}

	// the LIST call of every new sweep was made AND SigV4-signed.
	for _, op := range []string{"ListClusters", "DescribeVpcs", "ListRoles",
		"ListAttachedRolePolicies", "ListSecrets", "DescribeAlarms", "DescribeRepositories",
		"DescribeLoadBalancers", "DescribeListeners"} {
		if !rec.saw(op) {
			t.Fatalf("expected the sweep to issue %s", op)
		}
	}
	if rec.unsign != 0 {
		t.Fatalf("every discovery request must be SigV4-signed; %d were not", rec.unsign)
	}
	// D53: the secret VALUE is never read during discovery.
	if rec.saw("GetSecretValue") {
		t.Fatal("D53 violated: discovery must never call GetSecretValue")
	}
}

func obsMap(d provider.Discovered) map[string]any {
	m := map[string]any{}
	for _, o := range d.Observations {
		m[o.Path] = o.Value
	}
	return m
}

func TestListRequiresRegion(t *testing.T) {
	srv := discoverServer(t, nil)
	defer srv.Close()
	d := discoverDriver(t, srv)
	if _, _, err := d.List(""); err == nil {
		t.Fatal("discovery without a region must refuse")
	}
}

// TestDiscoverPerSweepIsolation proves one service's failure does not sink the
// others: an ECS ListClusters that 500s becomes a diagnostic while every other
// sweep still returns its resource (per-sweep isolation).
func TestDiscoverPerSweepIsolation(t *testing.T) {
	inner := discoverServer(t, nil)
	defer inner.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".ListClusters") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"__type":"ServerException"}`))
			return
		}
		// delegate everything else to the full fixture handler
		inner.Config.Handler.ServeHTTP(w, r)
	}))
	defer srv.Close()
	d := discoverDriver(t, srv)

	found, diags, err := d.List("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		if f.ResourceType == "capability.workload.container" {
			t.Fatal("a 500 on ListClusters must not yield an ECS resource")
		}
	}
	// the other sweeps still landed
	if len(found) == 0 {
		t.Fatal("one failing sweep sank the whole discovery")
	}
	var sawECSDiag bool
	for _, dg := range diags {
		if strings.Contains(dg, "ecs ListClusters") {
			sawECSDiag = true
		}
	}
	if !sawECSDiag {
		t.Fatalf("the ECS failure must surface as a diagnostic, got %v", diags)
	}
}
