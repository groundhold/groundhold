package aws

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// D275: typed create outputs. Derivation is pid-based (the identity resume
// reconciles by), so every succeeded path — fresh create, idempotent hit,
// create-adoption — receipts the same truthful set.

func TestDeriveOutputsFromPid(t *testing.T) {
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	cases := []struct {
		service, pid string
		want         map[string]any
	}{
		{"s3", "s3:eu-central-1:my-bucket", map[string]any{
			"bucketName": "my-bucket",
			"bucketArn":  "arn:aws:s3:::my-bucket"}},
		{"sns", "sns:eu-central-1:000000000000:alerts", map[string]any{
			"topicArn": "arn:aws:sns:eu-central-1:000000000000:alerts"}},
		{"kms", "akms:eu-central-1:1234abcd-12ab-34cd-56ef-1234567890ab", map[string]any{
			"keyId":  "1234abcd-12ab-34cd-56ef-1234567890ab",
			"keyArn": "arn:aws:kms:eu-central-1:000000000000:key/1234abcd-12ab-34cd-56ef-1234567890ab"}},
		{"acm", "acm:eu-central-1:000000000000:1cf48e24-aaaa-bbbb-cccc-000000000000", map[string]any{
			"certificateArn": "arn:aws:acm:eu-central-1:000000000000:certificate/1cf48e24-aaaa-bbbb-cccc-000000000000"}},
		{"eks", "eks:eu-central-1:acme", map[string]any{
			"clusterName": "acme", "region": "eu-central-1"}},
		{"iam", "iamrole:000000000000:pv-api-prod-abcdefgh", map[string]any{
			"roleName": "pv-api-prod-abcdefgh",
			"roleArn":  "arn:aws:iam::000000000000:role/pv-api-prod-abcdefgh"}},
		{"ecr", "ecr:eu-central-1:000000000000:pv-app-prod-1a2b3c4d", map[string]any{
			"repositoryUri": "000000000000.dkr.ecr.eu-central-1.amazonaws.com/pv-app-prod-1a2b3c4d",
			"repositoryArn": "arn:aws:ecr:eu-central-1:000000000000:repository/pv-app-prod-1a2b3c4d"}},
		{"backupvault", "bkv:eu-central-1:000000000000:pv-backup-prod", map[string]any{
			"vaultName": "pv-backup-prod",
			"vaultArn":  "arn:aws:backup:eu-central-1:000000000000:backup-vault:pv-backup-prod"}},
	}
	for _, c := range cases {
		got, err := d.deriveOutputs(c.service, c.pid)
		if err != nil {
			t.Fatalf("%s: %v", c.service, err)
		}
		if len(got) != len(c.want) {
			t.Fatalf("%s: outputs %v, want %v", c.service, got, c.want)
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Fatalf("%s: output %s = %v, want %v", c.service, k, got[k], v)
			}
		}
		// every derived output must be declared, and vice versa — the table
		// and the derivation cannot drift apart
		specs := d.OutputsFor(c.service)
		if len(specs) != len(got) {
			t.Fatalf("%s: OutputsFor declares %d, derivation yields %d", c.service, len(specs), len(got))
		}
		for _, s := range specs {
			if _, ok := got[s.Name]; !ok {
				t.Fatalf("%s: declared output %s not derived", c.service, s.Name)
			}
		}
	}
}

// TestEveryDeclaredServiceDerives pins table<->derivation completeness for the
// non-network services: a service added to awsOutputs without a derivation arm
// (or vice versa) must fail here, not at a customer's receipt gate.
func TestEveryDeclaredServiceDerives(t *testing.T) {
	pids := map[string]string{
		"s3":          "s3:eu-central-1:my-bucket",
		"sns":         "sns:eu-central-1:000000000000:topic",
		"kms":         "akms:eu-central-1:1234abcd-12ab-34cd-56ef-1234567890ab",
		"acm":         "acm:eu-central-1:000000000000:1cf48e24-aaaa-bbbb-cccc-000000000000",
		"eks":         "eks:eu-central-1:1cf48e24-aaaa-bbbb-cccc-000000000000",
		"iam":         "iamrole:000000000000:role",
		"ecr":         "ecr:eu-central-1:000000000000:pv-app-prod-1a2b3c4d",
		"backupvault": "bkv:eu-central-1:000000000000:pv-backup-prod",
		"vpc":         "", // network-reading derivation, covered by TestClassifyVpcSubnets
		// network-reading derivation (the endpoint address is server-assigned, read
		// live), covered by TestElastiCacheServerlessEndpointOutput
		"elasticache-serverless": "",
		// network-reading derivation (the cluster endpoints are server-assigned, read
		// live), covered by TestAuroraEndpointOutput
		"aurora": "",
		// network-reading derivation (the Function URL host is server-assigned, read
		// live), covered by TestLambdaFunctionURLOutputs
		"lambda": "",
		// network-reading derivation (the edge domainName is server-assigned, read
		// live), covered by TestCloudFrontOACEdgePattern
		"cloudfront": "",
	}
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	for svc := range awsOutputs {
		pid, known := pids[svc]
		if !known {
			t.Fatalf("service %s declares outputs but this completeness test does not know it — add it", svc)
		}
		if pid == "" {
			continue
		}
		if _, err := d.deriveOutputs(svc, pid); err != nil {
			t.Fatalf("%s: %v", svc, err)
		}
	}
}

func TestAttachOutputsUnderivableDemotesToUnknown(t *testing.T) {
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	cr := provider.CreateResult{ProviderID: "akms:not-a-region:zzz", Status: "succeeded"}
	d.attachOutputs("kms", &cr)
	if cr.Status != "unknown" {
		t.Fatalf("underivable outputs must demote to unknown, got %+v", cr)
	}
	// a service with no declared outputs is untouched
	cr = provider.CreateResult{ProviderID: "sqs:eu-central-1:000000000000:q", Status: "succeeded"}
	d.attachOutputs("sqs", &cr)
	if cr.Status != "succeeded" || cr.Outputs != nil {
		t.Fatalf("a non-declaring service must pass through untouched, got %+v", cr)
	}
}

// TestAuroraEndpointOutput: the writer/reader/port outputs are derived from one
// live DescribeDBClusters read (the endpoints are server-assigned, not in the
// pid), the honest source for a created OR adopted cluster.
func TestAuroraEndpointOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		if !strings.Contains(string(b), "Action=DescribeDBClusters") {
			t.Errorf("unexpected RDS action in %q", string(b))
			w.WriteHeader(400)
			return
		}
		fmt.Fprint(w, `<DescribeDBClustersResponse><DescribeDBClustersResult><DBClusters><DBCluster>`+
			`<DBClusterIdentifier>db</DBClusterIdentifier><Status>available</Status>`+
			`<Endpoint>db.cluster-abc123.eu-central-1.rds.amazonaws.com</Endpoint>`+
			`<ReaderEndpoint>db.cluster-ro-abc123.eu-central-1.rds.amazonaws.com</ReaderEndpoint>`+
			`<Port>5432</Port>`+
			`</DBCluster></DBClusters></DescribeDBClustersResult></DescribeDBClustersResponse>`)
	}))
	defer srv.Close()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.RDSBaseURL = srv.URL
	d.Account = "000000000000"

	outs, err := d.deriveOutputs("aurora", "aurora:eu-central-1:db")
	if err != nil {
		t.Fatal(err)
	}
	if outs["writerEndpoint"] != "db.cluster-abc123.eu-central-1.rds.amazonaws.com" {
		t.Fatalf("writerEndpoint = %v", outs["writerEndpoint"])
	}
	if outs["readerEndpoint"] != "db.cluster-ro-abc123.eu-central-1.rds.amazonaws.com" {
		t.Fatalf("readerEndpoint = %v", outs["readerEndpoint"])
	}
	if outs["port"] != "5432" {
		t.Fatalf("port = %v", outs["port"])
	}
}

func TestClassifyVpcSubnets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		body := string(b)
		switch {
		case strings.Contains(body, "Action=DescribeSubnets"):
			fmt.Fprint(w, `<DescribeSubnetsResponse><subnetSet>
				<item><subnetId>subnet-priv-b</subnetId></item>
				<item><subnetId>subnet-priv-a</subnetId></item>
				<item><subnetId>subnet-pub-1</subnetId></item>
				<item><subnetId>subnet-main-fallback</subnetId></item>
			</subnetSet></DescribeSubnetsResponse>`)
		case strings.Contains(body, "Action=DescribeRouteTables"):
			fmt.Fprint(w, `<DescribeRouteTablesResponse><routeTableSet>
				<item><routeTableId>rtb-main</routeTableId>
					<routeSet><item><destinationCidrBlock>0.0.0.0/0</destinationCidrBlock><natGatewayId>nat-1</natGatewayId></item></routeSet>
					<associationSet><item><main>true</main></item></associationSet>
				</item>
				<item><routeTableId>rtb-pub</routeTableId>
					<routeSet><item><destinationCidrBlock>0.0.0.0/0</destinationCidrBlock><gatewayId>igw-1</gatewayId></item></routeSet>
					<associationSet><item><subnetId>subnet-pub-1</subnetId></item></associationSet>
				</item>
				<item><routeTableId>rtb-priv</routeTableId>
					<routeSet><item><destinationCidrBlock>10.0.0.0/16</destinationCidrBlock><gatewayId>local</gatewayId></item></routeSet>
					<associationSet><item><subnetId>subnet-priv-a</subnetId></item><item><subnetId>subnet-priv-b</subnetId></item></associationSet>
				</item>
			</routeTableSet></DescribeRouteTablesResponse>`)
		default:
			t.Errorf("unexpected EC2 action in %q", body)
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.EC2BaseURL = srv.URL
	d.Account = "000000000000"

	outs, err := d.deriveOutputs("vpc", "vpc:eu-central-1:vpc-0abc123")
	if err != nil {
		t.Fatal(err)
	}
	if outs["vpcId"] != "vpc-0abc123" || outs["region"] != "eu-central-1" {
		t.Fatalf("vpcId/region = %v / %v", outs["vpcId"], outs["region"])
	}
	// sorted; the association-less subnet falls back to the MAIN table, whose
	// 0/0 goes to a NAT — private, not public
	priv := fmt.Sprint(outs["privateSubnetIds"])
	pub := fmt.Sprint(outs["publicSubnetIds"])
	if priv != "[subnet-main-fallback subnet-priv-a subnet-priv-b]" {
		t.Fatalf("privateSubnetIds = %s", priv)
	}
	if pub != "[subnet-pub-1]" {
		t.Fatalf("publicSubnetIds = %s", pub)
	}
}
