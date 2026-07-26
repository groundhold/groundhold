package aws

import (
	"net/url"
	"strings"
	"testing"
)

// q builds an AWS Query form body from field pairs.
func q(fields map[string]string) []byte {
	v := url.Values{}
	for k, val := range fields {
		v.Set(k, val)
	}
	return []byte(v.Encode())
}

// TestWireContractCatchesF10: the regression that motivated the gate — a
// CreateDBCluster without any master credential must be refused at the wire, BEFORE
// signing. This is the exact request the Aurora driver used to send.
func TestWireContractCatchesF10(t *testing.T) {
	err := enforceAWSWireContract(nil, q(map[string]string{
		"Action":              "CreateDBCluster",
		"DBClusterIdentifier": "acme-aurora",
		"Engine":              "aurora-postgresql",
		"DBSubnetGroupName":   "acme-db",
		// no MasterUsername, no ManageMasterUserPassword — the F10 bug
	}))
	if err == nil {
		t.Fatal("CreateDBCluster without a master credential must be refused at the wire")
	}
	if !strings.Contains(err.Error(), "MasterUsername") {
		t.Fatalf("refusal must name the missing field, got: %v", err)
	}
}

func TestWireContractHonorsValidRequests(t *testing.T) {
	ok := []map[string]string{
		{"Action": "CreateDBCluster", "DBClusterIdentifier": "c", "Engine": "aurora-postgresql",
			"MasterUsername": "admin", "MasterUserPassword": "pw"},
		{"Action": "CreateDBCluster", "DBClusterIdentifier": "c", "Engine": "aurora-postgresql",
			"MasterUsername": "admin", "ManageMasterUserPassword": "true"}, // AWS-managed secret
		{"Action": "CreateDBCluster", "DBClusterIdentifier": "c", "Engine": "aurora-postgresql",
			"SnapshotIdentifier": "snap-1"}, // snapshot restore waives master creds
		{"Action": "DescribeDBClusters", "DBClusterIdentifier": "c"}, // a read — no contract
		{"Action": "CreateDBInstance", "DBInstanceIdentifier": "i", "Engine": "aurora-postgresql",
			"DBInstanceClass": "db.serverless", "DBClusterIdentifier": "c"}, // cluster member inherits creds
	}
	for i, f := range ok {
		if err := enforceAWSWireContract(nil, q(f)); err != nil {
			t.Errorf("case %d must pass, got: %v", i, err)
		}
	}
}

func TestWireContractRefusesFloorAndConditional(t *testing.T) {
	bad := []map[string]string{
		{"Action": "CreateDBCluster", "DBClusterIdentifier": "c", "MasterUsername": "a", "MasterUserPassword": "p"}, // no Engine (floor)
		{"Action": "CreateDBInstance", "DBInstanceIdentifier": "i", "Engine": "postgres"},                           // no DBInstanceClass + no creds/cluster
	}
	for i, f := range bad {
		if err := enforceAWSWireContract(nil, q(f)); err == nil {
			t.Errorf("case %d must be refused", i)
		}
	}
}

// TestWireContractIgnoresNonQuery: JSON-protocol bodies and empty bodies are out
// of scope for this gate (no Action form field) — never a false refusal.
func TestWireContractIgnoresNonQuery(t *testing.T) {
	for _, b := range [][]byte{
		nil,
		[]byte(`{"KeyId":"abc"}`), // KMS JSON
		[]byte(`{"cluster":"x","serviceName":"y"}`), // ECS JSON
	} {
		if err := enforceAWSWireContract(nil, b); err != nil {
			t.Errorf("non-Query body must be ignored, got: %v", err)
		}
	}
}

// TestWireContractJSON: the JSON-RPC arm (X-Amz-Target + JSON body) catches a
// missing required field for ECS/DynamoDB, honors complete requests, and ignores
// unmodeled operations and reads.
func TestWireContractJSON(t *testing.T) {
	h := func(target string) map[string]string { return map[string]string{"X-Amz-Target": target} }

	// missing serviceName -> refused
	if err := enforceAWSWireContract(h("Ecs.CreateService"), []byte(`{"cluster":"c"}`)); err == nil {
		t.Fatal("ECS CreateService without serviceName must be refused at the wire")
	}
	// complete ECS CreateService -> ok
	if err := enforceAWSWireContract(h("Ecs.CreateService"),
		[]byte(`{"cluster":"c","serviceName":"s","taskDefinition":"t"}`)); err != nil {
		t.Fatalf("complete CreateService must pass: %v", err)
	}
	// DynamoDB CreateTable missing KeySchema -> refused
	if err := enforceAWSWireContract(h("DynamoDB_20120810.CreateTable"),
		[]byte(`{"TableName":"t","AttributeDefinitions":[{}],"BillingMode":"PAY_PER_REQUEST"}`)); err == nil {
		t.Fatal("CreateTable without KeySchema must be refused")
	}
	// DynamoDB CreateTable with a billing choice -> ok
	if err := enforceAWSWireContract(h("DynamoDB_20120810.CreateTable"),
		[]byte(`{"TableName":"t","KeySchema":[{}],"AttributeDefinitions":[{}],"BillingMode":"PAY_PER_REQUEST"}`)); err != nil {
		t.Fatalf("complete CreateTable must pass: %v", err)
	}
	// unmodeled JSON op (a read) -> no-op
	if err := enforceAWSWireContract(h("Ecs.DescribeServices"), []byte(`{}`)); err != nil {
		t.Fatalf("unmodeled JSON op must be ignored: %v", err)
	}
}
