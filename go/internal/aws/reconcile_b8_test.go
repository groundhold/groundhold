package aws

import (
	"strings"
	"testing"
)

// BATCH 8 reconcile: server-assigned ids, no list wrapper — TIER 1 (the pid on the
// receipt). Each service proves (a) a receipt WITH a valid targetProviderId for a
// live, ready, owned resource concludes succeeded WITH that pid, and (b) a receipt
// with NO targetProviderId honestly refuses (unknown, "not recorded"). Several also
// prove found-but-not-ours refuses to attribute a foreign resource (unknown).

func b8CreateReceipt(target, pid string) map[string]any {
	return map[string]any{"target": target, "operation": "create", "generation": 1, "targetProviderId": pid}
}

func b8NoPidReceipt(target string) map[string]any {
	return map[string]any{"target": target, "operation": "create", "generation": 1}
}

func TestReconcileVPC_B8(t *testing.T) {
	pid := "vpc:eu-central-1:vpc-0abc123"
	srv := awsVpcServer(t, "net")
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)

	if r := d.Reconcile("net", "prod", b8CreateReceipt("aws.vpc/x", pid)); r.Status != "succeeded" || r.ProviderID != pid {
		t.Fatalf("owned live vpc must reconcile succeeded with the pid, got %+v", r)
	}
	if r := d.Reconcile("net", "prod", b8NoPidReceipt("aws.vpc/x")); r.Status != "unknown" || !strings.Contains(r.Reason, "not recorded") {
		t.Fatalf("a vpc receipt with no recorded pid must be unknown, got %+v", r)
	}
	// a foreign-tagged vpc is not attributed to our create -> unknown (never succeeded).
	fsrv := awsVpcServer(t, "someone-else")
	defer fsrv.Close()
	fd := awsVpcTestDriver(t, fsrv)
	if r := fd.Reconcile("net", "prod", b8CreateReceipt("aws.vpc/x", pid)); r.Status != "unknown" {
		t.Fatalf("a foreign vpc must not be claimed, got %+v", r)
	}
}

func TestReconcileKMS_B8(t *testing.T) {
	pid := "akms:eu-central-1:" + testKeyID
	srv := awsKMSServer(t, "datakey", true, 90)
	defer srv.Close()
	d := awsKMSDriver(t, srv)

	if r := d.Reconcile("datakey", "prod", b8CreateReceipt("aws.kms/x", pid)); r.Status != "succeeded" || r.ProviderID != pid {
		t.Fatalf("an Enabled owned key must reconcile succeeded with the pid, got %+v", r)
	}
	if r := d.Reconcile("datakey", "prod", b8NoPidReceipt("aws.kms/x")); r.Status != "unknown" || !strings.Contains(r.Reason, "not recorded") {
		t.Fatalf("a kms receipt with no recorded pid must be unknown, got %+v", r)
	}
}

func TestReconcileCloudFront_B8(t *testing.T) {
	pid := "cf:000000000000:E1234567890ABC"
	srv := cfServer(t, "edge", "origin.example.com", "https-only", false)
	defer srv.Close()
	d := cfDriver(t, srv)

	if r := d.Reconcile("edge", "prod", b8CreateReceipt("aws.cloudfront/x", pid)); r.Status != "succeeded" || r.ProviderID != pid {
		t.Fatalf("a Deployed owned distribution must reconcile succeeded with the pid, got %+v", r)
	}
	if r := d.Reconcile("edge", "prod", b8NoPidReceipt("aws.cloudfront/x")); r.Status != "unknown" || !strings.Contains(r.Reason, "not recorded") {
		t.Fatalf("a cloudfront receipt with no recorded pid must be unknown, got %+v", r)
	}
}

func TestReconcileApiGW_B8(t *testing.T) {
	pid := "apigw:eu-central-1:000000000000:a1b2c3d4e5"
	srv := apigwServer(t, "front", "HTTP")
	defer srv.Close()
	d := apigwDriver(t, srv)

	if r := d.Reconcile("front", "prod", b8CreateReceipt("aws.apigateway/x", pid)); r.Status != "succeeded" || r.ProviderID != pid {
		t.Fatalf("a live owned HTTP API must reconcile succeeded with the pid, got %+v", r)
	}
	if r := d.Reconcile("front", "prod", b8NoPidReceipt("aws.apigateway/x")); r.Status != "unknown" || !strings.Contains(r.Reason, "not recorded") {
		t.Fatalf("an apigateway receipt with no recorded pid must be unknown, got %+v", r)
	}
	// a foreign-tagged API is not attributed to our create -> unknown.
	fsrv := apigwServer(t, "someone-else", "HTTP")
	defer fsrv.Close()
	fd := apigwDriver(t, fsrv)
	if r := fd.Reconcile("front", "prod", b8CreateReceipt("aws.apigateway/x", pid)); r.Status != "unknown" {
		t.Fatalf("a foreign API must not be claimed, got %+v", r)
	}
}

func TestReconcileRoute53Health_B8(t *testing.T) {
	pid := "r53hc:hc-123"
	srv := r53hcServer(t, "api")
	defer srv.Close()
	d := r53hcDriver(t, srv)

	if r := d.Reconcile("api", "prod", b8CreateReceipt("aws.route53health/x", pid)); r.Status != "succeeded" || r.ProviderID != pid {
		t.Fatalf("a live owned health check must reconcile succeeded with the pid, got %+v", r)
	}
	if r := d.Reconcile("api", "prod", b8NoPidReceipt("aws.route53health/x")); r.Status != "unknown" || !strings.Contains(r.Reason, "not recorded") {
		t.Fatalf("a route53health receipt with no recorded pid must be unknown, got %+v", r)
	}
}

func TestReconcileVpnGateway_B8(t *testing.T) {
	pid := "vgw:eu-central-1:vgw-0abc123"
	srv := vgwServer(t, "site")
	defer srv.Close()
	d := vgwDriver(t, srv)

	if r := d.Reconcile("site", "prod", b8CreateReceipt("aws.vpngateway/x", pid)); r.Status != "succeeded" || r.ProviderID != pid {
		t.Fatalf("an available owned vpn gateway must reconcile succeeded with the pid, got %+v", r)
	}
	if r := d.Reconcile("site", "prod", b8NoPidReceipt("aws.vpngateway/x")); r.Status != "unknown" || !strings.Contains(r.Reason, "not recorded") {
		t.Fatalf("a vpngateway receipt with no recorded pid must be unknown, got %+v", r)
	}
	// a foreign-tagged gateway is not attributed to our create -> unknown.
	fsrv := vgwServer(t, "someone-else")
	defer fsrv.Close()
	fd := vgwDriver(t, fsrv)
	if r := fd.Reconcile("site", "prod", b8CreateReceipt("aws.vpngateway/x", pid)); r.Status != "unknown" {
		t.Fatalf("a foreign vpn gateway must not be claimed, got %+v", r)
	}
}
