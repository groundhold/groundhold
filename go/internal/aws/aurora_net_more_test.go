package aws

import (
	"strings"
	"testing"
)

// This file rounds out aurora_net.go coverage: updateAurora, auroraPatchOutcome,
// ensureDBSubnetGroup, describeDBSubnetGroupSubnets, classifyAuroraChange and
// discoverAurora were all previously untested (0% each) — sizable gaps in a
// composite driver whose crux is the four-valued partial-failure shape.

// ---- classifyAuroraChange: PURE, table-driven over every path -------------

func TestClassifyAuroraChange(t *testing.T) {
	cases := []struct {
		path    string
		desired any
		want    string
	}{
		{"engine.protocol", nil, "mutable"},
		{"network.publicExposure", nil, "mutable"},
		{"recovery.rpo", nil, "mutable"},
		{"availability.class", "regional", "caveated"},
		{"availability.class", "multi-regional", "unsupported"},
		{"location.region", nil, "immutable"},
		{"encryption.atRest", nil, "immutable"},
		{"encryption.customerManagedKeys", nil, "immutable"},
		{"encryption.inTransit", nil, "unsupported"},
		{"service.managed", nil, "unsupported"},
		{"no.such.path", nil, "unsupported"},
	}
	for _, c := range cases {
		got, reason := classifyAuroraChange(c.path, c.desired, nil)
		if got != c.want {
			t.Errorf("classifyAuroraChange(%q, %v) = %q, want %q", c.path, c.desired, got, c.want)
		}
		if reason == "" && c.path != "network.publicExposure" && c.path != "recovery.rpo" {
			t.Errorf("classifyAuroraChange(%q) carries no reason", c.path)
		}
	}
}

// ---- auroraPatchOutcome: PURE fold of one RDS-family patch call -----------

func TestAuroraPatchOutcome(t *testing.T) {
	pid := "aurora:eu-central-1:db-1"
	if r := auroraPatchOutcome("modify cluster", pid, 200, nil, nil); r != nil {
		t.Fatalf("a 200 must be nil (keep going), got %+v", r)
	}
	if r := auroraPatchOutcome("modify cluster", pid, 0, nil, errTransport("boom")); r == nil ||
		r.Status != "unknown" || r.ProviderID != pid {
		t.Fatalf("a transport error must be unknown WITH the pid, got %+v", r)
	}
	if r := auroraPatchOutcome("modify cluster", pid, 503, nil, nil); r == nil ||
		r.Status != "unknown" || r.ProviderID != pid {
		t.Fatalf("a 5xx must be unknown WITH the pid, got %+v", r)
	}
	if r := auroraPatchOutcome("modify cluster", pid, 400,
		[]byte(`<ErrorResponse><Error><Code>InvalidParameterValue</Code></Error></ErrorResponse>`), nil); r == nil ||
		r.Status != "failed" {
		t.Fatalf("a 4xx must be a clean failed, got %+v", r)
	}
}

// errTransport is a tiny error type for direct pure-function tests that need a
// non-nil error without standing up a broken server.
type errTransport string

func (e errTransport) Error() string { return string(e) }

// ---- updateAurora ------------------------------------------------------------

func auroraUpdateSetup(t *testing.T) (*fakeAurora, *Driver, string) {
	t.Helper()
	f := newFakeAurora()
	f.clusterExists = true
	f.tags = map[string]string{
		"groundhold-capability": sanitizeTag("db"), "groundhold-environment": sanitizeTag("prod")}
	clusterID := DBIdentifier("000000000000", "prod", "db", 1)
	f.instances[clusterID+"-writer"] = true
	f.instances[clusterID+"-reader"] = true
	srv := f.handler(t, nil)
	t.Cleanup(srv.Close)
	d := auroraTestDriver(t, srv)
	return f, d, auroraProviderID("eu-central-1", clusterID)
}

func TestUpdateAurora_EngineProtocolPatchesCluster(t *testing.T) {
	f, d, pid := auroraUpdateSetup(t)
	a := auroraAttrs()
	a["engine.protocol"] = "postgresql/16.6"
	res := d.updateAurora("db", "prod", pid, a, auroraImpl(), []string{"engine.protocol"})
	if res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("engine.protocol update: %+v", res)
	}
	if len(f.modifyClusterBodies) != 1 {
		t.Fatalf("want exactly one ModifyDBCluster call, got %d", len(f.modifyClusterBodies))
	}
	if !strings.Contains(f.modifyClusterBodies[0], "EngineVersion=16.6") {
		t.Fatalf("ModifyDBCluster body missing EngineVersion=16.6: %s", f.modifyClusterBodies[0])
	}
}

func TestUpdateAurora_RecoveryRPOPatchesRetention(t *testing.T) {
	f, d, pid := auroraUpdateSetup(t)
	res := d.updateAurora("db", "prod", pid, auroraAttrs(), auroraImpl(), []string{"recovery.rpo"})
	if res.Status != "succeeded" {
		t.Fatalf("recovery.rpo update: %+v", res)
	}
	if len(f.modifyClusterBodies) != 1 || !strings.Contains(f.modifyClusterBodies[0], "BackupRetentionPeriod=7") {
		t.Fatalf("ModifyDBCluster body missing BackupRetentionPeriod=7: %v", f.modifyClusterBodies)
	}
}

func TestUpdateAurora_PublicExposurePatchesEveryMember(t *testing.T) {
	f, d, pid := auroraUpdateSetup(t)
	a := auroraAttrs()
	a["network.publicExposure"] = true
	res := d.updateAurora("db", "prod", pid, a, auroraImpl(), []string{"network.publicExposure"})
	if res.Status != "succeeded" {
		t.Fatalf("network.publicExposure update: %+v", res)
	}
	if len(f.modifyInstanceBodies) != 2 {
		t.Fatalf("want a ModifyDBInstance per member (2), got %d: %v", len(f.modifyInstanceBodies), f.modifyInstanceBodies)
	}
	for _, b := range f.modifyInstanceBodies {
		if !strings.Contains(b, "PubliclyAccessible=true") {
			t.Fatalf("member patch missing PubliclyAccessible=true: %s", b)
		}
	}
}

func TestUpdateAurora_AvailabilityClassRefuses(t *testing.T) {
	_, d, pid := auroraUpdateSetup(t)
	res := d.updateAurora("db", "prod", pid, auroraAttrs(), auroraImpl(), []string{"availability.class"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "reader instance") {
		t.Fatalf("availability.class must refuse as an added resource, got %+v", res)
	}
}

func TestUpdateAurora_UnmappedPathRefuses(t *testing.T) {
	_, d, pid := auroraUpdateSetup(t)
	res := d.updateAurora("db", "prod", pid, auroraAttrs(), auroraImpl(), []string{"no.such.path"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not patchable") {
		t.Fatalf("an unmapped path must refuse, got %+v", res)
	}
}

func TestUpdateAurora_NotFoundFails(t *testing.T) {
	f := newFakeAurora()
	f.clusterExists = false
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)
	pid := auroraProviderID("eu-central-1", "gone-db")
	res := d.updateAurora("db", "prod", pid, auroraAttrs(), auroraImpl(), []string{"recovery.rpo"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "no longer exists") {
		t.Fatalf("a vanished cluster must refuse update, got %+v", res)
	}
}

func TestUpdateAurora_ForeignTagsFails(t *testing.T) {
	f := newFakeAurora()
	f.clusterExists = true
	f.tags = map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)
	pid := auroraProviderID("eu-central-1", "foreign-db")
	res := d.updateAurora("db", "prod", pid, auroraAttrs(), auroraImpl(), []string{"recovery.rpo"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign cluster must refuse update, got %+v", res)
	}
	if len(f.modifyClusterBodies) != 0 {
		t.Fatalf("refusal must not mutate: %v", f.modifyClusterBodies)
	}
}

func TestUpdateAurora_InvalidPIDFails(t *testing.T) {
	d := NewDriver("eu-central-1")
	res := d.updateAurora("db", "prod", "not-a-pid", auroraAttrs(), auroraImpl(), []string{"recovery.rpo"})
	if res.Status != "failed" {
		t.Fatalf("a malformed pid must refuse, got %+v", res)
	}
}

func TestUpdateAurora_ClusterPatch5xxIsUnknown(t *testing.T) {
	f, d, pid := auroraUpdateSetup(t)
	f.modifyClusterHTTP = 503
	res := d.updateAurora("db", "prod", pid, auroraAttrs(), auroraImpl(), []string{"recovery.rpo"})
	if res.Status != "unknown" || res.ProviderID != pid {
		t.Fatalf("a 5xx ModifyDBCluster must be unknown WITH the pid, got %+v", res)
	}
}

func TestUpdateAurora_ClusterPatch4xxIsFailed(t *testing.T) {
	f, d, pid := auroraUpdateSetup(t)
	f.modifyClusterHTTP = 400
	f.modifyClusterErr = "InvalidParameterCombination"
	res := d.updateAurora("db", "prod", pid, auroraAttrs(), auroraImpl(), []string{"recovery.rpo"})
	if res.Status != "failed" {
		t.Fatalf("a 4xx ModifyDBCluster must be failed, got %+v", res)
	}
}

func TestUpdateAurora_MemberPatch5xxIsUnknown(t *testing.T) {
	f, d, pid := auroraUpdateSetup(t)
	f.modifyInstanceHTTP = 500
	a := auroraAttrs()
	a["network.publicExposure"] = true
	res := d.updateAurora("db", "prod", pid, a, auroraImpl(), []string{"network.publicExposure"})
	if res.Status != "unknown" || res.ProviderID != pid {
		t.Fatalf("a 5xx ModifyDBInstance must be unknown WITH the pid, got %+v", res)
	}
}

// ---- ensureDBSubnetGroup / describeDBSubnetGroupSubnets (D278 net path) ----

func TestCreateAurora_DerivesSubnetGroupBeforeCluster(t *testing.T) {
	f := newFakeAurora()
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)
	a, i := auroraAttrs(), auroraImpl()
	delete(i, "subnetGroupName")
	i["subnetIds"] = []any{"subnet-a", "subnet-b"}

	res := d.createAurora("eu-central-1", "000000000000", "prod", "db", a, i, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	want := derivedSubnetGroupName("prod", "db")
	if len(f.sgCreated) != 1 || f.sgCreated[0] != want {
		t.Fatalf("subnet group create = %v, want [%s]", f.sgCreated, want)
	}
	if f.order[0] != "CreateDBCluster" {
		t.Fatalf("subnet group must be created BEFORE the cluster; order = %v", f.order)
	}
	if !strings.Contains(f.clusterBody, "DBSubnetGroupName="+want) {
		t.Fatalf("cluster must attach the derived subnet group: %s", f.clusterBody)
	}
}

func TestEnsureDBSubnetGroup_ReusesMatchingContent(t *testing.T) {
	f := newFakeAurora()
	f.sgExists = true
	f.sgSubnetIDs = []string{"subnet-a", "subnet-b"}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)
	a, i := auroraAttrs(), auroraImpl()
	delete(i, "subnetGroupName")
	i["subnetIds"] = []any{"subnet-a", "subnet-b"}

	res := d.createAurora("eu-central-1", "000000000000", "prod", "db", a, i, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create with a reused matching subnet group: %+v", res)
	}
}

func TestEnsureDBSubnetGroup_DriftedContentRefuses(t *testing.T) {
	f := newFakeAurora()
	f.sgExists = true
	f.sgSubnetIDs = []string{"subnet-x", "subnet-y"} // different from the request
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)
	a, i := auroraAttrs(), auroraImpl()
	delete(i, "subnetGroupName")
	i["subnetIds"] = []any{"subnet-a", "subnet-b"}

	res := d.createAurora("eu-central-1", "000000000000", "prod", "db", a, i, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "DIFFERENT subnets") {
		t.Fatalf("a drifted/foreign subnet group must refuse to be reused, got %+v", res)
	}
	if f.order != nil {
		t.Fatalf("refusal must not create the cluster: order = %v", f.order)
	}
}

// ---- discoverAurora ---------------------------------------------------------

func TestDiscoverAurora(t *testing.T) {
	f := newFakeAurora()
	f.clusterExists = true
	f.engine = "aurora-postgresql"
	f.engineVersion = "16.4"
	f.storageEncrypted = true
	f.discoverList = []struct{ ID, Engine string }{
		{"acme-db", "aurora-postgresql"},
		{"legacy-mysql-rds", "mysql"}, // NOT an aurora-* engine — must be filtered out
	}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)

	found, _, err := d.discoverAurora("eu-central-1")
	if err != nil {
		t.Fatalf("discoverAurora: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("want exactly 1 discovered aurora cluster (the non-aurora RDS engine filtered out), got %d: %+v", len(found), found)
	}
	want := auroraProviderID("eu-central-1", "acme-db")
	if found[0].ProviderID != want || found[0].ResourceType != "capability.database.relational" {
		t.Fatalf("discovered = %+v, want pid %q", found[0], want)
	}
}

func TestDiscoverAurora_TransportErrorFails(t *testing.T) {
	d := NewDriver("eu-central-1")
	d.RDSBaseURL = "http://127.0.0.1:1" // nothing listens here
	if _, _, err := d.discoverAurora("eu-central-1"); err == nil {
		t.Fatal("an unreachable endpoint must surface an error, not a silent empty list")
	}
}
