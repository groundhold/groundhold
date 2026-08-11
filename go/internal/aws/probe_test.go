package aws

import (
	"fmt"
	"groundhold/internal/provider"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// rdsProbeOpts configures the RDS Query fake for the probe tests.
type rdsProbeOpts struct {
	publiclyAccessible bool
	endpointAddr       string
	endpointPort       string
	account            string // ARN account of the source instance
	capabilityTag      string // groundhold-capability tag value
	snapshotStatus     string // "" => no snapshots returned
	deleteHTTP         int    // status for DeleteDBInstance (0 => 200)
	restoreCalled      *atomic.Bool
	deleteCalled       *atomic.Bool
}

func rdsProbeServer(t *testing.T, o rdsProbeOpts) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			r.Body.Read(body)
			switch actionOf(string(body)) {
			case "DescribeDBInstances":
				w.Write([]byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>` +
					`<DBInstanceIdentifier>db-x</DBInstanceIdentifier>` +
					`<DBInstanceStatus>available</DBInstanceStatus>` +
					`<Engine>postgres</Engine><EngineVersion>16.3</EngineVersion>` +
					`<DBInstanceClass>db.t3.micro</DBInstanceClass>` +
					`<DBInstanceArn>arn:aws:rds:eu-central-1:` + o.account + `:db:db-x</DBInstanceArn>` +
					`<PubliclyAccessible>` + boolStr(o.publiclyAccessible) + `</PubliclyAccessible>` +
					`<Endpoint><Address>` + o.endpointAddr + `</Address><Port>` + o.endpointPort + `</Port></Endpoint>` +
					`<StorageEncrypted>true</StorageEncrypted><MultiAZ>false</MultiAZ>` +
					`<TagList><Tag><Key>groundhold-capability</Key><Value>` + o.capabilityTag + `</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag></TagList>` +
					`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
			case "DescribeDBSnapshots":
				snap := ""
				if o.snapshotStatus != "" {
					snap = `<DBSnapshot><DBSnapshotIdentifier>snap-1</DBSnapshotIdentifier>` +
						`<Status>` + o.snapshotStatus + `</Status>` +
						`<SnapshotCreateTime>2026-01-01T00:00:00Z</SnapshotCreateTime></DBSnapshot>`
				}
				w.Write([]byte(`<DescribeDBSnapshotsResponse><DescribeDBSnapshotsResult><DBSnapshots>` +
					snap + `</DBSnapshots></DescribeDBSnapshotsResult></DescribeDBSnapshotsResponse>`))
			case "RestoreDBInstanceFromDBSnapshot":
				if o.restoreCalled != nil {
					o.restoreCalled.Store(true)
				}
				w.Write([]byte(`<RestoreDBInstanceFromDBSnapshotResponse></RestoreDBInstanceFromDBSnapshotResponse>`))
			case "DeleteDBInstance":
				if o.deleteCalled != nil {
					o.deleteCalled.Store(true)
				}
				if o.deleteHTTP != 0 {
					w.WriteHeader(o.deleteHTTP)
					w.Write([]byte(`<ErrorResponse><Error><Code>InternalFailure</Code></Error></ErrorResponse>`))
					return
				}
				w.Write([]byte(`<DeleteDBInstanceResponse></DeleteDBInstanceResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func probeDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.RDSBaseURL = srv.URL
	d.Account = "000000000000"
	d.PollInterval = 0
	return d
}

// exposure true: the writer answers a handshake -> publicExposure=true.
func TestProbeRDSExposureTrue(t *testing.T) {
	srv := rdsProbeServer(t, rdsProbeOpts{
		publiclyAccessible: true, endpointAddr: "203.0.113.7", endpointPort: "5432",
		account: "000000000000", capabilityTag: "db"})
	defer srv.Close()
	d := probeDriver(t, srv)
	d.Dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		if addr != "203.0.113.7:5432" {
			return nil, fmt.Errorf("wrong addr %s", addr)
		}
		c, s := net.Pipe()
		go s.Close()
		return c, nil
	}
	out, err := d.Probe("rds", "db", "rds:eu-central-1:db-x", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Measurements) != 1 || out.Measurements[0].Value != true {
		t.Fatalf("handshake success must measure exposure true: %+v", out)
	}
}

// exposure false: not publicly accessible -> false WITHOUT a dial.
func TestProbeRDSExposureFalse(t *testing.T) {
	srv := rdsProbeServer(t, rdsProbeOpts{
		publiclyAccessible: false, endpointAddr: "10.0.0.7", endpointPort: "5432",
		account: "000000000000", capabilityTag: "db"})
	defer srv.Close()
	d := probeDriver(t, srv)
	d.Dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		t.Fatalf("a non-public instance must not be dialed (addr=%s)", addr)
		return nil, nil
	}
	out, err := d.Probe("rds", "db", "rds:eu-central-1:db-x", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Measurements) != 1 || out.Measurements[0].Value != false {
		t.Fatalf("no public endpoint must measure false: %+v", out)
	}
}

// exposure inconclusive: public but the handshake dies -> a FAILURE, never a value.
func TestProbeRDSExposureInconclusive(t *testing.T) {
	srv := rdsProbeServer(t, rdsProbeOpts{
		publiclyAccessible: true, endpointAddr: "203.0.113.7", endpointPort: "5432",
		account: "000000000000", capabilityTag: "db"})
	defer srv.Close()
	d := probeDriver(t, srv)
	d.Dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return nil, fmt.Errorf("timeout")
	}
	out, err := d.Probe("rds", "db", "rds:eu-central-1:db-x", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Measurements) != 0 || len(out.Failures) != 1 {
		t.Fatalf("filtered handshake must be a failure, not a value: %+v", out)
	}
	if out.Failures[0].Path != "network.publicExposure" {
		t.Fatalf("failure on wrong path: %+v", out.Failures[0])
	}
}

// intrusive RTO happy path: restore -> available -> deleted, measurement present
// and marked intrusive; the account gate is satisfied by an STS-resolved identity.
func TestProbeRDSRTOHappyPath(t *testing.T) {
	var restore, del atomic.Bool
	srv := rdsProbeServer(t, rdsProbeOpts{
		publiclyAccessible: false, account: "000000000000", capabilityTag: "db",
		snapshotStatus: "available", restoreCalled: &restore, deleteCalled: &del})
	defer srv.Close()

	// prove the STS wire: resolveAccount goes through GetCallerIdentity.
	sts := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult>` +
				`<Account>000000000000</Account><Arn>arn:aws:iam::000000000000:user/x</Arn>` +
				`</GetCallerIdentityResult></GetCallerIdentityResponse>`))
		}))
	defer sts.Close()

	d := probeDriver(t, srv)
	d.Account = "" // force resolution through STS
	d.STSBaseURL = sts.URL

	out, err := d.Probe("rds", "db", "rds:eu-central-1:db-x", true)
	if err != nil {
		t.Fatal(err)
	}
	if !restore.Load() {
		t.Fatal("restore was never issued")
	}
	if !del.Load() {
		t.Fatal("scratch instance was not deleted")
	}
	got := ""
	intrusive := false
	for _, m := range out.Measurements {
		if m.Path == "recovery.rto" {
			got, _ = m.Value.(string)
			intrusive = m.Intrusive
		}
	}
	if got == "" {
		t.Fatalf("no rto measurement: %+v", out)
	}
	if !intrusive {
		t.Fatal("restore-test measurement must be marked intrusive")
	}
	if got != "1m" { // sub-minute elapsed rounds UP, never down
		t.Fatalf("rto = %s, want 1m", got)
	}
	for _, f := range out.Failures {
		t.Errorf("unexpected failure: %+v", f)
	}
}

// intrusive refused when not ours: the capability tag mismatches -> an ERROR and
// NO restore is ever issued (the gate fires before any spend).
func TestProbeRDSRTORefusedNotOurs(t *testing.T) {
	var restore atomic.Bool
	srv := rdsProbeServer(t, rdsProbeOpts{
		account: "000000000000", capabilityTag: "someone-else",
		snapshotStatus: "available", restoreCalled: &restore})
	defer srv.Close()
	d := probeDriver(t, srv)
	_, err := d.Probe("rds", "db", "rds:eu-central-1:db-x", true)
	if err == nil {
		t.Fatal("an intrusive probe on a resource that is not ours must error")
	}
	if restore.Load() {
		t.Fatal("restore must NOT be issued once ownership is refused")
	}
}

// intrusive refused off-account: the resource's ARN account differs from the
// acting identity -> ERROR, no restore.
func TestProbeRDSRTORefusedOffAccount(t *testing.T) {
	var restore atomic.Bool
	srv := rdsProbeServer(t, rdsProbeOpts{
		account: "999999999999", capabilityTag: "db",
		snapshotStatus: "available", restoreCalled: &restore})
	defer srv.Close()
	d := probeDriver(t, srv) // acting account 000000000000
	_, err := d.Probe("rds", "db", "rds:eu-central-1:db-x", true)
	if err == nil {
		t.Fatal("an intrusive probe billing a foreign account must error")
	}
	if restore.Load() {
		t.Fatal("restore must NOT be issued once the account gate refuses")
	}
}

// no snapshot: RTO is a FAILURE, never a fabricated value.
func TestProbeRDSRTONoSnapshot(t *testing.T) {
	srv := rdsProbeServer(t, rdsProbeOpts{
		account: "000000000000", capabilityTag: "db", snapshotStatus: ""})
	defer srv.Close()
	d := probeDriver(t, srv)
	out, err := d.Probe("rds", "db", "rds:eu-central-1:db-x", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range out.Measurements {
		if m.Path == "recovery.rto" {
			t.Fatalf("rto fabricated without a restore: %+v", m)
		}
	}
	found := false
	for _, f := range out.Failures {
		if f.Path == "recovery.rto" && strings.Contains(f.Reason, "no snapshot") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing 'no snapshot' failure: %+v", out)
	}
}

// scratch-delete-failure: a scratch that could not be deleted is surfaced as a
// LOUD failure (it costs money), never silently leaked.
func TestProbeRDSScratchDeleteFailureLoud(t *testing.T) {
	srv := rdsProbeServer(t, rdsProbeOpts{
		account: "000000000000", capabilityTag: "db",
		snapshotStatus: "available", deleteHTTP: 500})
	defer srv.Close()
	d := probeDriver(t, srv)
	out, err := d.Probe("rds", "db", "rds:eu-central-1:db-x", true)
	if err != nil {
		t.Fatal(err)
	}
	loud := false
	for _, f := range out.Failures {
		if strings.Contains(f.Reason, "NOT deleted") && strings.Contains(f.Reason, "costs money") {
			loud = true
		}
	}
	if !loud {
		t.Fatalf("a leaked scratch must be surfaced loudly: %+v", out)
	}
}

// ---- Aurora ----------------------------------------------------------------

// auroraProbeOpts configures the RDS-family Query fake for the Aurora probes.
type auroraProbeOpts struct {
	account        string
	capabilityTag  string
	writerPublic   bool
	writerAddr     string
	snapshotStatus string // "" => no cluster snapshots
	restoreCalled  *atomic.Bool
	deleteInstance *atomic.Bool
	deleteCluster  *atomic.Bool
}

func auroraProbeServer(t *testing.T, o auroraProbeOpts) *httptest.Server {
	t.Helper()
	// Stateful, mirroring real Aurora async teardown: the scratch MEMBER lingers
	// after DeleteDBInstance until a describe reports it gone, and the CLUSTER refuses
	// deletion (InvalidDBClusterStateFault) until the member is observed gone. This is
	// what makes the happy path a genuine regression test for the cluster-leak bug: a
	// teardown that deletes the cluster without first waiting for the member to clear
	// gets InvalidDBClusterStateFault and surfaces a loud failure.
	var mu sync.Mutex
	instDeleted, goneObserved := false, false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			r.Body.Read(body)
			switch actionOf(string(body)) {
			case "DescribeDBClusters":
				w.Write([]byte(`<DescribeDBClustersResponse><DescribeDBClustersResult><DBClusters><DBCluster>` +
					`<DBClusterIdentifier>cl-x</DBClusterIdentifier><Status>available</Status>` +
					`<Engine>aurora-postgresql</Engine><EngineVersion>16.3</EngineVersion>` +
					`<DBClusterArn>arn:aws:rds:eu-central-1:` + o.account + `:cluster:cl-x</DBClusterArn>` +
					`<Endpoint>cl-x.cluster.eu-central-1.rds.amazonaws.com</Endpoint><Port>5432</Port>` +
					`<StorageEncrypted>true</StorageEncrypted>` +
					`<DBClusterMembers><DBClusterMember><DBInstanceIdentifier>cl-x-writer</DBInstanceIdentifier>` +
					`<IsClusterWriter>true</IsClusterWriter></DBClusterMember></DBClusterMembers>` +
					`<TagList><Tag><Key>groundhold-capability</Key><Value>` + o.capabilityTag + `</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag></TagList>` +
					`</DBCluster></DBClusters></DescribeDBClustersResult></DescribeDBClustersResponse>`))
			case "DescribeDBInstances":
				mu.Lock()
				gone := instDeleted
				if gone {
					goneObserved = true
				}
				mu.Unlock()
				if gone { // the scratch member has been torn down
					w.Write([]byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult>` +
						`<DBInstances></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
					return
				}
				w.Write([]byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>` +
					`<DBInstanceIdentifier>cl-x-writer</DBInstanceIdentifier>` +
					`<DBInstanceStatus>available</DBInstanceStatus><Engine>aurora-postgresql</Engine>` +
					`<PubliclyAccessible>` + boolStr(o.writerPublic) + `</PubliclyAccessible>` +
					`<Endpoint><Address>` + o.writerAddr + `</Address><Port>5432</Port></Endpoint>` +
					`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
			case "DescribeDBClusterSnapshots":
				snap := ""
				if o.snapshotStatus != "" {
					snap = `<DBClusterSnapshot><DBClusterSnapshotIdentifier>clsnap-1</DBClusterSnapshotIdentifier>` +
						`<Status>` + o.snapshotStatus + `</Status>` +
						`<SnapshotCreateTime>2026-01-01T00:00:00Z</SnapshotCreateTime></DBClusterSnapshot>`
				}
				w.Write([]byte(`<DescribeDBClusterSnapshotsResponse><DescribeDBClusterSnapshotsResult>` +
					`<DBClusterSnapshots>` + snap + `</DBClusterSnapshots>` +
					`</DescribeDBClusterSnapshotsResult></DescribeDBClusterSnapshotsResponse>`))
			case "RestoreDBClusterFromSnapshot":
				if o.restoreCalled != nil {
					o.restoreCalled.Store(true)
				}
				w.Write([]byte(`<RestoreDBClusterFromSnapshotResponse></RestoreDBClusterFromSnapshotResponse>`))
			case "CreateDBInstance":
				w.Write([]byte(`<CreateDBInstanceResponse></CreateDBInstanceResponse>`))
			case "DeleteDBInstance":
				if o.deleteInstance != nil {
					o.deleteInstance.Store(true)
				}
				mu.Lock()
				instDeleted = true
				mu.Unlock()
				w.Write([]byte(`<DeleteDBInstanceResponse></DeleteDBInstanceResponse>`))
			case "DeleteDBCluster":
				mu.Lock()
				ok := goneObserved
				mu.Unlock()
				if !ok { // the member is not yet gone — AWS refuses the cluster delete
					w.WriteHeader(400)
					w.Write([]byte(`<ErrorResponse><Error><Code>InvalidDBClusterStateFault</Code>` +
						`<Message>cluster has members</Message></Error></ErrorResponse>`))
					return
				}
				if o.deleteCluster != nil {
					o.deleteCluster.Store(true)
				}
				w.Write([]byte(`<DeleteDBClusterResponse></DeleteDBClusterResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
}

// aurora exposure: not publicly accessible writer -> false, without a dial.
func TestProbeAuroraExposureFalse(t *testing.T) {
	srv := auroraProbeServer(t, auroraProbeOpts{
		account: "000000000000", capabilityTag: "db", writerPublic: false, writerAddr: "10.0.0.9"})
	defer srv.Close()
	d := probeDriver(t, srv)
	d.Dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		t.Fatalf("a non-public aurora writer must not be dialed (addr=%s)", addr)
		return nil, nil
	}
	out, err := d.Probe("aurora", "db", "aurora:eu-central-1:cl-x", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Measurements) != 1 || out.Measurements[0].Value != false {
		t.Fatalf("private aurora writer must measure exposure false: %+v", out)
	}
}

// TestProbeAuroraExposureNoInstanceIsProviderConfig pins D990: a cluster with no member
// instance concludes not-exposed from the CONFIG (no endpoint to dial). The value is
// honest, but the method must say provider-config — naming a tcp-connect a handshake
// nobody attempted is the D775 lie, and this branch was left behind by that fix.
func TestProbeAuroraExposureNoInstanceIsProviderConfig(t *testing.T) {
	var out provider.ProbeOutcome
	(&Driver{}).probeAuroraExposure("eu-central-1", dbCluster{}, &out)
	if len(out.Measurements) != 1 {
		t.Fatalf("want one measurement, got %+v", out.Measurements)
	}
	m := out.Measurements[0]
	if m.Path != "network.publicExposure" || m.Value != false {
		t.Fatalf("a no-instance cluster must measure exposure false: %+v", m)
	}
	if m.Method != "provider-config" {
		t.Fatalf("method = %q, want provider-config — nothing was dialed, so a tcp-connect method is a false provenance", m.Method)
	}
}

// aurora exposure true: the cluster endpoint answers a handshake.
func TestProbeAuroraExposureTrue(t *testing.T) {
	srv := auroraProbeServer(t, auroraProbeOpts{
		account: "000000000000", capabilityTag: "db", writerPublic: true, writerAddr: "203.0.113.9"})
	defer srv.Close()
	d := probeDriver(t, srv)
	d.Dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		if addr != "cl-x.cluster.eu-central-1.rds.amazonaws.com:5432" {
			return nil, fmt.Errorf("wrong addr %s", addr)
		}
		c, s := net.Pipe()
		go s.Close()
		return c, nil
	}
	out, err := d.Probe("aurora", "db", "aurora:eu-central-1:cl-x", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Measurements) != 1 || out.Measurements[0].Value != true {
		t.Fatalf("reachable cluster endpoint must measure exposure true: %+v", out)
	}
}

// aurora intrusive RTO happy path: restore cluster + member -> available ->
// instance then cluster deleted, measurement present and intrusive.
func TestProbeAuroraRTOHappyPath(t *testing.T) {
	var restore, delI, delC atomic.Bool
	srv := auroraProbeServer(t, auroraProbeOpts{
		account: "000000000000", capabilityTag: "db", writerPublic: false, writerAddr: "10.0.0.9",
		snapshotStatus: "available", restoreCalled: &restore, deleteInstance: &delI, deleteCluster: &delC})
	defer srv.Close()
	d := probeDriver(t, srv)
	out, err := d.Probe("aurora", "db", "aurora:eu-central-1:cl-x", true)
	if err != nil {
		t.Fatal(err)
	}
	if !restore.Load() || !delI.Load() || !delC.Load() {
		t.Fatalf("restore/delete-instance/delete-cluster must all run: r=%v i=%v c=%v",
			restore.Load(), delI.Load(), delC.Load())
	}
	got, intrusive := "", false
	for _, m := range out.Measurements {
		if m.Path == "recovery.rto" {
			got, _ = m.Value.(string)
			intrusive = m.Intrusive
		}
	}
	if got != "1m" || !intrusive {
		t.Fatalf("aurora rto = %q intrusive=%v, want 1m/true (out=%+v)", got, intrusive, out)
	}
	for _, f := range out.Failures {
		t.Errorf("unexpected failure: %+v", f)
	}
}

// aurora intrusive refused when not ours: tag mismatch -> error, no restore.
func TestProbeAuroraRTORefusedNotOurs(t *testing.T) {
	var restore atomic.Bool
	srv := auroraProbeServer(t, auroraProbeOpts{
		account: "000000000000", capabilityTag: "not-ours",
		snapshotStatus: "available", restoreCalled: &restore})
	defer srv.Close()
	d := probeDriver(t, srv)
	if _, err := d.Probe("aurora", "db", "aurora:eu-central-1:cl-x", true); err == nil {
		t.Fatal("an intrusive aurora probe on a foreign resource must error")
	}
	if restore.Load() {
		t.Fatal("cluster restore must NOT be issued once ownership is refused")
	}
}

// dispatch: an unwired service is refused, not silently handled.
func TestProbeUnwiredService(t *testing.T) {
	srv := rdsProbeServer(t, rdsProbeOpts{})
	defer srv.Close()
	d := probeDriver(t, srv)
	if _, err := d.Probe("s3", "bucket", "s3:eu-central-1:x", false); err == nil {
		t.Fatal("probing an unwired service must error")
	}
}

// D775. `PubliclyAccessible: true` with an EMPTY endpoint address is an instance whose
// name is not readable yet — not one without a public endpoint. The old branch folded it
// with the genuinely-private case and reported `network.publicExposure: false` as a
// MEASURED outcome, with `Method: tcp-connect` on a value obtained by dialling nothing.
//
// A proven negative invented out of missing data is the exact shape D306 and D513 exist
// for: absent is not no.
func TestProbeWillNotProveAbsenceFromAMissingAddress(t *testing.T) {
	d := NewDriver("eu-central-1")

	t.Run("configured public, no address yet", func(t *testing.T) {
		var out provider.ProbeOutcome
		d.probeExposure("", 5432, true, "postgres", &out)
		if len(out.Measurements) != 0 {
			t.Fatalf("measured %+v from an unknown address — the endpoint may exist and "+
				"simply not be readable yet (D775)", out.Measurements)
		}
		if len(out.Failures) != 1 || !out.Failures[0].Retryable {
			t.Fatalf("want one RETRYABLE failure, got %+v", out.Failures)
		}
		// The REASON is what discriminates. A mutant that skips this branch falls
		// through and DIALS the empty address, producing a retryable failure too —
		// which the first version of this test accepted, and the meter said so.
		if !strings.Contains(out.Failures[0].Reason, "no endpoint address") {
			t.Fatalf("the failure must name the missing address rather than report a dial "+
				"that should never have been attempted: %q", out.Failures[0].Reason)
		}
	})

	t.Run("the provider says there is no public endpoint", func(t *testing.T) {
		var out provider.ProbeOutcome
		d.probeExposure("", 5432, false, "postgres", &out)
		if len(out.Measurements) != 1 || out.Measurements[0].Value != false {
			t.Fatalf("a provider-reported private resource IS a measured false: %+v", out.Measurements)
		}
		if m := out.Measurements[0].Method; m == "tcp-connect" {
			t.Errorf("method %q names a handshake nobody attempted — a probe's Method says "+
				"what was DONE, and a config read is not a dial (D775)", m)
		}
	})
}
