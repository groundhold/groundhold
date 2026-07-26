package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"groundhold/internal/cloudfake"
)

// auroraWorldServer renders a cloudfake.World as the RDS Query wire and routes
// mutations back through it — the Layer-2 wire adapter for the Aurora probe. The
// World, not ad-hoc booleans, is the source of truth: it enforces the async lifecycle
// (read-driven creating→available, deleting→absent) AND the real constraint that a
// cluster refuses deletion while a member still exists. So the ACTUAL d.Probe runs
// against a reality-anchored fake, and the World IS the leak detector.
//
// The adapter FAILS LOUD (500) on any action it does not model, so the fake can never
// silently pretend an endpoint answered.
func auroraWorldServer(t *testing.T, w *cloudfake.World, account string) *httptest.Server {
	t.Helper()
	status := func(s cloudfake.State) string {
		switch s {
		case cloudfake.Available:
			return "available"
		case cloudfake.Creating:
			return "creating"
		case cloudfake.Deleting:
			return "deleting"
		case cloudfake.Failed:
			return "failed"
		}
		return "unknown"
	}
	tagXML := func(tags map[string]string) string {
		var b strings.Builder
		b.WriteString("<TagList>")
		for k, v := range tags {
			b.WriteString("<Tag><Key>" + k + "</Key><Value>" + v + "</Value></Tag>")
		}
		b.WriteString("</TagList>")
		return b.String()
	}

	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		switch form.Get("Action") {
		case "GetCallerIdentity":
			rw.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult>` +
				`<Account>` + account + `</Account>` +
				`<Arn>arn:aws:iam::` + account + `:role/deployer</Arn>` +
				`</GetCallerIdentityResult></GetCallerIdentityResponse>`))

		case "DescribeDBClusters":
			id := form.Get("DBClusterIdentifier")
			st, tags, found := w.Describe(id)
			if !found {
				http.Error(rw, `<ErrorResponse><Error><Code>DBClusterNotFoundFault</Code></Error></ErrorResponse>`, 404)
				return
			}
			rw.Write([]byte(`<DescribeDBClustersResponse><DescribeDBClustersResult><DBClusters><DBCluster>` +
				`<DBClusterIdentifier>` + id + `</DBClusterIdentifier><Status>` + status(st) + `</Status>` +
				`<Engine>aurora-postgresql</Engine><EngineVersion>16.3</EngineVersion>` +
				`<DBClusterArn>arn:aws:rds:eu-central-1:` + account + `:cluster:` + id + `</DBClusterArn>` +
				`<Endpoint>` + id + `.cluster.eu-central-1.rds.amazonaws.com</Endpoint><Port>5432</Port>` +
				`<DBClusterMembers><DBClusterMember><DBInstanceIdentifier>` + id + `-writer</DBInstanceIdentifier>` +
				`<IsClusterWriter>true</IsClusterWriter></DBClusterMember></DBClusterMembers>` +
				tagXML(tags) +
				`</DBCluster></DBClusters></DescribeDBClustersResult></DescribeDBClustersResponse>`))

		case "DescribeDBInstances":
			id := form.Get("DBInstanceIdentifier")
			st, tags, found := w.Describe(id)
			if !found {
				http.Error(rw, `<ErrorResponse><Error><Code>DBInstanceNotFound</Code></Error></ErrorResponse>`, 404)
				return
			}
			rw.Write([]byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>` +
				`<DBInstanceIdentifier>` + id + `</DBInstanceIdentifier><DBInstanceStatus>` + status(st) + `</DBInstanceStatus>` +
				`<Engine>aurora-postgresql</Engine><DBInstanceClass>db.serverless</DBInstanceClass>` +
				`<PubliclyAccessible>false</PubliclyAccessible>` +
				`<DBInstanceArn>arn:aws:rds:eu-central-1:` + account + `:db:` + id + `</DBInstanceArn>` +
				`<Endpoint><Address>` + id + `.eu-central-1.rds.amazonaws.com</Address><Port>5432</Port></Endpoint>` +
				tagXML(tags) +
				`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))

		case "DescribeDBClusterSnapshots":
			rw.Write([]byte(`<DescribeDBClusterSnapshotsResponse><DescribeDBClusterSnapshotsResult><DBClusterSnapshots>` +
				`<DBClusterSnapshot><DBClusterSnapshotIdentifier>clsnap-1</DBClusterSnapshotIdentifier>` +
				`<Status>available</Status><SnapshotCreateTime>2026-01-01T00:00:00Z</SnapshotCreateTime></DBClusterSnapshot>` +
				`</DBClusterSnapshots></DescribeDBClusterSnapshotsResult></DescribeDBClusterSnapshotsResponse>`))

		case "RestoreDBClusterFromSnapshot":
			w.Create(form.Get("DBClusterIdentifier"), "cluster", map[string]string{"groundhold-probe": "scratch"})
			rw.Write([]byte(`<RestoreDBClusterFromSnapshotResponse></RestoreDBClusterFromSnapshotResponse>`))
		case "CreateDBInstance":
			w.Create(form.Get("DBInstanceIdentifier"), "member", map[string]string{"groundhold-probe": "scratch"})
			rw.Write([]byte(`<CreateDBInstanceResponse></CreateDBInstanceResponse>`))
		case "DeleteDBInstance":
			_ = w.Delete(form.Get("DBInstanceIdentifier"))
			rw.Write([]byte(`<DeleteDBInstanceResponse></DeleteDBInstanceResponse>`))
		case "DeleteDBCluster":
			if err := w.Delete(form.Get("DBClusterIdentifier")); err != nil {
				http.Error(rw, `<ErrorResponse><Error><Code>InvalidDBClusterStateFault</Code>`+
					`<Message>`+err.Error()+`</Message></Error></ErrorResponse>`, 400)
				return
			}
			rw.Write([]byte(`<DeleteDBClusterResponse></DeleteDBClusterResponse>`))

		default:
			// fail LOUD on an unmodeled operation — the fake never silently pretends.
			http.Error(rw, `<ErrorResponse><Error><Code>UnmodeledOperation</Code>`+
				`<Message>`+form.Get("Action")+`</Message></Error></ErrorResponse>`, 500)
		}
	}))
}

// auroraProbeWorld builds a world with the source cluster + writer (stable, owned) and
// the cluster-refuses-delete-while-member constraint — the real Aurora teardown rule.
func auroraProbeWorld(capTag string) *cloudfake.World {
	w := cloudfake.New(2) // scratch resources settle to available/absent after 2 reads
	w.AddConstraint(cloudfake.Constraint{
		Name: "cluster-has-member", Prov: cloudfake.Observed,
		Blocks: func(w *cloudfake.World, id string) string {
			if w.TypeOf(id) == "cluster" && w.ChildPresent(id, "member") {
				return "cluster still has a member"
			}
			return ""
		},
	})
	// the source is stable (never transitions): seed it Available with no settle budget.
	w.Seed(&cloudfake.Resource{ID: "cl-x", Type: "cluster", State: cloudfake.Available,
		Tags: map[string]string{"groundhold-capability": capTag, "groundhold-environment": "prod"}})
	w.Seed(&cloudfake.Resource{ID: "cl-x-writer", Type: "member", State: cloudfake.Available})
	return w
}

// TestProbeAuroraLeakDetector is the Layer-2 payoff on the REAL driver: d.Probe runs
// its actual intrusive Aurora RTO against a World-backed fake. The World enforces the
// real teardown constraint (a cluster refuses deletion while its member is still
// deleting), and the World's LeakCheck — the universal postcondition — asserts no
// scratch was left behind. On the fixed driver this is clean; revert the member-gone
// wait and the same postcondition flags the leaked cluster, with NO bug-specific
// assertion (the mutation gate exercises exactly that revert).
func TestProbeAuroraLeakDetector(t *testing.T) {
	w := auroraProbeWorld(sanitizeTag("db"))
	srv := auroraWorldServer(t, w, "000000000000")
	defer srv.Close()
	d := probeDriver(t, srv)
	d.STSBaseURL = srv.URL
	d.PollTimeout = 2 * time.Second // bound the cleanup retry so a regression fails fast

	out, err := d.Probe("aurora", "db", "aurora:eu-central-1:cl-x", true)
	if err != nil {
		t.Fatal(err)
	}

	// (a) reality was exercised: an RTO measurement, no failures.
	var rto bool
	for _, m := range out.Measurements {
		if m.Path == "recovery.rto" {
			rto = true
		}
	}
	if !rto {
		t.Fatalf("expected an rto measurement (out=%+v)", out)
	}
	for _, f := range out.Failures {
		t.Errorf("unexpected probe failure: %+v", f)
	}

	// (b) THE UNIVERSAL POSTCONDITION: the fake's world holds no leaked scratch. This
	// is the assertion that catches the Aurora class generically — no per-bug logic.
	if leaked := w.LeakCheck(func(tags map[string]string) bool { return tags["groundhold-probe"] == "scratch" }); len(leaked) != 0 {
		t.Fatalf("LEAK: probe left billed scratch resources behind: %v", leaked)
	}

	// (c) anti-recursion: the green result did not ride an Assumed rule.
	if a := w.UsedAssumed(); len(a) != 0 {
		t.Fatalf("test passed through Assumed fake rules (not trustworthy): %v", a)
	}
}
