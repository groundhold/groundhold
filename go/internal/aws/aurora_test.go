package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// ---- candidate under test ----

func auroraAttrs() map[string]any {
	return map[string]any{
		"engine.protocol":        "postgresql/16",
		"location.region":        "eu-central-1",
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"availability.class":     "regional", // writer + reader
		"service.managed":        true,
		"recovery.rpo":           "5m",
	}
}

func auroraImpl() map[string]any {
	return map[string]any{
		"subnetGroupName":     "db-subnets",
		"masterUsername":      "admin",
		"masterPassword":      "secret123!",
		"kmsKeyArn":           "arn:aws:kms:eu-central-1:000000000000:key/abc",
		"serverlessMinACU":    float64(0.5),
		"serverlessMaxACU":    float64(4),
		"vpcSecurityGroupIds": []any{"sg-123"},
	}
}

// ---- Query-protocol fake (rds.<region>.amazonaws.com, the SAME API Aurora uses) ----

type fakeAurora struct {
	mu            sync.Mutex
	order         []string
	clusterExists bool
	// deleteKeepsCluster: DeleteDBCluster leaves the cluster present (still
	// "deleting") — the async-not-gone case the poll-to-absence (D972) must not
	// conclude as succeeded.
	deleteKeepsCluster bool
	// endpoints: a standing cluster HAS them. Omitting them made every create-path
	// test stop short of output derivation (D396) — the create fixture and the
	// outputs fixture were different fakes that never met.
	endpoint       string
	readerEndpoint string
	port           int
	clusterStatus  string
	clusterPending bool // D953: inject PendingModifiedValues (modify still applying)
	clusterBody    string
	instances      map[string]bool
	instanceBodies map[string]string
	tags           map[string]string

	instanceCreateErr string // error Code returned (HTTP 400) on CreateDBInstance

	// observe reverse-map fields
	engine             string
	engineVersion      string
	storageEncrypted   bool
	kmsKeyId           string
	keyManager         string // KMS DescribeKey KeyManager for the adopt-check trace (default CUSTOMER)
	backupRetention    int
	deletionProtection bool
	publiclyAccessible bool
	clusterParamGroup  string // DBClusterParameterGroup attached to the cluster
	forceSSL           string // TLS param value the group reports ("1"/"ON"/"0"/"")
	tlsParamName       string // which parameter the fake group carries (default rds.force_ssl)
	pgCreated          []string
	pgModified         []string
	pgDeleted          []string
	pgExists           bool // CreateDBClusterParameterGroup answers AlreadyExists
	forceSSLPage2      bool // rds.force_ssl only on the SECOND page (paginated)

	// DB subnet group (D278) fields.
	sgExists     bool     // CreateDBSubnetGroup answers AlreadyExists
	sgSubnetIDs  []string // subnets an existing group reports (DescribeDBSubnetGroups)
	sgCreated    []string // captured DBSubnetGroupName values from CreateDBSubnetGroup
	sgDeleted    []string
	sgDeleteErr  string // error Code returned (400) on DeleteDBSubnetGroup
	sgDeleteHTTP int    // non-zero overrides the DeleteDBSubnetGroup HTTP status

	// ModifyDBCluster / ModifyDBInstance (updateAurora) fields.
	modifyClusterBodies  []string
	modifyInstanceBodies []string
	modifyClusterErr     string // error Code (400) on ModifyDBCluster
	modifyClusterHTTP    int    // non-zero overrides the ModifyDBCluster HTTP status
	modifyInstanceErr    string
	modifyInstanceHTTP   int

	// discoverList, when non-nil, makes a no-filter DescribeDBClusters (used by
	// discoverAurora) answer a LIST of {id,engine} pairs instead of the single
	// f.clusterExists/clusterXML(id) cluster. A per-id DescribeDBClusters call
	// (identifier set) still falls through to the normal single-cluster behavior.
	discoverList []struct{ ID, Engine string }
}

func newFakeAurora() *fakeAurora {
	return &fakeAurora{
		instances:      map[string]bool{},
		instanceBodies: map[string]string{},
		tags:           map[string]string{},
		clusterStatus:  "available",
	}
}

func parseForm(body string) map[string]string {
	m := map[string]string{}
	for _, kv := range strings.Split(body, "&") {
		parts := strings.SplitN(kv, "=", 2)
		k, _ := url.QueryUnescape(parts[0])
		v := ""
		if len(parts) == 2 {
			v, _ = url.QueryUnescape(parts[1])
		}
		m[k] = v
	}
	return m
}

func (f *fakeAurora) sortedInstances() []string {
	out := make([]string, 0, len(f.instances))
	for k := range f.instances {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// endpointXML emits the endpoint trio only when the fake was given them, so every
// existing test keeps its exact wire shape.
func endpointXML(writer, reader string, port int) string {
	if writer == "" {
		return ""
	}
	return `<Endpoint>` + writer + `</Endpoint>` +
		`<ReaderEndpoint>` + reader + `</ReaderEndpoint>` +
		`<Port>` + strconv.Itoa(port) + `</Port>`
}

// pendingXML injects a PendingModifiedValues element (D953): non-empty means an accepted
// modify is still applying, empty means it has landed.
func pendingXML(pending bool) string {
	if pending {
		return `<PendingModifiedValues><BackupRetentionPeriod>1</BackupRetentionPeriod></PendingModifiedValues>`
	}
	return `<PendingModifiedValues></PendingModifiedValues>`
}

func (f *fakeAurora) clusterXML(id string) string {
	var members string
	for _, m := range f.sortedInstances() {
		writer := "false"
		if strings.HasSuffix(m, "-writer") {
			writer = "true"
		}
		members += `<DBClusterMember><DBInstanceIdentifier>` + m + `</DBInstanceIdentifier>` +
			`<IsClusterWriter>` + writer + `</IsClusterWriter></DBClusterMember>`
	}
	var taglist string
	if len(f.tags) > 0 {
		keys := make([]string, 0, len(f.tags))
		for k := range f.tags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		taglist = "<TagList>"
		for _, k := range keys {
			taglist += "<Tag><Key>" + k + "</Key><Value>" + f.tags[k] + "</Value></Tag>"
		}
		taglist += "</TagList>"
	}
	return `<DescribeDBClustersResponse><DescribeDBClustersResult><DBClusters><DBCluster>` +
		`<DBClusterIdentifier>` + id + `</DBClusterIdentifier>` +
		`<Status>` + f.clusterStatus + `</Status>` +
		endpointXML(f.endpoint, f.readerEndpoint, f.port) +
		`<Engine>` + f.engine + `</Engine><EngineVersion>` + f.engineVersion + `</EngineVersion>` +
		`<StorageEncrypted>` + boolStr(f.storageEncrypted) + `</StorageEncrypted>` +
		`<KmsKeyId>` + f.kmsKeyId + `</KmsKeyId>` +
		`<DBClusterParameterGroup>` + f.clusterParamGroup + `</DBClusterParameterGroup>` +
		`<BackupRetentionPeriod>` + strconv.Itoa(f.backupRetention) + `</BackupRetentionPeriod>` +
		`<DeletionProtection>` + boolStr(f.deletionProtection) + `</DeletionProtection>` +
		pendingXML(f.clusterPending) +
		`<DBClusterMembers>` + members + `</DBClusterMembers>` + taglist +
		`</DBCluster></DBClusters></DescribeDBClustersResult></DescribeDBClustersResponse>`
}

func auroraInstanceXML(id string, public bool) string {
	return `<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>` +
		`<DBInstanceIdentifier>` + id + `</DBInstanceIdentifier>` +
		`<DBInstanceStatus>available</DBInstanceStatus>` +
		`<Engine>aurora-postgresql</Engine>` +
		`<PubliclyAccessible>` + boolStr(public) + `</PubliclyAccessible>` +
		`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`
}

func (f *fakeAurora) handler(t *testing.T, rec *capture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		if rec != nil {
			rec.record(r, body)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		// D1062: the adopt-check's KMS key trace is a JSON-protocol call (X-Amz-Target:
		// TrentService.DescribeKey), not a Query Action= — answer it before the switch.
		if tgt := r.Header.Get("X-Amz-Target"); strings.HasSuffix(tgt, "DescribeKey") {
			km := f.keyManager
			if km == "" {
				km = "CUSTOMER"
			}
			_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyManager":"` + km + `"}}`))
			return
		}
		form := parseForm(body)
		switch form["Action"] {
		case "CreateDBCluster":
			f.order = append(f.order, "CreateDBCluster")
			f.clusterExists = true
			f.clusterBody = body
			_, _ = w.Write([]byte(`<CreateDBClusterResponse></CreateDBClusterResponse>`))
		case "CreateDBInstance":
			if f.instanceCreateErr != "" {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>` + f.instanceCreateErr + `</Code></Error></ErrorResponse>`))
				return
			}
			f.order = append(f.order, "CreateDBInstance")
			id := form["DBInstanceIdentifier"]
			f.instances[id] = true
			f.instanceBodies[id] = body
			_, _ = w.Write([]byte(`<CreateDBInstanceResponse></CreateDBInstanceResponse>`))
		case "DescribeDBClusters":
			if form["DBClusterIdentifier"] == "" && f.discoverList != nil {
				var items string
				for _, c := range f.discoverList {
					items += `<DBCluster><DBClusterIdentifier>` + c.ID + `</DBClusterIdentifier>` +
						`<Engine>` + c.Engine + `</Engine></DBCluster>`
				}
				_, _ = w.Write([]byte(`<DescribeDBClustersResponse><DescribeDBClustersResult><DBClusters>` +
					items + `</DBClusters></DescribeDBClustersResult></DescribeDBClustersResponse>`))
				return
			}
			if !f.clusterExists {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>DBClusterNotFoundFault</Code></Error></ErrorResponse>`))
				return
			}
			_, _ = w.Write([]byte(f.clusterXML(form["DBClusterIdentifier"])))
		case "CreateDBSubnetGroup":
			f.sgCreated = append(f.sgCreated, form["DBSubnetGroupName"])
			if f.sgExists {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>DBSubnetGroupAlreadyExists</Code></Error></ErrorResponse>`))
				return
			}
			_, _ = w.Write([]byte(`<CreateDBSubnetGroupResponse/>`))
		case "DescribeDBSubnetGroups":
			if !f.sgExists {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>DBSubnetGroupNotFoundFault</Code></Error></ErrorResponse>`))
				return
			}
			var subnets string
			for _, s := range f.sgSubnetIDs {
				subnets += `<Subnet><SubnetIdentifier>` + s + `</SubnetIdentifier></Subnet>`
			}
			_, _ = w.Write([]byte(`<DescribeDBSubnetGroupsResponse><DescribeDBSubnetGroupsResult><DBSubnetGroups>` +
				`<DBSubnetGroup><Subnets>` + subnets + `</Subnets></DBSubnetGroup>` +
				`</DBSubnetGroups></DescribeDBSubnetGroupsResult></DescribeDBSubnetGroupsResponse>`))
		case "DeleteDBSubnetGroup":
			f.sgDeleted = append(f.sgDeleted, form["DBSubnetGroupName"])
			if f.sgDeleteHTTP != 0 {
				w.WriteHeader(f.sgDeleteHTTP)
				if f.sgDeleteErr != "" {
					_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>` + f.sgDeleteErr + `</Code></Error></ErrorResponse>`))
				}
				return
			}
			_, _ = w.Write([]byte(`<DeleteDBSubnetGroupResponse/>`))
		case "ModifyDBCluster":
			f.modifyClusterBodies = append(f.modifyClusterBodies, body)
			if f.modifyClusterHTTP != 0 {
				w.WriteHeader(f.modifyClusterHTTP)
				if f.modifyClusterErr != "" {
					_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>` + f.modifyClusterErr + `</Code></Error></ErrorResponse>`))
				}
				return
			}
			_, _ = w.Write([]byte(`<ModifyDBClusterResponse/>`))
		case "ModifyDBInstance":
			f.modifyInstanceBodies = append(f.modifyInstanceBodies, body)
			if f.modifyInstanceHTTP != 0 {
				w.WriteHeader(f.modifyInstanceHTTP)
				if f.modifyInstanceErr != "" {
					_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>` + f.modifyInstanceErr + `</Code></Error></ErrorResponse>`))
				}
				return
			}
			_, _ = w.Write([]byte(`<ModifyDBInstanceResponse/>`))
		case "CreateDBClusterParameterGroup":
			f.pgCreated = append(f.pgCreated, form["DBClusterParameterGroupName"]+"|"+form["DBParameterGroupFamily"])
			if f.pgExists {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>DBParameterGroupAlreadyExists</Code></Error></ErrorResponse>`))
				return
			}
			_, _ = w.Write([]byte(`<CreateDBClusterParameterGroupResponse/>`))
		case "ModifyDBClusterParameterGroup":
			f.pgModified = append(f.pgModified,
				form["Parameters.member.1.ParameterName"]+"="+form["Parameters.member.1.ParameterValue"])
			_, _ = w.Write([]byte(`<ModifyDBClusterParameterGroupResponse/>`))
		case "DeleteDBClusterParameterGroup":
			f.pgDeleted = append(f.pgDeleted, form["DBClusterParameterGroupName"])
			_, _ = w.Write([]byte(`<DeleteDBClusterParameterGroupResponse/>`))
		case "DescribeDBClusterParameters":
			param, respMarker := "", ""
			pname := f.tlsParamName
			if pname == "" {
				pname = "rds.force_ssl"
			}
			forceParam := `<Parameter><ParameterName>` + pname + `</ParameterName>` +
				`<ParameterValue>` + f.forceSSL + `</ParameterValue></Parameter>`
			switch {
			case f.forceSSLPage2:
				// rds.force_ssl sits on page 2: page 1 is empty + a Marker; the
				// follow-up request (Marker set) returns the parameter.
				if form["Marker"] == "" {
					respMarker = "PAGE2"
				} else if f.forceSSL != "" {
					param = forceParam
				}
			case f.forceSSL != "":
				param = forceParam
			}
			_, _ = w.Write([]byte(`<DescribeDBClusterParametersResponse><DescribeDBClusterParametersResult>` +
				`<Parameters>` + param + `</Parameters><Marker>` + respMarker + `</Marker>` +
				`</DescribeDBClusterParametersResult></DescribeDBClusterParametersResponse>`))
		case "DescribeDBInstances":
			id := form["DBInstanceIdentifier"]
			if !f.instances[id] {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>DBInstanceNotFound</Code></Error></ErrorResponse>`))
				return
			}
			_, _ = w.Write([]byte(auroraInstanceXML(id, f.publiclyAccessible)))
		case "DeleteDBInstance":
			f.order = append(f.order, "DeleteDBInstance")
			delete(f.instances, form["DBInstanceIdentifier"])
			_, _ = w.Write([]byte(`<DeleteDBInstanceResponse></DeleteDBInstanceResponse>`))
		case "DeleteDBCluster":
			f.order = append(f.order, "DeleteDBCluster")
			if !f.deleteKeepsCluster {
				f.clusterExists = false
			}
			_, _ = w.Write([]byte(`<DeleteDBClusterResponse></DeleteDBClusterResponse>`))
		default:
			w.WriteHeader(404)
		}
	}))
}

func auroraTestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.RDSBaseURL = srv.URL
	// KMS trace defaults to the same fake (KMS is a different protocol, so it 404s
	// -> the CMK trace is unreadable -> a diagnostic); tests that measure CMK point
	// KMSBaseURL at a real KMS fake. Keeps the suite hermetic (no live KMS call).
	d.KMSBaseURL = srv.URL
	d.Account = "000000000000"
	d.PollInterval = 0
	d.PollTimeout = 2 * time.Second
	return d
}

// ---- tests ----

// TestAuroraFullCreateSucceeds: CreateDBCluster (aurora-postgresql + Serverless v2
// min/max + ownership tags) -> CreateDBInstance (db.serverless) x2 (regional) ->
// poll available -> succeeded WITH the pid. Every request is SigV4-signed.
func TestAuroraFullCreateSucceeds(t *testing.T) {
	f := newFakeAurora()
	f.clusterExists = false // a fresh create
	rec := newCapture()
	srv := f.handler(t, rec)
	defer srv.Close()
	d := auroraTestDriver(t, srv)

	res := d.createAurora("eu-central-1", "000000000000", "prod", "db", auroraAttrs(), auroraImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("create status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	wantPID := auroraProviderID("eu-central-1", DBIdentifier("000000000000", "prod", "db", 1))
	if res.ProviderID != wantPID {
		t.Fatalf("create providerId = %q, want %q", res.ProviderID, wantPID)
	}
	// CreateDBCluster BEFORE CreateDBInstance, and exactly one cluster + two members.
	if len(f.order) < 1 || f.order[0] != "CreateDBCluster" {
		t.Fatalf("order = %v, want CreateDBCluster first", f.order)
	}
	if strings.Count(strings.Join(f.order, ","), "CreateDBInstance") != 2 {
		t.Fatalf("order = %v, want two CreateDBInstance (writer + reader)", f.order)
	}
	// CreateDBCluster body assertions.
	for _, want := range []string{
		"Action=CreateDBCluster", "Engine=aurora-postgresql", "EngineVersion=16",
		"ServerlessV2ScalingConfiguration.MinCapacity=0.5",
		"ServerlessV2ScalingConfiguration.MaxCapacity=4",
		"StorageEncrypted=true", "DBSubnetGroupName=db-subnets",
		"MasterUsername=admin", "MasterUserPassword=secret123",
		"BackupRetentionPeriod=7", "DeletionProtection=true",
		// D884: the real query wire is VpcSecurityGroupIds.VpcSecurityGroupId.N — no extra
		// .member. level. The old expectation pinned the malformed form AWS 400s.
		"groundhold-capability", "VpcSecurityGroupIds.VpcSecurityGroupId.1=sg-123",
	} {
		if !strings.Contains(f.clusterBody, want) {
			t.Errorf("CreateDBCluster body missing %q\nbody: %s", want, f.clusterBody)
		}
	}
	// CreateDBInstance body: db.serverless, attached to the cluster.
	sawServerless := false
	for _, b := range f.instanceBodies {
		if strings.Contains(b, "DBInstanceClass=db.serverless") && strings.Contains(b, "Engine=aurora-postgresql") {
			sawServerless = true
		}
	}
	if !sawServerless {
		t.Fatalf("no CreateDBInstance body carried DBInstanceClass=db.serverless: %v", f.instanceBodies)
	}
	if rec.unsign != 0 {
		t.Fatalf("every Aurora request must be SigV4-signed; %d were not", rec.unsign)
	}
}

// TestAuroraPartialInstanceFailIsUnknownWithPID: the four-valued crux — the
// CLUSTER lands but CreateDBInstance fails. The result must be unknown WITH the
// providerId (a half-provisioned cluster to reconcile), never a bare "failed".
func TestAuroraPartialInstanceFailIsUnknownWithPID(t *testing.T) {
	f := newFakeAurora()
	f.clusterExists = false
	f.instanceCreateErr = "InvalidParameterValue"
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)

	res := d.createAurora("eu-central-1", "000000000000", "prod", "db", auroraAttrs(), auroraImpl(), 1)
	if res.Status != "unknown" {
		t.Fatalf("cluster created + instance failed must be unknown, got %q (%s)", res.Status, res.Reason)
	}
	wantPID := auroraProviderID("eu-central-1", DBIdentifier("000000000000", "prod", "db", 1))
	if res.ProviderID != wantPID {
		t.Fatalf("partial-failure unknown must carry the providerId, got %q", res.ProviderID)
	}
	if !f.clusterExists {
		t.Fatal("the cluster should have landed before the instance failure")
	}
}

// TestAuroraObserveReverseMap: DescribeDBClusters -> the database.relational
// attrs; public exposure comes from the writer member instance.
func TestAuroraObserveReverseMap(t *testing.T) {
	f := newFakeAurora()
	f.clusterExists = true
	f.engine = "aurora-postgresql"
	f.engineVersion = "16.4"
	f.storageEncrypted = true
	f.kmsKeyId = "arn:aws:kms:eu-central-1:000000000000:key/abc"
	f.backupRetention = 7
	f.publiclyAccessible = false
	clusterID := DBIdentifier("000000000000", "prod", "db", 1)
	f.instances[clusterID+"-writer"] = true // sets the writer member
	f.instances[clusterID+"-reader"] = true // second member => regional
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)

	obs, diags, err := d.observeAurora("db", auroraProviderID("eu-central-1", clusterID))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["engine.protocol"] != "postgresql/16.4" {
		t.Fatalf("engine.protocol = %v, want postgresql/16.4", got["engine.protocol"])
	}
	if got["encryption.atRest"] != true {
		t.Fatalf("encryption.atRest = %v", got["encryption.atRest"])
	}
	if got["availability.class"] != "regional" {
		t.Fatalf("availability.class = %v, want regional (writer + reader)", got["availability.class"])
	}
	if got["network.publicExposure"] != false {
		t.Fatalf("network.publicExposure = %v, want false", got["network.publicExposure"])
	}
	// D1062: the fixture's KmsKeyId is traced to KMS (DescribeKey -> KeyManager=CUSTOMER
	// by default), so CMEK is a MEASURED true — the KmsKeyId is no longer punted as
	// "cannot prove a customer key"; the trace proves it (the same read the adopt-check
	// relies on).
	if got["encryption.customerManagedKeys"] != true {
		t.Fatalf("CMEK = %v, want measured true (traced customer key)", got["encryption.customerManagedKeys"])
	}
	_ = diags
}

// TestAuroraCreateForeignRefuses: a cluster already at our name whose tags are
// not ours must be refused (failed), never adopted, before any mutation.
func TestAuroraCreateForeignRefuses(t *testing.T) {
	f := newFakeAurora()
	f.clusterExists = true
	f.tags = map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)

	res := d.createAurora("eu-central-1", "000000000000", "prod", "db", auroraAttrs(), auroraImpl(), 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign cluster must be refused, got %+v", res)
	}
	for _, o := range f.order {
		if o == "CreateDBCluster" || o == "CreateDBInstance" {
			t.Fatalf("refusal must not mutate; order = %v", f.order)
		}
	}
}

// TestAuroraDeleteAsyncNotGoneIsUnknown pins D972: a cluster delete the provider
// ACCEPTS but that leaves the cluster "deleting" (not gone) must report unknown —
// never a terminal "succeeded" that tombstones a data-bearing cluster still live.
func TestAuroraDeleteAsyncNotGoneIsUnknown(t *testing.T) {
	f := newFakeAurora()
	f.clusterExists = true
	f.deleteKeepsCluster = true // the cluster never leaves "deleting"
	f.tags = map[string]string{
		"groundhold-capability": sanitizeTag("db"), "groundhold-environment": sanitizeTag("prod")}
	clusterID := DBIdentifier("000000000000", "prod", "db", 1)
	f.instances[clusterID+"-writer"] = true
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)
	d.PollTimeout = 5 * time.Millisecond // times out fast; the cluster never leaves "deleting"
	res := d.deleteAurora("db", "prod", auroraProviderID("eu-central-1", clusterID))
	if res.Status != "unknown" {
		t.Fatalf("an accepted-but-still-deleting cluster must be unknown (keep the handle), "+
			"got %+v — reporting succeeded tombstones a data-bearing cluster still live", res)
	}
}

// TestAuroraDeleteReverseOrder: delete tears the composite down in REVERSE order —
// the member instances first, then DeleteDBCluster — ownership-guarded.
func TestAuroraDeleteReverseOrder(t *testing.T) {
	f := newFakeAurora()
	f.clusterExists = true
	f.tags = map[string]string{
		"groundhold-capability": sanitizeTag("db"), "groundhold-environment": sanitizeTag("prod")}
	clusterID := DBIdentifier("000000000000", "prod", "db", 1)
	f.instances[clusterID+"-writer"] = true
	f.instances[clusterID+"-reader"] = true
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)

	res := d.deleteAurora("db", "prod", auroraProviderID("eu-central-1", clusterID))
	if res.Status != "succeeded" {
		t.Fatalf("delete status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	joined := strings.Join(f.order, ",")
	if f.order[len(f.order)-1] != "DeleteDBCluster" {
		t.Fatalf("DeleteDBCluster must be last (reverse order); order = %v", f.order)
	}
	if strings.Count(joined, "DeleteDBInstance") != 2 {
		t.Fatalf("both member instances must be deleted before the cluster; order = %v", f.order)
	}
	if strings.Index(joined, "DeleteDBInstance") > strings.Index(joined, "DeleteDBCluster") {
		t.Fatalf("instances must be deleted BEFORE the cluster; order = %v", f.order)
	}
}

// TestAuroraDeleteProtectedRefused: deletion protection is never auto-disabled.
func TestAuroraDeleteProtectedRefused(t *testing.T) {
	f := newFakeAurora()
	f.clusterExists = true
	f.deletionProtection = true
	f.tags = map[string]string{
		"groundhold-capability": sanitizeTag("db"), "groundhold-environment": sanitizeTag("prod")}
	clusterID := DBIdentifier("000000000000", "prod", "db", 1)
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)

	res := d.deleteAurora("db", "prod", auroraProviderID("eu-central-1", clusterID))
	if res.Status != "failed" || !strings.Contains(res.Reason, "deletion protection") {
		t.Fatalf("protected cluster must refuse delete, got %+v", res)
	}
}

// TestAuroraBuildRefusals: refuse-before-mutate for the required operands and
// unmapped attributes — all at BuildAurora, before any network call.
func TestAuroraBuildRefusals(t *testing.T) {
	cases := map[string]func(a, i map[string]any){
		"missing subnetGroupName": func(a, i map[string]any) { delete(i, "subnetGroupName") },
		"missing serverlessMin":   func(a, i map[string]any) { delete(i, "serverlessMinACU") },
		"missing serverlessMax":   func(a, i map[string]any) { delete(i, "serverlessMaxACU") },
		"max below min":           func(a, i map[string]any) { i["serverlessMaxACU"] = float64(0.25) },
		"atRest without kms":      func(a, i map[string]any) { delete(i, "kmsKeyArn") },
		"unknown engine":          func(a, i map[string]any) { a["engine.protocol"] = "oracle/19" },
		"encryption false":        func(a, i map[string]any) { a["encryption.atRest"] = false },
		"multi-regional":          func(a, i map[string]any) { a["availability.class"] = "multi-regional" },
		// D288 REPLACES the old "inTransit without a group refuses" case: the
		// driver now DERIVES the group. What must still refuse is the case where
		// deriving would be a GUESS — an engine version too vague to name the
		// parameter-group family. The safety property survives the decision
		// change; only the case that carries it moved.
		"inTransit with an underivable family": func(a, i map[string]any) {
			a["encryption.inTransit"] = true
			a["engine.protocol"] = "postgresql" // no major version
		},
		"missing masterUsername":    func(a, i map[string]any) { delete(i, "masterUsername") },
		"missing master credential": func(a, i map[string]any) { delete(i, "masterPassword") },
		"password and managed both": func(a, i map[string]any) { i["manageMasterUserPassword"] = true },
		"unmapped attr":             func(a, i map[string]any) { a["network.foo"] = "x" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			a, i := auroraAttrs(), auroraImpl()
			mut(a, i)
			if _, err := BuildAurora("000000000000", "prod", "db", a, i, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}

// TestAuroraManagedMasterPassword: manageMasterUserPassword=true is the secure
// credential shape (AWS Secrets Manager holds the password, no plaintext in the
// candidate) — CreateDBCluster carries ManageMasterUserPassword and no
// MasterUserPassword.
func TestAuroraManagedMasterPassword(t *testing.T) {
	i := auroraImpl()
	delete(i, "masterPassword")
	i["manageMasterUserPassword"] = true
	plan, err := BuildAurora("000000000000", "prod", "db", auroraAttrs(), i, 1)
	if err != nil {
		t.Fatalf("managed master password must be honored: %v", err)
	}
	if plan.clusterParams["ManageMasterUserPassword"] != "true" {
		t.Fatalf("ManageMasterUserPassword not set: %v", plan.clusterParams)
	}
	if _, has := plan.clusterParams["MasterUserPassword"]; has {
		t.Fatal("a managed password must NOT put a plaintext MasterUserPassword on the request")
	}
	if plan.clusterParams["MasterUsername"] != "admin" {
		t.Fatal("masterUsername is still required with a managed password")
	}
}

// TestAuroraInTransitParamGroup: encryption.inTransit=true is honored when the
// operator brings a pre-created cluster parameter group (rds.force_ssl=1) — the
// driver references it on CreateDBCluster (DBClusterParameterGroupName), the same
// operand shape as subnetGroupName/kmsKeyArn.
func TestAuroraInTransitParamGroup(t *testing.T) {
	a := auroraAttrs()
	a["encryption.inTransit"] = true
	i := auroraImpl()
	i["clusterParameterGroupName"] = "force-ssl-pg16"
	plan, err := BuildAurora("000000000000", "prod", "db", a, i, 1)
	if err != nil {
		t.Fatalf("inTransit with a param group must be honored: %v", err)
	}
	if plan.clusterParams["DBClusterParameterGroupName"] != "force-ssl-pg16" {
		t.Fatalf("DBClusterParameterGroupName = %q, want force-ssl-pg16",
			plan.clusterParams["DBClusterParameterGroupName"])
	}
}

// TestAuroraObserveInTransit: observe reads rds.force_ssl from the attached
// cluster parameter group (DescribeDBClusterParameters) and reports the MEASURED
// reality — force_ssl=1 => inTransit true, force_ssl=0 => false. A group without
// force_ssl must never be reported as TLS-enforced.
func TestAuroraObserveInTransit(t *testing.T) {
	clusterID := DBIdentifier("000000000000", "prod", "db", 1)
	for _, tc := range []struct {
		name  string
		force string
		want  bool
	}{
		{"forced", "1", true},
		{"not forced", "0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAurora()
			f.clusterExists = true
			f.engine = "aurora-postgresql"
			f.clusterParamGroup = "force-ssl-pg16"
			f.forceSSL = tc.force
			f.instances[clusterID+"-writer"] = true
			srv := f.handler(t, nil)
			defer srv.Close()
			d := auroraTestDriver(t, srv)
			obs, _, err := d.observeAurora("db", auroraProviderID("eu-central-1", clusterID))
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["encryption.inTransit"] != tc.want {
				t.Fatalf("encryption.inTransit = %v, want %v", got["encryption.inTransit"], tc.want)
			}
		})
	}
}

// TestAuroraObserveCMK: observe traces the cluster's KMS key to KMS
// (DescribeKey -> KeyManager) and MEASURES encryption.customerManagedKeys — a
// CUSTOMER key => true, an AWS-managed default => false. No more punting.
func TestAuroraObserveCMK(t *testing.T) {
	clusterID := DBIdentifier("000000000000", "prod", "db", 1)
	for _, tc := range []struct {
		name    string
		manager string
		want    bool
	}{
		{"customer key", "CUSTOMER", true},
		{"aws default", "AWS", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAurora()
			f.clusterExists = true
			f.engine = "aurora-postgresql"
			f.storageEncrypted = true
			f.kmsKeyId = "arn:aws:kms:eu-central-1:000000000000:key/abc"
			f.instances[clusterID+"-writer"] = true
			srv := f.handler(t, nil)
			defer srv.Close()
			kms := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyManager":"` + tc.manager + `"}}`))
				}))
			defer kms.Close()
			d := auroraTestDriver(t, srv)
			d.KMSBaseURL = kms.URL
			obs, _, err := d.observeAurora("db", auroraProviderID("eu-central-1", clusterID))
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["encryption.customerManagedKeys"] != tc.want {
				t.Fatalf("customerManagedKeys = %v, want %v", got["encryption.customerManagedKeys"], tc.want)
			}
		})
	}
}

// TestAuroraZonalIsSingleWriter: availability.class=zonal plans one member.
func TestAuroraZonalIsSingleWriter(t *testing.T) {
	a := auroraAttrs()
	a["availability.class"] = "zonal"
	plan, err := BuildAurora("000000000000", "prod", "db", a, auroraImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Regional || plan.ReaderID != "" {
		t.Fatalf("zonal must plan no reader, got regional=%v reader=%q", plan.Regional, plan.ReaderID)
	}
	if plan.WriterID == "" {
		t.Fatal("zonal must still plan a writer")
	}
}

// TestSplitAuroraProviderID guards the id shape.
func TestSplitAuroraProviderID(t *testing.T) {
	if _, _, err := splitAuroraProviderID("aurora:eu-central-1:db-abcd1234"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	for _, bad := range []string{"eu:db", "rds:eu-central-1:db", "aurora:eu-central-1:9bad", "aurora:bad:db"} {
		if _, _, err := splitAuroraProviderID(bad); err == nil {
			t.Errorf("accepted malformed aurora id %q", bad)
		}
	}
}

// TestAuroraObserveInTransitPaginated pins the reconcile fix: rds.force_ssl on a
// LATER page of DescribeDBClusterParameters must still be found — a single-page
// scan false-negatived TLS and drifted a bound cluster at reconcile (real-cloud F17).
func TestAuroraObserveInTransitPaginated(t *testing.T) {
	clusterID := DBIdentifier("000000000000", "prod", "db", 1)
	f := newFakeAurora()
	f.clusterExists = true
	f.engine = "aurora-postgresql"
	f.clusterParamGroup = "acme-aurora-pg"
	f.forceSSL = "1"
	f.forceSSLPage2 = true // only reachable by following the Marker
	f.instances[clusterID+"-writer"] = true
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)
	obs, _, err := d.observeAurora("db", auroraProviderID("eu-central-1", clusterID))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["encryption.inTransit"] != true {
		t.Fatalf("force_ssl=1 on page 2 must observe inTransit=true (pagination), got %v", got["encryption.inTransit"])
	}
}

// D278: placement via implementation.subnetIds (typically {$ref:
// vpc.privateSubnetIds}) — the driver derives and owns the DB subnet group.
func TestBuildAuroraSubnetIdsDerivesGroup(t *testing.T) {
	i := auroraImpl()
	delete(i, "subnetGroupName")
	i["subnetIds"] = []any{"subnet-a", "subnet-b"}
	plan, err := BuildAurora("000000000000", "prod", "db", auroraAttrs(), i, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := derivedSubnetGroupName("prod", "db")
	if plan.DeriveSubnetGroup != want || plan.clusterParams["DBSubnetGroupName"] != want {
		t.Fatalf("derived group = %q / cp %q, want %q",
			plan.DeriveSubnetGroup, plan.clusterParams["DBSubnetGroupName"], want)
	}
	if len(plan.SubnetIDs) != 2 {
		t.Fatalf("SubnetIDs = %v", plan.SubnetIDs)
	}

	// both sources → refuse (one source of truth)
	i = auroraImpl()
	i["subnetIds"] = []any{"subnet-a", "subnet-b"}
	if _, err := BuildAurora("000000000000", "prod", "db", auroraAttrs(), i, 1); err == nil {
		t.Fatal("subnetGroupName+subnetIds together must refuse")
	}

	// a single subnet cannot span AZs → refuse
	i = auroraImpl()
	delete(i, "subnetGroupName")
	i["subnetIds"] = []any{"subnet-a"}
	if _, err := BuildAurora("000000000000", "prod", "db", auroraAttrs(), i, 1); err == nil {
		t.Fatal("a 1-subnet DB subnet group must refuse")
	}

	// neither source → the refusal names BOTH options
	i = auroraImpl()
	delete(i, "subnetGroupName")
	_, err = BuildAurora("000000000000", "prod", "db", auroraAttrs(), i, 1)
	if err == nil || !strings.Contains(err.Error(), "subnetIds") ||
		!strings.Contains(err.Error(), "subnetGroupName") {
		t.Fatalf("the placement refusal must name both operand options, got: %v", err)
	}
}

// D288: encryption.inTransit=true with no operator group makes the driver
// DERIVE and own a cluster parameter group carrying exactly the parameter that
// enforces TLS for THIS engine — the mechanism realizing a declared attribute,
// the D278 shape. The engine split is the trap: PostgreSQL and MySQL enforce
// through different parameters, so a single hardcoded name would create a group
// that enforces nothing on the other engine while the contract claims TLS.
func TestBuildAuroraDerivesTLSParamGroupPerEngine(t *testing.T) {
	cases := []struct {
		proto, wantFamily, wantParam, wantValue string
	}{
		{"postgresql/16", "aurora-postgresql16", "rds.force_ssl", "1"},
		{"postgresql/15.4", "aurora-postgresql15", "rds.force_ssl", "1"},
		{"mysql/8.0", "aurora-mysql8.0", "require_secure_transport", "ON"},
		{"mysql/5.7", "aurora-mysql5.7", "require_secure_transport", "ON"},
	}
	for _, c := range cases {
		a, i := auroraAttrs(), auroraImpl()
		a["encryption.inTransit"] = true
		a["engine.protocol"] = c.proto
		delete(i, "clusterParameterGroupName")
		p, err := BuildAurora("000000000000", "prod", "db", a, i, 1)
		if err != nil {
			t.Fatalf("%s: %v", c.proto, err)
		}
		want := derivedParamGroupName("prod", "db")
		if p.DeriveParamGroup != want || p.clusterParams["DBClusterParameterGroupName"] != want {
			t.Fatalf("%s: group = %q / attached %q, want %q",
				c.proto, p.DeriveParamGroup, p.clusterParams["DBClusterParameterGroupName"], want)
		}
		if p.ParamFamily != c.wantFamily {
			t.Fatalf("%s: family = %q, want %q", c.proto, p.ParamFamily, c.wantFamily)
		}
		if p.TLSParamName != c.wantParam || p.TLSParamValue != c.wantValue {
			t.Fatalf("%s: parameter = %s=%s, want %s=%s",
				c.proto, p.TLSParamName, p.TLSParamValue, c.wantParam, c.wantValue)
		}
	}
}

// An operator-supplied group still WINS and is attached verbatim — the driver
// never edits a group it does not own, and derives nothing alongside it.
func TestBuildAuroraOperatorGroupWins(t *testing.T) {
	a, i := auroraAttrs(), auroraImpl()
	a["encryption.inTransit"] = true
	i["clusterParameterGroupName"] = "acme-aurora-pg"
	p, err := BuildAurora("000000000000", "prod", "db", a, i, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.DeriveParamGroup != "" {
		t.Fatalf("an operator group must suppress derivation, got %q", p.DeriveParamGroup)
	}
	if p.clusterParams["DBClusterParameterGroupName"] != "acme-aurora-pg" {
		t.Fatalf("operator group must be attached verbatim: %q",
			p.clusterParams["DBClusterParameterGroupName"])
	}
}

// The refusal that REPLACES the old one: an engine whose TLS parameter or
// family this driver cannot name refuses, rather than creating a group that
// enforces nothing while the contract claims encryption.inTransit=true.
func TestBuildAuroraRefusesToGuessTLSMechanism(t *testing.T) {
	a, i := auroraAttrs(), auroraImpl()
	a["encryption.inTransit"] = true
	a["engine.protocol"] = "mysql/9.9" // no known family
	delete(i, "clusterParameterGroupName")
	_, err := BuildAurora("000000000000", "prod", "db", a, i, 1)
	if err == nil || !strings.Contains(err.Error(), "clusterParameterGroupName") {
		t.Fatalf("an underivable family must refuse and name the operand escape: %v", err)
	}
}

// D288 net path: the derived group is created with the right FAMILY, the TLS
// parameter is set on it, and only THEN is the cluster created attaching it.
func TestCreateAuroraDerivesParamGroupBeforeCluster(t *testing.T) {
	f := newFakeAurora()
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)
	a, i := auroraAttrs(), auroraImpl()
	a["encryption.inTransit"] = true
	delete(i, "clusterParameterGroupName")

	res := d.createAurora("eu-central-1", "000000000000", "prod", "db", a, i, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create = %+v", res)
	}
	want := derivedParamGroupName("prod", "db")
	if len(f.pgCreated) != 1 || f.pgCreated[0] != want+"|aurora-postgresql16" {
		t.Fatalf("param group create = %v, want %s with family aurora-postgresql16", f.pgCreated, want)
	}
	if len(f.pgModified) != 1 || f.pgModified[0] != "rds.force_ssl=1" {
		t.Fatalf("TLS parameter must be set: %v", f.pgModified)
	}
	if len(f.order) == 0 || f.order[0] != "CreateDBCluster" {
		t.Fatalf("cluster order = %v", f.order)
	}
	if !strings.Contains(f.clusterBody, "DBClusterParameterGroupName="+want) {
		t.Fatalf("cluster must attach the derived group: %s", f.clusterBody)
	}
}

// An existing group that ALREADY enforces TLS is reused untouched; the driver
// does not re-set a parameter it did not need to.
func TestEnsureParamGroupReusesEnforcingGroup(t *testing.T) {
	f := newFakeAurora()
	f.pgExists = true
	f.forceSSL = "1"
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)
	a, i := auroraAttrs(), auroraImpl()
	a["encryption.inTransit"] = true
	delete(i, "clusterParameterGroupName")

	res := d.createAurora("eu-central-1", "000000000000", "prod", "db", a, i, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create = %+v", res)
	}
	if len(f.pgModified) != 0 {
		t.Fatalf("an already-enforcing group must not be re-modified: %v", f.pgModified)
	}
}

// The F17-class regression guard: a MySQL cluster created WITH enforcement must
// OBSERVE inTransit=true. Reading the PostgreSQL parameter on a MySQL engine
// would report false forever and drift a correctly-configured cluster.
func TestObserveAuroraMySQLReadsItsOwnTLSParameter(t *testing.T) {
	f := newFakeAurora()
	f.clusterExists = true
	f.engine = "aurora-mysql"
	f.engineVersion = "8.0.mysql_aurora.3.04.0"
	f.clusterParamGroup = "pv-db-prod-tls-x"
	f.tlsParamName = "require_secure_transport"
	f.forceSSL = "ON" // MySQL spells it ON, not 1
	srv := f.handler(t, nil)
	defer srv.Close()
	d := auroraTestDriver(t, srv)

	obs, _, err := d.observeAurora("db", "aurora:eu-central-1:acme-db")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["encryption.inTransit"] != true {
		t.Fatalf("a MySQL cluster enforcing require_secure_transport=ON must observe "+
			"inTransit=true, got %v (all: %v)", got["encryption.inTransit"], got)
	}
}

// D3xx: Serverless v2 auto-pause — serverlessMinACU=0 scales the cluster to zero
// (idle floor ~0), the field-requested cost lever. AWS carries the pause delay in
// SecondsUntilAutoPause (300..86400, default 300), meaningful ONLY when min is 0.
func TestAuroraServerlessAutoPause(t *testing.T) {
	build := func(mut func(i map[string]any)) (AuroraPlan, error) {
		i := auroraImpl()
		mut(i)
		return BuildAurora("000000000000", "prod", "db", auroraAttrs(), i, 1)
	}
	const minKey = "ServerlessV2ScalingConfiguration.MinCapacity"
	const secKey = "ServerlessV2ScalingConfiguration.SecondsUntilAutoPause"

	// min=0 -> MinCapacity=0 + the default 300s auto-pause delay, explicit on the wire.
	p, err := build(func(i map[string]any) { i["serverlessMinACU"] = float64(0) })
	if err != nil {
		t.Fatalf("serverlessMinACU=0 must be allowed (auto-pause): %v", err)
	}
	if p.clusterParams[minKey] != "0" {
		t.Fatalf("MinCapacity = %q, want 0", p.clusterParams[minKey])
	}
	if p.clusterParams[secKey] != "300" {
		t.Fatalf("default auto-pause delay = %q, want 300", p.clusterParams[secKey])
	}

	// explicit in-range delay is carried through.
	p, err = build(func(i map[string]any) {
		i["serverlessMinACU"] = float64(0)
		i["serverlessSecondsUntilAutoPause"] = float64(3600)
	})
	if err != nil {
		t.Fatalf("min=0 + valid delay: %v", err)
	}
	if p.clusterParams[secKey] != "3600" {
		t.Fatalf("auto-pause delay = %q, want 3600", p.clusterParams[secKey])
	}

	// a pause delay with min>0 is meaningless — refuse, never silently ignore.
	if _, err = build(func(i map[string]any) { i["serverlessSecondsUntilAutoPause"] = float64(600) }); err == nil {
		t.Fatal("serverlessSecondsUntilAutoPause with min>0 must refuse")
	}
	// delay out of the AWS 300..86400 range refuses.
	if _, err = build(func(i map[string]any) {
		i["serverlessMinACU"] = float64(0)
		i["serverlessSecondsUntilAutoPause"] = float64(60)
	}); err == nil {
		t.Fatal("auto-pause delay < 300 must refuse")
	}
	// max=0 is still refused — only the MIN floor may be zero.
	if _, err = build(func(i map[string]any) { i["serverlessMaxACU"] = float64(0) }); err == nil {
		t.Fatal("serverlessMaxACU=0 must refuse")
	}
}

func rdsQueryRole(req *http.Request, body []byte) certifynet.Role {
	// the adopt-check's KMS key trace is a JSON-protocol read (X-Amz-Target:
	// TrentService.DescribeKey), not a Query-protocol Action= — classify it as the
	// READ it is, or it inflates the mutation count (D1062).
	if tgt := req.Header.Get("X-Amz-Target"); tgt != "" {
		op := tgt[strings.LastIndex(tgt, ".")+1:]
		if strings.HasPrefix(op, "Describe") || strings.HasPrefix(op, "List") || strings.HasPrefix(op, "Get") {
			return certifynet.RoleRead
		}
	}
	if v, err := url.ParseQuery(string(body)); err == nil {
		a := v.Get("Action")
		if strings.HasPrefix(a, "Describe") || strings.HasPrefix(a, "List") {
			return certifynet.RoleRead
		}
	}
	return certifynet.RoleMutateOpaque
}

// auroraAdoptSrv builds a 409/pre-read adopt fixture: our cluster (writer+reader
// both standing, so no member creation) configured by cfg (D1062).
func auroraAdoptSrv(t *testing.T, clusterID string, cfg func(*fakeAurora)) func() *httptest.Server {
	return func() *httptest.Server {
		f := newFakeAurora()
		f.clusterExists = true
		f.storageEncrypted = true // the candidate declares encryption.atRest
		f.engine = "aurora-postgresql"
		f.engineVersion = "16.3" // so observe can pick the TLS parameter name (rds.force_ssl)
		f.tags = map[string]string{
			"groundhold-capability":  sanitizeTag("db"),
			"groundhold-environment": sanitizeTag("prod"),
		}
		f.instances[clusterID+"-writer"] = true
		f.instances[clusterID+"-reader"] = true
		f.endpoint = clusterID + ".cluster-abc123.eu-central-1.rds.amazonaws.com"
		f.readerEndpoint = clusterID + ".cluster-ro-abc123.eu-central-1.rds.amazonaws.com"
		f.port = 5432
		if cfg != nil {
			cfg(f)
		}
		return f.handler(t, nil)
	}
}

// TestAdoptsExistingAurora enrols aurora in the D391 gate. Aurora is a COMPOSITE
// (cluster plus member instances) whose foreign case already had a test; the OURS case —
// our own cluster already standing, which is what every re-converge meets — did not.
func TestAdoptsExistingAurora(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	clusterID := DBIdentifier("000000000000", "prod", "db", 1)
	newDriver := func(happyURL string, rt http.RoundTripper) provider.Provider {
		d := NewDriver("eu-central-1")
		d.HTTP = &http.Client{Transport: rt}
		d.RDSBaseURL = happyURL
		d.KMSBaseURL = happyURL
		d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
		d.PollInterval = 0
		d.PollTimeout = 2 * time.Second
		return d
	}
	p := &certifynet.ExistingProbe{
		Name:           "aws/aurora",
		Classify:       rdsQueryRole,
		ExistingServer: auroraAdoptSrv(t, clusterID, nil),
		New:            newDriver,
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("aurora", "db", "prod", auroraAttrs(), auroraImpl(), "db", 1)
		},
		PID:              auroraProviderID("eu-central-1", clusterID),
		AllowedMutations: 4, // parameter-group + tag convergence onto the standing cluster
		// D1062: mirror RDS — encryption at rest, its customer key and TLS enforcement
		// are immutable; member public exposure is a mutable ModifyDBInstance.
		AdoptControls: auroraAdoptControls,
		MissingControl: []certifynet.ControlCase{
			{Path: "encryption.atRest", WantStatus: "failed", WantMutations: 4,
				Server: auroraAdoptSrv(t, clusterID, func(f *fakeAurora) { f.storageEncrypted = false })},
			{Path: "encryption.customerManagedKeys", WantStatus: "failed", WantMutations: 4,
				Server: auroraAdoptSrv(t, clusterID, func(f *fakeAurora) {
					f.kmsKeyId = "arn:aws:kms:eu-central-1:000000000000:key/abc"
					f.keyManager = "AWS"
				}),
				Create: func(pr provider.Provider) provider.CreateResult {
					a := auroraAttrs()
					a["encryption.customerManagedKeys"] = true
					im := auroraImpl()
					im["kms_key_id"] = "arn:aws:kms:eu-central-1:000000000000:key/abc"
					return pr.Create("aurora", "db", "prod", a, im, "db", 1)
				}},
			{Path: "encryption.inTransit", WantStatus: "failed", WantMutations: 4,
				Server: auroraAdoptSrv(t, clusterID, func(f *fakeAurora) {
					f.clusterParamGroup = "pg-tls"
					f.forceSSL = "0"
				}),
				Create: func(pr provider.Provider) provider.CreateResult {
					a := auroraAttrs()
					a["encryption.inTransit"] = true
					im := auroraImpl()
					im["db_cluster_parameter_group"] = "pg-tls"
					return pr.Create("aurora", "db", "prod", a, im, "db", 1)
				}},
			{Path: "network.publicExposure", WantStatus: "unknown", WantMutations: 4,
				Server: auroraAdoptSrv(t, clusterID, func(f *fakeAurora) { f.publiclyAccessible = true })},
		},
		MoreSecure: auroraAdoptSrv(t, clusterID, func(f *fakeAurora) {
			f.kmsKeyId = "arn:aws:kms:eu-central-1:000000000000:key/abc"
			f.keyManager = "CUSTOMER"
			f.clusterParamGroup = "pg-tls"
			f.forceSSL = "1"
		}),
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
