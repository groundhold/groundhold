package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func rdsAttrs() map[string]any {
	return map[string]any{
		"engine.protocol":        "postgresql/16",
		"location.region":        "eu-central-1",
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"availability.class":     "zonal",
		"service.managed":        true,
	}
}

func rdsImpl() map[string]any {
	return map[string]any{
		"instance_class":  "db.t3.micro",
		"master_username": "admin",
		"master_password": "secret123!",
	}
}

func TestBuildRDSGolden(t *testing.T) {
	id, body, err := BuildRDSCreate("000000000000", "prod", "db", rdsAttrs(), rdsImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !dbIDOK.MatchString(id) {
		t.Fatalf("db id invalid: %q", id)
	}
	for _, want := range []string{
		"Action=CreateDBInstance", "Engine=postgres", "EngineVersion=16",
		"StorageEncrypted=true", "PubliclyAccessible=false", "MultiAZ=false",
		"DBInstanceClass=db.t3.micro", "DeletionProtection=true",
		"groundhold-capability", "MasterUsername=admin",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("create body missing %q\nbody: %s", want, body)
		}
	}
}

func TestBuildRDSEngineMapping(t *testing.T) {
	for proto, eng := range map[string]string{
		"postgresql/16": "postgres", "mysql/8.0": "mysql", "mariadb/10": "mariadb",
	} {
		a := rdsAttrs()
		a["engine.protocol"] = proto
		_, body, err := BuildRDSCreate("a", "e", "db", a, rdsImpl(), 1)
		if err != nil || !strings.Contains(body, "Engine="+eng) {
			t.Errorf("%s -> Engine=%s failed: err=%v", proto, eng, err)
		}
	}
}

func TestBuildRDSRefusals(t *testing.T) {
	cases := map[string]struct {
		a func(map[string]any)
		i func(map[string]any)
	}{
		"unknown engine":  {func(a map[string]any) { a["engine.protocol"] = "oracle/19" }, nil},
		"no encryption":   {func(a map[string]any) { a["encryption.atRest"] = false }, nil},
		"multi-regional":  {func(a map[string]any) { a["availability.class"] = "multi-regional" }, nil},
		"unknown attr":    {func(a map[string]any) { a["network.foo"] = "x" }, nil},
		"no class":        {nil, func(i map[string]any) { delete(i, "instance_class") }},
		"no username":     {nil, func(i map[string]any) { delete(i, "master_username") }},
		"no password":     {nil, func(i map[string]any) { delete(i, "master_password") }},
		"nonbool delprot": {nil, func(i map[string]any) { i["deletion_protection"] = "false" }},
		"inTransit no pg": {func(a map[string]any) { a["encryption.inTransit"] = true }, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a, i := rdsAttrs(), rdsImpl()
			if c.a != nil {
				c.a(a)
			}
			if c.i != nil {
				c.i(i)
			}
			if _, _, err := BuildRDSCreate("a", "e", "db", a, i, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}

// TestBuildRDSInTransitParamGroup: encryption.inTransit=true is honored when the
// operator brings a pre-created DB parameter group (rds.force_ssl=1) — the driver
// references it on CreateDBInstance (DBParameterGroupName), the same operand shape
// as db_subnet_group/kms_key_id.
func TestBuildRDSInTransitParamGroup(t *testing.T) {
	a := rdsAttrs()
	a["encryption.inTransit"] = true
	i := rdsImpl()
	i["db_parameter_group"] = "force-ssl-pg16"
	_, body, err := BuildRDSCreate("000000000000", "prod", "db", a, i, 1)
	if err != nil {
		t.Fatalf("inTransit with a param group must be honored: %v", err)
	}
	if !strings.Contains(body, "DBParameterGroupName=force-ssl-pg16") {
		t.Fatalf("create body missing DBParameterGroupName=force-ssl-pg16\nbody: %s", body)
	}
}

// TestObserveRDSInTransit: observe reads the ENGINE'S TLS-enforcement parameter from
// the attached DB parameter group (DescribeDBParameters) and reports the MEASURED
// reality. D952: the parameter name is engine-specific — rds.force_ssl for Postgres,
// require_secure_transport for MySQL/MariaDB. The MySQL/MariaDB cases are the regression
// guard: before the fix observe scanned only rds.force_ssl, so a MySQL instance ENFORCING
// TLS via require_secure_transport was reported inTransit=false (a security-shaped lie).
func TestObserveRDSInTransit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		engine  string
		version string
		param   string
		value   string
		want    bool
	}{
		{"postgres forced", "postgres", "16.3", "rds.force_ssl", "1", true},
		{"postgres not forced", "postgres", "16.3", "rds.force_ssl", "0", false},
		{"mysql forced", "mysql", "8.0", "require_secure_transport", "ON", true},
		{"mysql not forced", "mysql", "8.0", "require_secure_transport", "OFF", false},
		{"mariadb forced", "mariadb", "10.11", "require_secure_transport", "1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					body := make([]byte, r.ContentLength)
					r.Body.Read(body)
					action := ""
					for _, kv := range strings.Split(string(body), "&") {
						if strings.HasPrefix(kv, "Action=") {
							action = strings.TrimPrefix(kv, "Action=")
						}
					}
					switch action {
					case "DescribeDBInstances":
						_, _ = w.Write([]byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>` +
							`<DBInstanceIdentifier>db-x</DBInstanceIdentifier>` +
							`<DBInstanceStatus>available</DBInstanceStatus>` +
							`<Engine>` + tc.engine + `</Engine><EngineVersion>` + tc.version + `</EngineVersion>` +
							`<StorageEncrypted>true</StorageEncrypted><PubliclyAccessible>false</PubliclyAccessible>` +
							`<MultiAZ>false</MultiAZ>` +
							`<DBParameterGroups><DBParameterGroup><DBParameterGroupName>tls-grp</DBParameterGroupName></DBParameterGroup></DBParameterGroups>` +
							`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
					case "DescribeDBParameters":
						param := `<Parameter><ParameterName>` + tc.param + `</ParameterName>` +
							`<ParameterValue>` + tc.value + `</ParameterValue></Parameter>`
						_, _ = w.Write([]byte(`<DescribeDBParametersResponse><DescribeDBParametersResult>` +
							`<Parameters>` + param + `</Parameters>` +
							`</DescribeDBParametersResult></DescribeDBParametersResponse>`))
					default:
						w.WriteHeader(404)
					}
				}))
			defer srv.Close()
			d := rdsTestDriver(t, srv)
			obs, _, err := d.observeRDS("db", "rds:eu-central-1:db-abcd1234")
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["encryption.inTransit"] != tc.want {
				t.Fatalf("engine %s: encryption.inTransit = %v, want %v",
					tc.engine, got["encryption.inTransit"], tc.want)
			}
		})
	}
}

// TestObserveRDSCMK: observe traces the instance's KMS key to KMS (DescribeKey ->
// KeyManager) and MEASURES encryption.customerManagedKeys — CUSTOMER => true,
// AWS-managed default => false.
func TestObserveRDSCMK(t *testing.T) {
	for _, tc := range []struct {
		name    string
		manager string
		want    bool
	}{
		{"customer key", "CUSTOMER", true},
		{"aws default", "AWS", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					body := make([]byte, r.ContentLength)
					r.Body.Read(body)
					if strings.Contains(string(body), "Action=DescribeDBInstances") {
						_, _ = w.Write([]byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>` +
							`<DBInstanceIdentifier>db-x</DBInstanceIdentifier>` +
							`<DBInstanceStatus>available</DBInstanceStatus>` +
							`<Engine>postgres</Engine><EngineVersion>16.3</EngineVersion>` +
							`<StorageEncrypted>true</StorageEncrypted><PubliclyAccessible>false</PubliclyAccessible>` +
							`<MultiAZ>false</MultiAZ>` +
							`<KmsKeyId>arn:aws:kms:eu-central-1:000000000000:key/abc</KmsKeyId>` +
							`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
						return
					}
					w.WriteHeader(404)
				}))
			defer srv.Close()
			kms := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyManager":"` + tc.manager + `"}}`))
				}))
			defer kms.Close()
			d := rdsTestDriver(t, srv)
			d.KMSBaseURL = kms.URL
			obs, _, err := d.observeRDS("db", "rds:eu-central-1:db-abcd1234")
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

// rdsServer answers the Query protocol. describeStatus controls the polled
// DBInstanceStatus; the first N describes return "creating" then "available".
func rdsServer(t *testing.T, createErr, delProtect string) *httptest.Server {
	t.Helper()
	describes := 0
	deleted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			r.Body.Read(body)
			action := ""
			for _, kv := range strings.Split(string(body), "&") {
				if strings.HasPrefix(kv, "Action=") {
					action = strings.TrimPrefix(kv, "Action=")
				}
			}
			// once deleted, the instance is GONE — the delete's poll-to-absence
			// (D968) must be able to confirm a 404, or a delete could never conclude.
			if deleted && action == "DescribeDBInstances" {
				w.WriteHeader(404)
				_, _ = w.Write([]byte("<ErrorResponse><Error><Code>DBInstanceNotFound</Code></Error></ErrorResponse>"))
				return
			}
			switch action {
			case "CreateDBInstance":
				if createErr != "" {
					w.WriteHeader(400)
					_, _ = w.Write([]byte("<ErrorResponse><Error><Code>" + createErr + "</Code></Error></ErrorResponse>"))
					return
				}
				_, _ = w.Write([]byte(`<CreateDBInstanceResponse></CreateDBInstanceResponse>`))
			case "DescribeDBInstances":
				describes++
				status := "creating"
				if describes >= 2 {
					status = "available"
				}
				_, _ = w.Write([]byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>` +
					`<DBInstanceIdentifier>db-x</DBInstanceIdentifier>` +
					`<DBInstanceStatus>` + status + `</DBInstanceStatus>` +
					`<Engine>postgres</Engine><EngineVersion>16.3</EngineVersion>` +
					`<StorageEncrypted>true</StorageEncrypted><PubliclyAccessible>false</PubliclyAccessible>` +
					`<MultiAZ>false</MultiAZ><DeletionProtection>` + delProtect + `</DeletionProtection>` +
					`<TagList><Tag><Key>groundhold-capability</Key><Value>db</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag></TagList>` +
					`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
			case "DeleteDBInstance":
				deleted = true
				_, _ = w.Write([]byte(`<DeleteDBInstanceResponse></DeleteDBInstanceResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func rdsTestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.RDSBaseURL = srv.URL
	// KMS trace defaults to the same fake (different protocol -> 404 -> CMK
	// unreadable -> diagnostic); CMK-measuring tests override KMSBaseURL. Keeps the
	// suite hermetic.
	d.KMSBaseURL = srv.URL
	d.Account = "000000000000"
	d.PollInterval = time.Millisecond
	return d
}

func TestCreateRDSPollsToAvailable(t *testing.T) {
	srv := rdsServer(t, "", "false")
	defer srv.Close()
	d := rdsTestDriver(t, srv)
	res := d.createRDS("eu-central-1", "000000000000", "prod", "db", rdsAttrs(), rdsImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "rds:eu-central-1:") {
		t.Fatalf("got %+v, want succeeded once available", res)
	}
}

func TestObserveRDS(t *testing.T) {
	srv := rdsServer(t, "", "false")
	defer srv.Close()
	d := rdsTestDriver(t, srv)
	obs, _, err := d.observeRDS("db", "rds:eu-central-1:db-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["engine.protocol"] != "postgresql/16.3" {
		t.Fatalf("engine.protocol = %v", got["engine.protocol"])
	}
	if got["network.publicExposure"] != false || got["encryption.atRest"] != true {
		t.Fatalf("exposure/encryption = %v / %v", got["network.publicExposure"], got["encryption.atRest"])
	}
}

func TestDeleteRDSProtectedRefused(t *testing.T) {
	srv := rdsServer(t, "", "true") // deletion protection on
	defer srv.Close()
	d := rdsTestDriver(t, srv)
	res := d.deleteRDS("db", "prod", "rds:eu-central-1:db-abcd1234")
	if res.Status != "failed" || !strings.Contains(res.Reason, "deletion protection") {
		t.Fatalf("protected instance must refuse delete, got %+v", res)
	}
}

func TestDeleteRDSOurs(t *testing.T) {
	srv := rdsServer(t, "", "false")
	defer srv.Close()
	d := rdsTestDriver(t, srv)
	res := d.deleteRDS("db", "prod", "rds:eu-central-1:db-abcd1234")
	if res.Status != "succeeded" {
		t.Fatalf("delete of an owned unprotected instance must succeed, got %+v", res)
	}
}

// TestDeleteRDSAsyncNotGoneIsUnknown pins D968: a delete the provider ACCEPTS but
// that leaves the instance in "deleting" (not gone) must report unknown — keep the
// handle for a reconcile — never a terminal "succeeded" that tombstones a resource
// still live and billing. Before the fix, the accepted delete returned succeeded.
func TestDeleteRDSAsyncNotGoneIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			r.Body.Read(body)
			action := ""
			for _, kv := range strings.Split(string(body), "&") {
				if strings.HasPrefix(kv, "Action=") {
					action = strings.TrimPrefix(kv, "Action=")
				}
			}
			switch action {
			case "DescribeDBInstances": // never gone — stays "deleting"
				_, _ = w.Write([]byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>` +
					`<DBInstanceIdentifier>db-x</DBInstanceIdentifier><DBInstanceStatus>deleting</DBInstanceStatus>` +
					`<Engine>postgres</Engine><EngineVersion>16.3</EngineVersion>` +
					`<StorageEncrypted>true</StorageEncrypted><PubliclyAccessible>false</PubliclyAccessible>` +
					`<MultiAZ>false</MultiAZ><DeletionProtection>false</DeletionProtection>` +
					`<TagList><Tag><Key>groundhold-capability</Key><Value>db</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag></TagList>` +
					`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
			case "DeleteDBInstance":
				_, _ = w.Write([]byte(`<DeleteDBInstanceResponse></DeleteDBInstanceResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := rdsTestDriver(t, srv)
	d.PollTimeout = 5 * time.Millisecond // the instance never leaves "deleting" → times out fast
	res := d.deleteRDS("db", "prod", "rds:eu-central-1:db-abcd1234")
	if res.Status != "unknown" {
		t.Fatalf("an accepted-but-not-terminal delete must be unknown (keep the handle, reconcile), "+
			"got %+v — reporting succeeded tombstones a resource still live and billing", res)
	}
}

func TestSplitRDSProviderID(t *testing.T) {
	if _, _, err := splitRDSProviderID("rds:eu-central-1:db-abcd1234"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	for _, bad := range []string{"eu:db", "s3:eu-central-1:db", "rds:eu-central-1:9bad", "rds:bad:db"} {
		if _, _, err := splitRDSProviderID(bad); err == nil {
			t.Errorf("accepted malformed rds id %q", bad)
		}
	}
}

// rdsFix configures a 409-adopt fixture: an instance that already exists and is ours,
// with the security controls set however the case needs (D1062).
type rdsFix struct {
	encrypted  bool
	kmsKeyId   string // "" = none (unencrypted or default)
	keyManager string // AWS | CUSTOMER (for the DescribeKey trace)
	publicAcc  bool
	paramGroup bool // attach a TLS parameter group (so observe reads inTransit)
	tlsForced  bool
}

func rdsAdoptSrv(f rdsFix) func() *httptest.Server {
	return func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tgt := r.Header.Get("X-Amz-Target"); strings.HasSuffix(tgt, "DescribeKey") {
				km := f.keyManager
				if km == "" {
					km = "AWS"
				}
				_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyManager":"` + km + `"}}`))
				return
			}
			body := make([]byte, r.ContentLength)
			r.Body.Read(body)
			action := ""
			for _, kv := range strings.Split(string(body), "&") {
				if strings.HasPrefix(kv, "Action=") {
					action = strings.TrimPrefix(kv, "Action=")
				}
			}
			switch action {
			case "CreateDBInstance":
				w.WriteHeader(400)
				_, _ = w.Write([]byte("<ErrorResponse><Error><Code>DBInstanceAlreadyExists</Code></Error></ErrorResponse>"))
			case "DescribeDBInstances":
				enc, pub := "false", "false"
				if f.encrypted {
					enc = "true"
				}
				if f.publicAcc {
					pub = "true"
				}
				kms, pg := "", ""
				if f.kmsKeyId != "" {
					kms = "<KmsKeyId>" + f.kmsKeyId + "</KmsKeyId>"
				}
				if f.paramGroup {
					pg = `<DBParameterGroups><DBParameterGroup><DBParameterGroupName>tls-grp</DBParameterGroupName></DBParameterGroup></DBParameterGroups>`
				}
				_, _ = w.Write([]byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>` +
					`<DBInstanceIdentifier>db-x</DBInstanceIdentifier><DBInstanceStatus>available</DBInstanceStatus>` +
					`<Engine>postgres</Engine><EngineVersion>16.3</EngineVersion>` +
					`<StorageEncrypted>` + enc + `</StorageEncrypted><PubliclyAccessible>` + pub + `</PubliclyAccessible>` +
					kms + `<MultiAZ>false</MultiAZ>` + pg +
					`<TagList><Tag><Key>groundhold-capability</Key><Value>db</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag></TagList>` +
					`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
			case "DescribeDBParameters":
				val := "0"
				if f.tlsForced {
					val = "1"
				}
				_, _ = w.Write([]byte(`<DescribeDBParametersResponse><DescribeDBParametersResult><Parameters>` +
					`<Parameter><ParameterName>rds.force_ssl</ParameterName><ParameterValue>` + val + `</ParameterValue></Parameter>` +
					`</Parameters></DescribeDBParametersResult></DescribeDBParametersResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
	}
}

// TestAdoptsExistingRDS enrols rds in the D391 gate. The instance identifier is
// deterministic and client-assigned, so a second create is answered
// DBInstanceAlreadyExists — the tags on the standing instance are what license binding
// it, and an instance at our name that is not ours is refused. rdsServer's stock fixture
// already carries our tags, so the whole existing estate is one createErr away.
func TestAdoptsExistingRDS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:           "aws/rds",
		Classify:       rdsQueryRole,
		ExistingServer: func() *httptest.Server { return rdsServer(t, "DBInstanceAlreadyExists", "false") },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.RDSBaseURL = happyURL
			d.KMSBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.PollInterval = time.Millisecond
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("rds", "db", "prod", rdsAttrs(), rdsImpl(), "db", 1)
		},
		AllowedMutations: 1, // the refused CreateDBInstance
		// D1062: encryption at rest, its customer key and TLS enforcement are immutable
		// at create; public exposure is a mutable ModifyDBInstance. Each must block an
		// adopt that lacks it; a more-secure instance still adopts.
		AdoptControls: rdsAdoptControls,
		MissingControl: []certifynet.ControlCase{
			{Path: "encryption.atRest", Server: rdsAdoptSrv(rdsFix{encrypted: false}),
				WantStatus: "failed", WantMutations: 1},
			{Path: "encryption.customerManagedKeys", WantStatus: "failed", WantMutations: 1,
				Server: rdsAdoptSrv(rdsFix{encrypted: true, kmsKeyId: "arn:aws:kms:eu-central-1:000000000000:key/abc", keyManager: "AWS"}),
				Create: func(pr provider.Provider) provider.CreateResult {
					a := rdsAttrs()
					a["encryption.customerManagedKeys"] = true
					im := rdsImpl()
					im["kms_key_id"] = "arn:aws:kms:eu-central-1:000000000000:key/abc"
					return pr.Create("rds", "db", "prod", a, im, "db", 1)
				}},
			{Path: "encryption.inTransit", WantStatus: "failed", WantMutations: 1,
				Server: rdsAdoptSrv(rdsFix{encrypted: true, paramGroup: true, tlsForced: false}),
				Create: func(pr provider.Provider) provider.CreateResult {
					a := rdsAttrs()
					a["encryption.inTransit"] = true
					im := rdsImpl()
					im["db_parameter_group"] = "tls-grp"
					return pr.Create("rds", "db", "prod", a, im, "db", 1)
				}},
			{Path: "network.publicExposure", Server: rdsAdoptSrv(rdsFix{encrypted: true, publicAcc: true}),
				WantStatus: "unknown", WantMutations: 1}, // mutable — converge patches it
		},
		MoreSecure: rdsAdoptSrv(rdsFix{encrypted: true, kmsKeyId: "arn:aws:kms:eu-central-1:000000000000:key/abc",
			keyManager: "CUSTOMER", paramGroup: true, tlsForced: true}),
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
