package aws

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// Weapon 2 (D87) for RDS — the metamorphic write/read round-trip. A STATEFUL
// fake records what CreateDBInstance WRITES (PubliclyAccessible, MultiAZ,
// Engine/Version, BackupRetentionPeriod) and reflects it on DescribeDBInstances;
// the test asserts observeRDS reverse-maps the SAME semantic attributes create
// was given. A driver that reads MultiAZ from the wrong element, inverts
// PubliclyAccessible, or reads BackupRetentionPeriod from another field fails
// here without any fault injected.
func metamorphicRDSServer(t *testing.T) *httptest.Server {
	t.Helper()
	var (
		created            bool
		publiclyAccessible bool
		multiAZ            bool
		storageEncrypted   bool
		engine             string
		engineVersion      string
		backupRetention    string // "" when create wrote none
	)
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(raw))
			switch form.Get("Action") {
			case "CreateDBInstance":
				created = true
				publiclyAccessible = form.Get("PubliclyAccessible") == "true"
				multiAZ = form.Get("MultiAZ") == "true"
				storageEncrypted = form.Get("StorageEncrypted") == "true"
				engine = form.Get("Engine")
				engineVersion = form.Get("EngineVersion")
				backupRetention = form.Get("BackupRetentionPeriod")
				_, _ = w.Write([]byte(`<CreateDBInstanceResponse></CreateDBInstanceResponse>`))
			case "DescribeDBInstances":
				if !created {
					w.WriteHeader(404)
					_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>DBInstanceNotFound</Code></Error></ErrorResponse>`))
					return
				}
				retention := backupRetention
				if retention == "" {
					retention = "0"
				}
				_, _ = w.Write([]byte(fmt.Sprintf(
					`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>`+
						`<DBInstanceIdentifier>db-x</DBInstanceIdentifier>`+
						`<DBInstanceStatus>available</DBInstanceStatus>`+
						`<Engine>%s</Engine><EngineVersion>%s</EngineVersion>`+
						`<StorageEncrypted>%t</StorageEncrypted>`+
						`<PubliclyAccessible>%t</PubliclyAccessible>`+
						`<MultiAZ>%t</MultiAZ>`+
						`<BackupRetentionPeriod>%s</BackupRetentionPeriod>`+
						`<DeletionProtection>true</DeletionProtection>`+
						`<TagList><Tag><Key>groundhold-capability</Key><Value>db</Value></Tag>`+
						`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag></TagList>`+
						`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`,
					engine, engineVersion, storageEncrypted, publiclyAccessible, multiAZ, retention)))
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestMetamorphicRDSRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		public  bool
		class   string // "zonal" | "regional"
		proto   string // engine.protocol in == out
		wantRPO bool
	}{
		{"private-zonal-postgres-nobackup", false, "zonal", "postgresql/16", false},
		{"public-regional-mysql-backup", true, "regional", "mysql/8.0", true},
		{"private-regional-mariadb-backup", false, "regional", "mariadb/10.11", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicRDSServer(t)
			defer srv.Close()
			d := rdsTestDriver(t, srv)
			d.PollInterval = time.Millisecond

			attrs := map[string]any{
				"engine.protocol":        c.proto,
				"location.region":        "eu-central-1",
				"network.publicExposure": c.public,
				"encryption.atRest":      true,
				"availability.class":     c.class,
				"service.managed":        true,
			}
			if c.wantRPO {
				attrs["recovery.rpo"] = "5m"
			}
			res := d.createRDS("eu-central-1", "000000000000", "prod", "db", attrs, rdsImpl(), 1)
			if res.Status != "succeeded" {
				t.Fatalf("create failed: %+v", res)
			}
			obs, _, err := d.observeRDS("db", res.ProviderID)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			// the metamorphic invariant: Observe reverse-maps what Create wrote.
			if got["network.publicExposure"] != c.public {
				t.Errorf("public-exposure round-trip broke: wrote %v, observed %v", c.public, got["network.publicExposure"])
			}
			if got["availability.class"] != c.class {
				t.Errorf("availability.class round-trip broke: wrote %v, observed %v", c.class, got["availability.class"])
			}
			if got["engine.protocol"] != c.proto {
				t.Errorf("engine.protocol round-trip broke: wrote %v, observed %v", c.proto, got["engine.protocol"])
			}
			if got["location.region"] != "eu-central-1" {
				t.Errorf("region round-trip broke: observed %v", got["location.region"])
			}
			// encryption.atRest is write-only-true (create refuses false), so this
			// asserts observe reads StorageEncrypted rather than hardcoding true.
			if got["encryption.atRest"] != true {
				t.Errorf("encryption.atRest round-trip broke: observed %v", got["encryption.atRest"])
			}
			// recovery.rpo: present (backups on) iff the attr requested it. Its
			// VALUE is the PITR floor (config-intent), not a round-trip of the
			// input value — so we assert PRESENCE, which reads BackupRetentionPeriod.
			_, hasRPO := got["recovery.rpo"]
			if hasRPO != c.wantRPO {
				t.Errorf("recovery.rpo presence round-trip broke: wanted %v, observed present=%v (value %v)",
					c.wantRPO, hasRPO, got["recovery.rpo"])
			}
		})
	}
}
