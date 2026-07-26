package gcp

import (
	"encoding/json"
	"reflect"
	"testing"
)

// A realistic, NOISY instances.get response: output-only fields,
// defaults, implementation detail. The golden pins that ONLY semantic
// attributes come out, with honest derivations.
const noisyInstance = `{
  "kind": "sql#instance",
  "name": "orders-db-production-6bd985f0",
  "databaseVersion": "POSTGRES_16",
  "databaseInstalledVersion": "POSTGRES_16_4",
  "region": "europe-west1",
  "state": "RUNNABLE",
  "selfLink": "https://sqladmin.googleapis.com/v1/projects/x/instances/y",
  "etag": "deprecated-noise",
  "connectionName": "acme-prod:europe-west1:orders-db",
  "serviceAccountEmailAddress": "x@gcp-sa.iam.gserviceaccount.com",
  "currentDiskSize": "12345678",
  "ipAddresses": [
    {"type": "PRIVATE", "ipAddress": "10.1.2.3"}
  ],
  "settings": {
    "settingsVersion": "7",
    "tier": "db-custom-2-8192",
    "dataDiskType": "PD_SSD",
    "dataDiskSizeGb": "100",
    "storageAutoResize": true,
    "availabilityType": "REGIONAL",
    "activationPolicy": "ALWAYS",
    "ipConfiguration": {
      "ipv4Enabled": false,
      "privateNetwork": "projects/p/global/networks/vpc",
      "authorizedNetworks": [],
      "sslMode": "ENCRYPTED_ONLY"
    },
    "backupConfiguration": {
      "enabled": true,
      "pointInTimeRecoveryEnabled": true,
      "startTime": "03:00"
    },
    "userLabels": {"groundhold-capability": "orders-db"}
  }
}`

func TestMapInstanceGolden(t *testing.T) {
	var inst map[string]any
	if err := json.Unmarshal([]byte(noisyInstance), &inst); err != nil {
		t.Fatal(err)
	}
	got, diags := MapInstance(inst)
	want := []Observed{
		{"engine.protocol", "postgresql/16", "measured"}, // never invent 16.4
		{"location.region", "europe-west1", "measured"},
		{"availability.class", "regional", "measured"},
		{"network.publicExposure", false, "measured"}, // config AND evidence
		{"service.managed", true, "measured"},
		{"encryption.atRest", true, "config-intent"},
		{"encryption.inTransit", true, "measured"}, // noisyInstance enforces sslMode
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("golden mismatch:\n got: %+v\nwant: %+v", got, want)
	}
	// PITR is on: rpo must be a diagnostic, never a fabricated value
	if len(diags) != 1 {
		t.Errorf("expected exactly the PITR diagnostic, got %v", diags)
	}
}

// parse returns a FRESH map each time — json.Unmarshal into an existing
// map merges, which would contaminate sub-tests.
func parse(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMapInstanceHonesty(t *testing.T) {
	// public instance: exposure true from either surface
	inst := parse(t, `{
	  "databaseVersion": "MYSQL_8_0",
	  "region": "us-east1",
	  "ipAddresses": [{"type": "PRIMARY", "ipAddress": "34.1.2.3"}],
	  "settings": {"ipConfiguration": {"ipv4Enabled": true}}
	}`)
	got, _ := MapInstance(inst)
	byPath := map[string]Observed{}
	for _, o := range got {
		byPath[o.Path] = o
	}
	if byPath["network.publicExposure"].Value != true {
		t.Error("public instance must observe exposure=true")
	}
	if byPath["engine.protocol"].Value != "mysql/8.0" {
		t.Errorf("mysql mapping: %v", byPath["engine.protocol"].Value)
	}

	// absent config: emit NOTHING for exposure, never a zero-value false
	inst = parse(t, `{"databaseVersion": "POSTGRES_16",
	  "region": "x", "settings": {}}`)
	got, diags := MapInstance(inst)
	for _, o := range got {
		if o.Path == "network.publicExposure" {
			t.Error("absent ipConfiguration must not default to an observation")
		}
	}
	if len(diags) == 0 {
		t.Error("skipping exposure must leave a diagnostic")
	}

	// config says private but no ipAddresses evidence: no false claim
	inst = parse(t, `{"databaseVersion": "POSTGRES_16", "region": "x",
	  "settings": {"ipConfiguration": {"ipv4Enabled": false}}}`)
	got, _ = MapInstance(inst)
	for _, o := range got {
		if o.Path == "network.publicExposure" {
			t.Error("intent without evidence must not claim exposure=false")
		}
	}

	// daily backups without PITR: rpo 24h worst case, config-intent
	inst = parse(t, `{"databaseVersion": "POSTGRES_16", "region": "x",
	  "settings": {"backupConfiguration": {"enabled": true,
	  "pointInTimeRecoveryEnabled": false}}}`)
	got, _ = MapInstance(inst)
	found := false
	for _, o := range got {
		if o.Path == "recovery.rpo" {
			found = true
			if o.Value != "24h" || o.Derivation != "config-intent" {
				t.Errorf("rpo: %+v", o)
			}
		}
	}
	if !found {
		t.Error("daily backups must bound rpo at 24h")
	}

	// unknown enum: skip with diagnostic, never crash
	inst = parse(t, `{"databaseVersion": "SQLSERVER_2022_STANDARD",
	  "region": "x", "settings": {"availabilityType":
	  "SQL_AVAILABILITY_TYPE_UNSPECIFIED"}}`)
	got, diags = MapInstance(inst)
	for _, o := range got {
		if o.Path == "engine.protocol" || o.Path == "availability.class" {
			t.Errorf("unknown enums must be skipped, got %+v", o)
		}
	}
	if len(diags) < 2 {
		t.Errorf("expected diagnostics for both unknown enums, got %v", diags)
	}
}
