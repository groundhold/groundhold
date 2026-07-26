package importer

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func parse(t *testing.T, s string) map[string]any {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

const tfstate = `{
  "version": 4, "terraform_version": "1.5.7", "serial": 42,
  "lineage": "0b7bd93d-conf",
  "resources": [
    {"mode": "managed", "type": "google_sql_database_instance",
     "name": "legacy",
     "instances": [{"schema_version": 0, "attributes": {
       "name": "legacy-db", "project": "acme-prod",
       "region": "europe-central2", "database_version": "MYSQL_8_0",
       "deletion_protection": false,
       "settings": [{"tier": "db-f1-micro", "availability_type": "ZONAL",
         "ip_configuration": [{"ipv4_enabled": false}],
         "backup_configuration": [{"enabled": true,
           "point_in_time_recovery_enabled": false}]}]}}]},
    {"mode": "managed", "type": "google_sql_user", "name": "app",
     "instances": [{"attributes": {"name": "app",
       "password": "SUPER-SECRET"}}]},
    {"mode": "data", "type": "google_project", "name": "current",
     "instances": []},
    {"mode": "managed", "type": "google_compute_network", "name": "vpc",
     "instances": []}
  ]
}`

func TestTFStateGolden(t *testing.T) {
	res, err := Map(parse(t, tfstate), "auto")
	if err != nil {
		t.Fatal(err)
	}
	if res.Source.Format != "tfstate" || res.Source.Lineage != "0b7bd93d-conf" {
		t.Errorf("source: %+v", res.Source)
	}
	if len(res.Hints) != 1 {
		t.Fatalf("expected 1 hint, got %d", len(res.Hints))
	}
	h := res.Hints[0]
	if h.ProviderID != "acme-prod:europe-central2:legacy-db" {
		t.Errorf("providerId: %s", h.ProviderID)
	}
	wantExpected := map[string]any{
		"engine.protocol":        "mysql/8.0",
		"location.region":        "europe-central2",
		"availability.class":     "zonal",
		"network.publicExposure": false,
		"recovery.rpo":           "24h",
		"service.managed":        true,
	}
	if !reflect.DeepEqual(h.Expected, wantExpected) {
		t.Errorf("expected attrs:\n got %v\nwant %v", h.Expected, wantExpected)
	}
	if len(h.Notes) != 1 || !strings.Contains(h.Notes[0], "deletion_protection is OFF") {
		t.Errorf("notes: %v", h.Notes)
	}
	// tier is implementation noise — must NOT appear as a hint
	if _, ok := h.Expected["tier"]; ok {
		t.Error("tier leaked into expected attributes")
	}
	joined := strings.Join(res.Diagnostics, "\n")
	for _, want := range []string{
		"google_sql_user.app: composite child",
		"data.google_project.current: data source, skipped",
		"google_compute_network.vpc: no vocabulary mapping",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("diagnostics missing %q in %v", want, res.Diagnostics)
		}
	}
}

// Secrets are structurally excluded: the WHOLE result must not carry
// state values outside the explicit mapping.
func TestNoSecretEverCrosses(t *testing.T) {
	res, err := Map(parse(t, tfstate), "tfstate")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), "SUPER-SECRET") {
		t.Fatal("a secret from state crossed into the hints document")
	}
}

const pulumiState = `{
  "version": 3,
  "deployment": {
    "resources": [
      {"urn": "urn:pulumi:prod::app::pulumi:pulumi:Stack::app-prod",
       "type": "pulumi:pulumi:Stack"},
      {"urn": "urn:pulumi:prod::app::gcp:sql/databaseInstance:DatabaseInstance::legacy",
       "type": "gcp:sql/databaseInstance:DatabaseInstance",
       "inputs": {"settings": {"tier": "db-f1-micro"}},
       "outputs": {
         "name": "legacy-db", "project": "acme-prod",
         "region": "europe-central2", "databaseVersion": "POSTGRES_16",
         "deletionProtection": true,
         "settings": {"availabilityType": "REGIONAL",
           "ipConfiguration": {"ipv4Enabled": true},
           "backupConfiguration": {"enabled": true,
             "pointInTimeRecoveryEnabled": true}}}},
      {"urn": "urn:pulumi:prod::app::gcp:sql/user:User::app",
       "type": "gcp:sql/user:User",
       "outputs": {"password": "PULUMI-SECRET"}}
    ]
  }
}`

func TestPulumiGolden(t *testing.T) {
	res, err := Map(parse(t, pulumiState), "auto")
	if err != nil {
		t.Fatal(err)
	}
	if res.Source.Format != "pulumi" {
		t.Errorf("format: %s", res.Source.Format)
	}
	if len(res.Hints) != 1 {
		t.Fatalf("expected 1 hint, got %d", len(res.Hints))
	}
	h := res.Hints[0]
	if h.ProviderID != "acme-prod:europe-central2:legacy-db" {
		t.Errorf("providerId: %s", h.ProviderID)
	}
	wantExpected := map[string]any{
		"engine.protocol":        "postgresql/16",
		"location.region":        "europe-central2",
		"availability.class":     "regional",
		"network.publicExposure": true,
		"service.managed":        true,
	}
	if !reflect.DeepEqual(h.Expected, wantExpected) {
		t.Errorf("expected attrs:\n got %v\nwant %v", h.Expected, wantExpected)
	}
	// PITR: rpo needs a probe — a diagnostic, never a fabricated hint
	if _, ok := h.Expected["recovery.rpo"]; ok {
		t.Error("recovery.rpo fabricated despite PITR")
	}
	if !strings.Contains(strings.Join(res.Diagnostics, "\n"), "PITR enabled") {
		t.Errorf("missing PITR diagnostic: %v", res.Diagnostics)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), "PULUMI-SECRET") {
		t.Fatal("a secret from pulumi state crossed into hints")
	}
}

func TestDetectUnknownFormatRefuses(t *testing.T) {
	if _, err := Map(parse(t, `{"foo": 1}`), "auto"); err == nil {
		t.Fatal("unknown format must error, never guess")
	}
}

// Review blocker 1: identity disagreement refuses the hint — a
// mis-seeded adoption is worse than no suggestion.
func TestIdentityDisagreementRefusesHint(t *testing.T) {
	state := `{"version": 4, "serial": 1, "lineage": "x", "resources": [
	  {"mode": "managed", "type": "google_sql_database_instance",
	   "name": "legacy", "instances": [{"attributes": {
	     "name": "legacy-db", "project": "acme-prod",
	     "region": "europe-central2",
	     "connection_name": "other-project:europe-central2:legacy-db",
	     "database_version": "MYSQL_8_0"}}]}]}`
	res, err := Map(parse(t, state), "tfstate")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hints) != 0 {
		t.Fatalf("disagreeing identity must refuse the hint, got %+v",
			res.Hints)
	}
	joined := strings.Join(res.Diagnostics, "\n")
	if !strings.Contains(joined, "identity disagreement") {
		t.Errorf("missing disagreement diagnostic: %v", res.Diagnostics)
	}
}

func TestSelfLinkDisagreementRefusesHint(t *testing.T) {
	state := `{"version": 4, "serial": 1, "lineage": "x", "resources": [
	  {"mode": "managed", "type": "google_sql_database_instance",
	   "name": "legacy", "instances": [{"attributes": {
	     "name": "legacy-db", "project": "acme-prod",
	     "region": "europe-central2",
	     "self_link": "https://sqladmin.googleapis.com/sql/v1beta4/projects/acme-prod/instances/OTHER-db",
	     "database_version": "MYSQL_8_0"}}]}]}`
	res, err := Map(parse(t, state), "tfstate")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hints) != 0 {
		t.Fatal("disagreeing self_link must refuse the hint")
	}
}

// Agreeing cross-check fields keep the hint — the check is a
// consistency gate, not a new requirement.
func TestAgreeingIdentityKeepsHint(t *testing.T) {
	state := `{"version": 4, "serial": 1, "lineage": "x", "resources": [
	  {"mode": "managed", "type": "google_sql_database_instance",
	   "name": "legacy", "instances": [{"attributes": {
	     "name": "legacy-db", "project": "acme-prod",
	     "region": "europe-central2",
	     "connection_name": "acme-prod:europe-central2:legacy-db",
	     "self_link": "https://sqladmin.googleapis.com/sql/v1beta4/projects/acme-prod/instances/legacy-db",
	     "database_version": "MYSQL_8_0"}}]}]}`
	res, err := Map(parse(t, state), "tfstate")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hints) != 1 ||
		res.Hints[0].ProviderID != "acme-prod:europe-central2:legacy-db" {
		t.Fatalf("agreeing identity must keep the hint: %+v", res.Hints)
	}
}

// Review blocker 2: adversarial secret-looking fields ON THE MAPPED
// RESOURCE ITSELF — the allowlist must hold as it expands, so this
// fixture is the regression tripwire.
func TestAdversarialSecretsNeverCross(t *testing.T) {
	state := `{"version": 4, "serial": 1, "lineage": "x", "resources": [
	  {"mode": "managed", "type": "google_sql_database_instance",
	   "name": "legacy", "instances": [{"attributes": {
	     "name": "legacy-db", "project": "acme-prod",
	     "region": "europe-central2", "database_version": "MYSQL_8_0",
	     "root_password": "ROOT-SECRET-1",
	     "private_ip_address": "10.9.8.7",
	     "server_ca_cert": [{"cert": "PEM-SECRET-2"}],
	     "settings": [{"tier": "db-f1-micro",
	       "password_validation_policy": [{"password": "POLICY-SECRET-3"}],
	       "ip_configuration": [{"ipv4_enabled": false,
	         "psc_config": [{"psc_auto_connections":
	           [{"consumer_service_attachment": "ATTACH-SECRET-4"}]}]}]}]}}],
	   "sensitive_attributes": [{"path": "root_password"}]}]}`
	res, err := Map(parse(t, state), "tfstate")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res)
	for _, secret := range []string{"ROOT-SECRET-1", "PEM-SECRET-2",
		"POLICY-SECRET-3", "ATTACH-SECRET-4", "10.9.8.7", "db-f1-micro"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("%q crossed into the hints document", secret)
		}
	}
	if len(res.Hints) != 1 {
		t.Fatalf("the legitimate hint must survive: %+v", res.Hints)
	}
}
