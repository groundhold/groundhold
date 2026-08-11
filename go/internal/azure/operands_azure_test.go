package azure

import (
	"reflect"
	"sort"
	"testing"
)

// TestConsumedOperandsSpotChecks pins the EXACT declared operand set for a
// representative spread of services — the D307 SILENT-IGNORE GUARD: an operand a
// candidate declares that the driver does not read here is refused at compile
// time. A wrong or drifted entry here would silently widen (or narrow) what a
// candidate is allowed to pass through `implementation:`.
func TestConsumedOperandsSpotChecks(t *testing.T) {
	d := &Driver{}
	cases := map[string][]string{
		// no operands at all: the create path reads nothing beyond attrs.
		"changefeed":     {},
		"roleassignment": {"principal_type"},
		"customroledef":  {},
		// the naming trap called out in the source comment: dnsrecord reads
		// camelCase "resourceGroup" while every other service reads snake_case.
		"dnsrecord": {"record_name", "resourceGroup", "zone"},
		"dnszone":   {"resource_group"},
		// a multi-operand composite (blob's substrate + CMK + replication operands).
		"blob": {"key_vault_key_uri", "replication_destination_account_id",
			"replication_destination_container", "resource_group", "user_assigned_identity"},
		// a map-valued operand declared as ONE top-level key (nodePool), per the
		// file's own documented convention for structural (not by-name) reads.
		"aks": {"authorizedIPRanges", "clusterName", "dnsPrefix", "identity", "kmsKeyId",
			"nodePool", "resource_group", "userAssignedIdentityId"},
		"aks-workloadidentity": {"oidcIssuer", "resource_group", "uamiName", "uamiResourceId"},
		"managedidentity":      {"location", "resource_group"},
		"flexpostgres": {"admin_password", "admin_username", "key_vault_key_uri",
			"resource_group", "sku", "user_assigned_identity"},
	}
	for service, want := range cases {
		got := d.ConsumedOperands(service)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ConsumedOperands(%q) = %v, want %v", service, got, want)
		}
	}
}

// TestConsumedOperandsUnknownServiceIsEmpty: an unrecognized/unwired service token
// declares NO consumed operands — any operand a candidate supplied for it would
// then be refused by the compiler, never silently accepted (fail-closed, D307).
func TestConsumedOperandsUnknownServiceIsEmpty(t *testing.T) {
	d := &Driver{}
	if got := d.ConsumedOperands("__not_a_service__"); len(got) != 0 {
		t.Fatalf("unknown service must declare no operands, got %v", got)
	}
	if got := d.ConsumedOperands(""); len(got) != 0 {
		t.Fatalf("empty service must declare no operands, got %v", got)
	}
}

// TestConsumedOperandsCoversEveryWiredService is the completeness twin of
// TestObserveCompleteness/TestClassifyChangeCompleteness (completeness_test.go):
// EVERY service the driver dispatches (azureServices) must have an entry in
// azureConsumedOperands — even an explicit empty set. A new wired service that
// forgets to declare its operand set would otherwise silently accept (and never
// gate) ANY implementation operand a candidate supplies for it, undermining the
// whole SILENT-IGNORE GUARD. The reverse direction (a stale operand entry for a
// service no longer wired) is checked too.
func TestConsumedOperandsCoversEveryWiredService(t *testing.T) {
	var missing []string
	for svc := range azureServices {
		if _, ok := azureConsumedOperands[svc]; !ok {
			missing = append(missing, svc)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("wired azure services with NO azureConsumedOperands entry (the SILENT-IGNORE "+
			"GUARD would never gate their implementation operands): %v", missing)
	}

	var stale []string
	for svc := range azureConsumedOperands {
		if !azureServices[svc] {
			stale = append(stale, svc)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("azureConsumedOperands has entries for services that are not wired: %v", stale)
	}
}

// TestConsumedOperandsKeysAreSorted: the map's own doc comment presents each
// service's operand list as an enumerated, deterministic set. Keeping every list
// sorted makes a future diff/review of a change legible (and a duplicate key
// impossible to miss) — this is a lightweight hygiene pin, not a semantic one.
func TestConsumedOperandsKeysAreSorted(t *testing.T) {
	for svc, ops := range azureConsumedOperands {
		if !sort.StringsAreSorted(ops) {
			t.Errorf("azureConsumedOperands[%q] = %v is not sorted", svc, ops)
		}
		seen := map[string]bool{}
		for _, o := range ops {
			if seen[o] {
				t.Errorf("azureConsumedOperands[%q] has a duplicate operand %q", svc, o)
			}
			seen[o] = true
		}
	}
}

// TestConsumedOperandsIsProviderOperandConsumer pins the interface satisfaction
// the production code already asserts at package scope (var _ provider.OperandConsumer
// = (*Driver)(nil)) — exercised here through an actual interface-typed call so the
// method is covered, not merely declared.
func TestConsumedOperandsIsProviderOperandConsumer(t *testing.T) {
	var oc = &Driver{}
	got := oc.ConsumedOperands("vnet")
	want := []string{"resource_group", "service_endpoints"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ConsumedOperands(\"vnet\") = %v, want %v", got, want)
	}
}
