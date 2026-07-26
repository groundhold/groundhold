package caplens

import "testing"

func TestAvailabilityClass(t *testing.T) {
	if got := AvailabilityClass(true); got != "regional" {
		t.Fatalf("regional HA = %q, want regional", got)
	}
	if got := AvailabilityClass(false); got != "zonal" {
		t.Fatalf("single-zone = %q, want zonal", got)
	}
}

// TestEngineProtocolReproducesDrivers pins the exact strings the three hand-coded
// paths produced, so the extraction is byte-identical (the golden/differential
// suites prove the rest end to end).
func TestEngineProtocolReproducesDrivers(t *testing.T) {
	cases := []struct {
		engine, version, want string
	}{
		{"postgres", "14.5", "postgresql/14.5"}, // AWS canonicalizes postgres
		{"mysql", "8.0", "mysql/8.0"},           // AWS passes other engines through
		{"postgres", "", "postgresql"},          // AWS: no version -> bare protocol
		{"mysql", "", "mysql"},
		{EnginePostgres, "16", "postgresql/16"}, // Azure/GCP hand the canonical name in
		{EngineMySQL, "8.0", "mysql/8.0"},
	}
	for _, c := range cases {
		if got := EngineProtocol(c.engine, c.version); got != c.want {
			t.Errorf("EngineProtocol(%q,%q) = %q, want %q", c.engine, c.version, got, c.want)
		}
	}
}

func TestCanonicalEngineOnlyAliasesPostgres(t *testing.T) {
	if CanonicalEngine("postgres") != "postgresql" {
		t.Fatal("postgres must canonicalize to postgresql")
	}
	if CanonicalEngine("mysql") != "mysql" {
		t.Fatal("mysql must pass through unchanged")
	}
	if CanonicalEngine("mariadb") != "mariadb" {
		t.Fatal("an unknown engine must pass through, never be dropped")
	}
}
