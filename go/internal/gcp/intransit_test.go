package gcp

import "testing"

// encryption.inTransit (Slice C): Cloud SQL enforces TLS via
// settings.ipConfiguration.sslMode = ENCRYPTED_ONLY, a field on the SAME
// insert. Cloud SQL honors it cleanly (RDS refuses — see the aws package).

func TestBuildCloudSQLInTransit(t *testing.T) {
	a := map[string]any{
		"engine.protocol":      "postgresql/16",
		"location.region":      "europe-west1",
		"encryption.inTransit": true,
	}
	req, err := BuildCreateRequest("p", "e", "db", a, map[string]any{"tier": "t"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := req.Body["settings"].(map[string]any)
	ip, ok := s["ipConfiguration"].(map[string]any)
	if !ok {
		t.Fatalf("no ipConfiguration: %+v", s)
	}
	if ip["sslMode"] != "ENCRYPTED_ONLY" {
		t.Fatalf("sslMode = %v, want ENCRYPTED_ONLY", ip["sslMode"])
	}
}

func TestBuildCloudSQLInTransitFalseIsNoop(t *testing.T) {
	a := map[string]any{
		"engine.protocol":      "postgresql/16",
		"location.region":      "europe-west1",
		"encryption.inTransit": false,
	}
	req, err := BuildCreateRequest("p", "e", "db", a, map[string]any{"tier": "t"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := req.Body["settings"].(map[string]any)
	if ip, ok := s["ipConfiguration"].(map[string]any); ok {
		if _, has := ip["sslMode"]; has {
			t.Fatal("inTransit=false must not enforce sslMode (provider default)")
		}
	}
}

func TestObserveCloudSQLInTransit(t *testing.T) {
	for mode, want := range map[string]bool{
		"ENCRYPTED_ONLY":                      true,
		"TRUSTED_CLIENT_CERTIFICATE_REQUIRED": true,
		"ALLOW_UNENCRYPTED_AND_ENCRYPTED":     false,
	} {
		inst := map[string]any{
			"databaseVersion": "POSTGRES_16",
			"region":          "europe-west1",
			"settings":        map[string]any{"ipConfiguration": map[string]any{"sslMode": mode}},
		}
		out, _ := MapInstance(inst)
		got, has := false, false
		for _, o := range out {
			if o.Path == "encryption.inTransit" {
				has = true
				got, _ = o.Value.(bool)
			}
		}
		if !has {
			t.Fatalf("sslMode %q must observe encryption.inTransit", mode)
		}
		if got != want {
			t.Fatalf("sslMode %q -> inTransit %v, want %v", mode, got, want)
		}
	}
}

// D1041: an absent sslMode is the deterministic Cloud SQL default
// (ALLOW_UNENCRYPTED_AND_ENCRYPTED = TLS not enforced), a MEASURED inTransit=false, not
// an omitted observation — a plaintext-accepting database must not read as TLS-enforced
// (was TestObserveCloudSQLInTransitAbsentEmitsNothing, which asserted the omit bug).
func TestObserveCloudSQLInTransitDefaultIsMeasuredFalse(t *testing.T) {
	inst := map[string]any{
		"databaseVersion": "POSTGRES_16",
		"region":          "europe-west1",
		"settings":        map[string]any{"ipConfiguration": map[string]any{"ipv4Enabled": true}},
	}
	out, _ := MapInstance(inst)
	found := false
	for _, o := range out {
		if o.Path == "encryption.inTransit" {
			found = true
			if o.Value != false {
				t.Fatalf("an absent sslMode must observe inTransit=false, got %v", o.Value)
			}
		}
	}
	if !found {
		t.Fatal("inTransit must be emitted (measured false), not omitted")
	}
}
