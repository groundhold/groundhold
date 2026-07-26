package aws

import "testing"

// encryption.inTransit (Slice C): RDS REFUSES. Enforcing TLS needs a DB
// parameter group (rds.force_ssl=1), a separate binding the thesis forbids —
// an honest refusal (Cloud SQL honors it via sslMode), never a half-apply.

func TestBuildRDSInTransitRefused(t *testing.T) {
	a := rdsAttrs()
	a["encryption.inTransit"] = true
	if _, _, err := BuildRDSCreate("000000000000", "prod", "db", a, rdsImpl(), 1); err == nil {
		t.Fatal("encryption.inTransit=true must be refused on RDS (needs a parameter group)")
	}
}

func TestBuildRDSInTransitFalseIsNoop(t *testing.T) {
	a := rdsAttrs()
	a["encryption.inTransit"] = false
	if _, _, err := BuildRDSCreate("000000000000", "prod", "db", a, rdsImpl(), 1); err != nil {
		t.Fatalf("encryption.inTransit=false must be accepted (no TLS enforcement requested): %v", err)
	}
}
