package parity

import "testing"

// a synthetic three-cloud map exercising fulfilled / gap / unbuilt without needing
// the live drivers.
func sampleCaps() map[string]map[string]string {
	return map[string]map[string]string{
		"aws": {
			"rds":         "capability.database.relational",
			"aurora":      "capability.database.relational",
			"ses-sending": "capability.email.sending",
		},
		"gcp":   {"cloudsql": "capability.database.relational"},
		"azure": {"acsemail": "capability.email.sending"},
	}
}

func TestCanFulfil(t *testing.T) {
	caps := sampleCaps()

	// fulfilled, many-to-one — both tokens, sorted.
	f := CanFulfil(caps, "aws", "capability.database.relational")
	if f.State != "fulfilled" || len(f.Tokens) != 2 || f.Tokens[0] != "aurora" || f.Tokens[1] != "rds" {
		t.Fatalf("aws database.relational = %+v, want fulfilled [aurora rds]", f)
	}
	// structural gap — from the authored table (email.sending on gcp).
	g := CanFulfil(caps, "gcp", "capability.email.sending")
	if g.State != "gap" || g.Class != "no-native-service" || g.Reason == "" {
		t.Fatalf("gcp email.sending = %+v, want gap no-native-service", g)
	}
	// unbuilt — no token, no declared gap (azure has no relational in the sample).
	u := CanFulfil(caps, "azure", "capability.database.relational")
	if u.State != "unbuilt" {
		t.Fatalf("azure database.relational = %+v, want unbuilt", u)
	}
}

func TestCheckBinding(t *testing.T) {
	caps := sampleCaps()

	// coherent binding — no error.
	if err := CheckBinding(caps, "db", "aws", "rds", "capability.database.relational"); err != nil {
		t.Fatalf("coherent binding refused: %v", err)
	}
	// confused-capability: rds bound to a cache type it does not fulfil.
	if err := CheckBinding(caps, "db", "aws", "rds", "capability.cache.keyvalue"); err == nil {
		t.Fatal("confused-capability (rds as cache) must refuse")
	}
	// structural gap: an email-sending candidate on gcp.
	err := CheckBinding(caps, "mail", "gcp", "some-relay", "capability.email.sending")
	if err == nil {
		t.Fatal("targeting a structural gap must refuse")
	}
	// exemptions: fake / empty fields / unknown provider are not gated.
	for _, tc := range []struct{ cloud, svc, typ string }{
		{"fake", "x", "capability.database.relational"},
		{"aws", "", "capability.database.relational"},
		{"aws", "rds", ""},
		{"hetzner", "server", "capability.compute.instance"},
	} {
		if err := CheckBinding(caps, "c", tc.cloud, tc.svc, tc.typ); err != nil {
			t.Errorf("CheckBinding(%s,%s,%s) should be a no-op, got %v", tc.cloud, tc.svc, tc.typ, err)
		}
	}
}
