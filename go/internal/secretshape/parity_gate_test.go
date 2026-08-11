package secretshape_test

import (
	"strings"
	"testing"

	"groundhold/internal/canonical"
	"groundhold/internal/collector"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/provider"
	"groundhold/internal/secretshape"
)

// The credential shapes, one table, exercised against every consumer. Before D648
// each consumer had its own list and no two agreed: a capsule carrying
// `postgres://app:hunter2@…` was CERTIFIED while the same capsule carrying a bearer
// token was refused, and `backup` reported `"credentialWarnings": 0` over the DSN.
var credentials = []struct{ name, value string }{
	{"dsn", "postgres://app:Sup3rSecretDbPassw0rd@db.internal:5432/orders"},
	{"dsn inside a sentence", `create failed (HTTP 400 Invalid value for ` +
		`DATABASE_URL=postgres://app:Sup3rSecretDbPassw0rd@db.internal:5432/orders)`},
	{"uppercase scheme", "POSTGRES://app:Sup3rSecretDbPassw0rd@db.internal:5432/x"},
	{"bearer", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefg"},
	{"jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payloadpayload.sig"},
	{"aws key id", "AKIAIOSFODNN7EXAMPLE"},
	{"pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----"},
	{"sendgrid", "SG.abcdefghijklmnopq.rstuvwxyz0123456789"},
	{"slack", "xoxb-1234567890-abcdefghij"},
}

// D648. One alphabet, three consumers, checked against each other rather than
// declared. The publish-time scan warns, the capsule certifier refuses, and the
// redactor removes the value from a diagnostic that would otherwise be persisted
// and published.
func TestEveryCredentialDetectorSeesTheSameAlphabet(t *testing.T) {
	if len(secretshape.ValueShapes()) < 8 {
		t.Fatalf("the value alphabet collapsed to %d shapes — this gate would be "+
			"measuring nothing (D328)", len(secretshape.ValueShapes()))
	}
	for _, c := range credentials {
		t.Run(c.name, func(t *testing.T) {
			if kind, ok := secretshape.ValueLooksLikeCredential(c.value); !ok {
				t.Fatalf("the shared alphabet does not know this shape")
			} else if kind == "" {
				t.Error("the shape has no name, so no finding can say what it saw")
			}

			// 1. publish-time scan: says it out loud.
			if fs := contract.ScanValue("/implementation/x", c.value); len(fs) == 0 {
				t.Error("the publish-time scan is silent — the operator is never " +
					"told the ledger just inherited this value's sensitivity (D364)")
			}

			// 2. capsule certification: refuses.
			evDoc := map[string]any{"apiVersion": "state/v0", "kind": "LedgerEvent",
				"event": map[string]any{"type": "operation.receipt",
					"occurredAt":   "2026-01-01T00:00:00Z",
					"capabilities": []any{"db"},
					"actor":        map[string]any{"id": "t", "type": "runtime"},
					"prev":         map[string]any{"db": "genesis"},
					"body": map[string]any{"operationId": "op-1",
						"status": "failed", "reason": c.value}}}
			head, herr := canonical.HashEvent(evDoc)
			if herr != nil {
				t.Fatal(herr)
			}
			caps := &ledger.Capsule{
				APIVersion: "capsule/v0.1", Kind: "EvidenceCapsule",
				EventHashAlg: "sha256", Canonicalization: "groundhold/canon/v1",
				Capability: "db", AsOf: "2026-01-01T00:00:00Z", Head: head,
				Events: []map[string]any{evDoc}}
			rep := collector.Certify(caps)
			var refused bool
			for _, f := range rep.Findings {
				if f.Kind == "secret" {
					refused = true
				}
			}
			if !refused {
				t.Errorf("certify-capsule accepts a capsule carrying this value — "+
					"D53 says secrets are structurally excluded from imported "+
					"evidence: %+v", rep.Findings)
			}

			// 3. the redactor: removes it from a reason that becomes a ledger event.
			var r provider.Redactor
			r.Remember(map[string]any{"environment": map[string]any{
				"DATABASE_URL": c.value}})
			got := r.Scrub("create failed: " + c.value)
			if strings.Contains(got, c.value) {
				t.Errorf("the redactor echoed the credential into a persisted "+
					"reason: %q — `environment` is not a secret-NAMED key, and the "+
					"value's shape is the only thing that can save it", got)
			}
		})
	}
}

// The control, without which the case above is satisfied by calling everything a
// secret: ordinary configuration must stay readable, or the operator loses the
// diagnostics that tell them what was refused.
func TestOrdinaryConfigurationIsNotTreatedAsACredential(t *testing.T) {
	for _, v := range []string{
		"eu-central-1", "db.t3.micro", "https://example.internal/health",
		"arn:aws:kms:eu-central-1:000000000000:key/abcd-ef01",
		"projects/p/locations/eu/keyRings/r/cryptoKeys/k",
		"postgres://db.internal:5432/orders", // no inline credential
		"true", "14", "gp3",
	} {
		if kind, ok := secretshape.ValueLooksLikeCredential(v); ok {
			t.Errorf("%q was called %s — a detector that fires on ordinary "+
				"configuration trains people to ignore it", v, kind)
		}
	}
	// And key-RESOURCE names must stay readable: redacting them blinds the
	// operator to WHICH key was refused while protecting nothing.
	for _, k := range []string{"kms_key", "key_vault_key", "key_id", "region"} {
		if secretshape.KeyLooksLikeCredential(k) {
			t.Errorf("key %q is treated as credential material — it names a "+
				"resource, not a secret", k)
		}
	}
}

// The key alphabet, which was the narrowest of the four. Every name here was
// measured passing the redactor while another detector in the same repository
// would have caught it.
func TestTheKeyAlphabetCoversWhatItsSiblingsKnew(t *testing.T) {
	for _, k := range []string{
		"admin_pwd", "db_pass", "auth", "access_key_id", "client_secret",
		"session_token", "masterPassword", "MasterUserPassword", "api-key",
	} {
		if !secretshape.KeyLooksLikeCredential(k) {
			t.Errorf("key %q is not treated as a credential name", k)
		}
		var r provider.Redactor
		r.Remember(map[string]any{k: "Sup3rSecretValue123"})
		if got := r.Scrub("failed with " + k + "=Sup3rSecretValue123"); strings.Contains(
			got, "Sup3rSecretValue123") {
			t.Errorf("the redactor kept the value under %q: %q", k, got)
		}
	}
}
