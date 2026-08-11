package backup

import (
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/ledger"
)

// D536, from the field, weight: high. Their backup of a live production ledger
// (7.5 MB, 1323 events) worked — restore reproduced a byte-identical plan, and a
// negative control (one string changed in one capsule) came back CORRUPTED with
// exit 5. What they then found is that events 66, 67 and 110, recorded before they
// migrated to secret REFERENCES, carry an Aurora connection string WITH THE
// PASSWORD, an OAuth secret and a private key. Current state is clean; the ledger
// is append-only, so the capsules carry the whole chain.
//
// Their sentence: "the more diligently you back up, the more places hold live
// credentials." A resilience tool working against security, invisibly — nobody
// reads a 3 MB capsule.
//
// They explicitly did NOT ask for redaction: it would break the hash chain their
// own negative control just proved works. Immutability is a feature. So this warns
// and COUNTS, and nothing else.
func TestBackupWarnsWhenCapsulesCarryCredentialShapedValues(t *testing.T) {
	dir := t.TempDir()
	led := filepath.Join(dir, "led.jsonl")
	writeLedgerWithSecret(t, led)

	rep, code := Run(Options{LedgerPath: led, Out: filepath.Join(dir, "out")})
	if code != 0 {
		t.Fatalf("backup refused: %v", rep.Reasons)
	}
	if rep.CredentialWarnings == 0 {
		t.Fatalf("a backup carrying a plaintext connection string reported no "+
			"credential warnings — the operator moves it off-host knowing nothing.\n"+
			"report: %+v", rep)
	}
	joined := strings.Join(rep.Reasons, "\n")
	if !strings.Contains(strings.ToLower(joined), "encrypt") {
		t.Errorf("the warning does not tell the operator what to DO: %q", joined)
	}
	// A warning that quotes the secret defeats itself.
	if strings.Contains(joined, "hunter2") {
		t.Errorf("the warning printed the credential VALUE: %q", joined)
	}
}

// The clean case must stay silent, or the warning becomes noise on every backup
// and stops being read (D364).
func TestBackupQuietWhenNothingLooksLikeACredential(t *testing.T) {
	dir := t.TempDir()
	led := filepath.Join(dir, "led.jsonl")
	writeLedgerClean(t, led)

	rep, code := Run(Options{LedgerPath: led, Out: filepath.Join(dir, "out")})
	if code != 0 {
		t.Fatalf("backup refused: %v", rep.Reasons)
	}
	if rep.CredentialWarnings != 0 {
		t.Errorf("a clean ledger produced %d credential warning(s): %v",
			rep.CredentialWarnings, rep.Reasons)
	}
}

func writeLedgerWithSecret(t *testing.T, path string) {
	t.Helper()
	buildCredLedger(t, path, map[string]any{
		"DATABASE_URL": "postgres://app:hunter2@db.internal:5432/orders",
	})
}

func writeLedgerClean(t *testing.T, path string) {
	t.Helper()
	buildCredLedger(t, path, map[string]any{
		"DATABASE_URL": "secretsmanager:acme/database-url",
	})
}

// buildLedger records a bound capability whose apply receipt carries the given
// environment — the shape the field ledger had before secrets became references.
func buildCredLedger(t *testing.T, path string, env map[string]any) {
	t.Helper()
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := &ledger.Writer{Path: path, Led: led, Env: "test", Actor: "t"}
	w.Clock = 1000
	tok, err := w.AppendLease([]string{"api"}, map[string]any{"ttlSeconds": 100000})
	if err != nil {
		t.Fatal(err)
	}
	w.Clock = 1001
	body := map[string]any{
		"resources": []any{map[string]any{
			"id": "primary", "type": "fake.thing", "providerId": "fake:api-1", "generation": 1}},
		"implementation": map[string]any{"environment": env},
	}
	if err := w.Append("binding.updated", []string{"api"}, body, tok); err != nil {
		t.Fatal(err)
	}
	w.Clock = 1002
	if err := w.Append("lease.released", []string{"api"}, nil, tok); err != nil {
		t.Fatal(err)
	}
}
