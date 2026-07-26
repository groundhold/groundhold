package restore

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/ledger"
)

// D312 (adversarial audit of restore, finding 2): the --partial failure CODE is
// chosen by substring-matching the verification error text for words like "key",
// "signed" or "trust" — and several of those error texts embed the CAPABILITY
// NAME, which the contract author chooses.
//
// So a capability called "api-keys" (or "monkey-cache", or anything containing
// "key") turns every STRUCTURAL corruption into a reported `capsule-trust-refused`.
// The consequence is bounded — both codes withhold the capability's events and
// answer unknown — but the code is the machine-readable half of the report, and
// this repo has already ruled once (D62/D73) that classifying on substrings of
// text that embeds user-controlled ids is spoofable and must not decide anything.
func TestPartialCodeIsNotSpoofableByCapabilityName(t *testing.T) {
	ledger.ResetSigning()
	dir := t.TempDir()
	// a perfectly ordinary capability name that happens to contain "key"
	src := buildLinearLedger(t, "api-keys", 3)
	anchorPath, capsules := emitAnchorAndCapsules(t, src, filepath.Join(dir, "backup"), "api-keys")

	// STRUCTURAL corruption. Nothing to do with signatures or trust.
	c := loadCapsuleFile(t, capsules[0])
	ev, _ := c.Events[0]["event"].(map[string]any)
	if ev == nil {
		t.Fatal("capsule event has no event block")
	}
	// drop the capability from the event's list — VerifyCapsule then reports
	// `does not list capability "api-keys"`, a message that embeds the NAME.
	ev["capabilities"] = []any{"something-else"}
	writeJSON(t, capsules[0], c)

	rep, code := Run(Options{
		Out:          filepath.Join(dir, "restored.jsonl"),
		AnchorPath:   anchorPath,
		CapsulePaths: capsules,
		Partial:      true,
	})
	if code == ExitOK && len(rep.Partial) == 0 {
		t.Fatalf("a tampered capsule must not restore silently: %+v", rep)
	}
	var got CapStatus
	for _, st := range rep.Partial {
		if st.Capability == "api-keys" {
			got = st
		}
	}
	if got.Status != "unknown" {
		t.Fatalf("a tampered capsule must be unknown, got %+v (reasons %v)", got, rep.Reasons)
	}
	if got.Code != "capsule-tampered" {
		t.Errorf("structural corruption must report capsule-tampered; got %q — the "+
			"capability NAME (%q, contains \"key\") decided the code, which makes the "+
			"machine-readable half of the report author-controlled.\nreason: %s",
			got.Code, "api-keys", got.Reason)
	}
	if strings.Contains(got.Code, "trust") {
		t.Errorf("no signature or trust policy was involved in this failure at all")
	}
}

// The other direction: a GENUINE trust failure must still report
// capsule-trust-refused. Nothing covered this code before D312 — the typed error
// could have made it unreachable and every test would still have passed.
func TestPartialTrustFailureReportsTrustRefused(t *testing.T) {
	ledger.ResetSigning()
	dir := t.TempDir()

	// a ledger signed by key A
	seedA := strings.Repeat("11", 32)
	keyA := filepath.Join(dir, "a.key")
	if err := os.WriteFile(keyA, []byte(seedA), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ledger.LoadSignKey(keyA); err != nil {
		t.Fatal(err)
	}
	src := buildLinearLedger(t, "orders-db", 3)
	anchorPath, capsules := emitAnchorAndCapsules(t, src, filepath.Join(dir, "backup"), "orders-db")

	// verified under a trust policy that only knows key B — a foreign-key refusal,
	// not corruption: every hash and every link is intact.
	ledger.ResetSigning()
	pubB := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32)).Public().(ed25519.PublicKey)
	if err := ledger.AddTrust(hex.EncodeToString(pubB)); err != nil {
		t.Fatal(err)
	}
	defer ledger.ResetSigning()

	rep, _ := Run(Options{
		Out:          filepath.Join(dir, "restored.jsonl"),
		AnchorPath:   anchorPath,
		CapsulePaths: capsules,
		Partial:      true,
	})
	var got CapStatus
	for _, st := range rep.Partial {
		if st.Capability == "orders-db" {
			got = st
		}
	}
	if got.Status != "unknown" {
		t.Fatalf("a capsule signed by an untrusted key must not restore: %+v", got)
	}
	if got.Code != "capsule-trust-refused" {
		t.Errorf("a foreign-key signature is a TRUST refusal, not corruption; "+
			"got code %q (reason: %s)", got.Code, got.Reason)
	}
}
