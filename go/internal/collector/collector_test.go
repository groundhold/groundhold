package collector

import (
	"path/filepath"
	"testing"

	"groundhold/internal/ledger"
)

// capsuleWith builds a valid, structurally-sound one-capability capsule whose
// single observation.recorded event carries obs — so Certify's STRUCTURE check
// passes and the honesty checks are what decide the verdict.
func capsuleWith(t *testing.T, obs map[string]any) *ledger.Capsule {
	t.Helper()
	ledger.ResetSigning()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := &ledger.Writer{Path: path, Led: led, Env: "test", Actor: "t", Clock: 1000}
	if err := w.Append("observation.recorded", []string{"billing-db"},
		map[string]any{"observations": []any{obs}}, 0); err != nil {
		t.Fatal(err)
	}
	c, err := ledger.EmitCapsule(path, "billing-db")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func measured() map[string]any {
	return map[string]any{"path": "encryption.atRest", "value": true,
		"observedAt": "2026-07-15T08:06:00Z", "derivation": "measured", "source": "collector"}
}

// TestCertifyCleanCapsule: a well-formed collector capsule certifies.
func TestCertifyCleanCapsule(t *testing.T) {
	rep := Certify(capsuleWith(t, measured()))
	if rep.Status != "certified" {
		t.Fatalf("a clean capsule must certify, got %s: %+v", rep.Status, rep.Findings)
	}
	if rep.Capability != "billing-db" || rep.Events != 1 {
		t.Fatalf("report meta wrong: %+v", rep)
	}
}

// TestCertifyRejectsSecretValue: an observation value carrying a secret signature
// (an AWS access key) is rejected by the D53 boundary scan.
func TestCertifyRejectsSecretValue(t *testing.T) {
	o := measured()
	o["value"] = "AKIAIOSFODNN7EXAMPLE"
	rep := Certify(capsuleWith(t, o))
	if rep.Status != "rejected" || !hasKind(rep, "secret") {
		t.Fatalf("a secret-valued observation must be rejected as secret, got %+v", rep)
	}
}

// TestCertifyRejectsSecretNamedPath: an observation mapped to a secret-named path
// is rejected — a capability attribute is never a secret.
func TestCertifyRejectsSecretNamedPath(t *testing.T) {
	o := measured()
	o["path"] = "auth.token"
	rep := Certify(capsuleWith(t, o))
	if rep.Status != "rejected" || !hasKind(rep, "secret") {
		t.Fatalf("a secret-named path must be rejected, got %+v", rep)
	}
}

// TestCertifyRejectsBadDerivation: an observation with an invented basis is rejected.
func TestCertifyRejectsBadDerivation(t *testing.T) {
	o := measured()
	o["derivation"] = "guessed"
	rep := Certify(capsuleWith(t, o))
	if rep.Status != "rejected" || !hasKind(rep, "derivation") {
		t.Fatalf("an invalid derivation must be rejected, got %+v", rep)
	}
}

// TestCertifyRejectsMissingObservedAt: an observation with no observedAt is rejected
// (the core must own freshness).
func TestCertifyRejectsMissingObservedAt(t *testing.T) {
	o := measured()
	delete(o, "observedAt")
	rep := Certify(capsuleWith(t, o))
	if rep.Status != "rejected" || !hasKind(rep, "observedAt") {
		t.Fatalf("a missing observedAt must be rejected, got %+v", rep)
	}
}

// TestCertifyRejectsTamperedStructure: a byte-flipped event breaks the hash chain,
// so VerifyCapsule refuses before any honesty check — corruption cannot be laundered.
func TestCertifyRejectsTamperedStructure(t *testing.T) {
	c := capsuleWith(t, measured())
	ev, _ := c.Events[0]["event"].(map[string]any)
	ev["environment"] = "TAMPERED"
	rep := Certify(c)
	if rep.Status != "rejected" || !hasKind(rep, "structure") {
		t.Fatalf("a tampered capsule must be rejected on structure, got %+v", rep)
	}
}

func hasKind(rep *Report, kind string) bool {
	for _, f := range rep.Findings {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

// TestFutureDatedNumericCompare pins the trust-boundary honesty gate: an
// observation whose RFC3339 offset makes it chronologically LATER than the
// capsule asOf must be caught even though its string sorts EARLIER. A lexical
// compare (the pre-fix bug) would let a collector forge freshness past the gate.
func TestFutureDatedNumericCompare(t *testing.T) {
	asOf := "2026-07-19T23:00:00Z"
	asOfSec, err := ledger.ParseTs(asOf)
	if err != nil {
		t.Fatalf("parse asOf: %v", err)
	}
	// -05:00 offset: 20:00-05:00 == 2026-07-20T01:00:00Z, two hours AFTER asOf,
	// yet "2026-07-19T20:..." < "2026-07-19T23:..." byte-wise.
	trap := "2026-07-19T20:00:00-05:00"
	if trap >= asOf {
		t.Fatalf("test premise broken: %q should string-sort before %q", trap, asOf)
	}
	if future, bad := futureDated(trap, asOfSec); !future || bad {
		t.Errorf("offset-future observation must be caught: future=%v bad=%v", future, bad)
	}
	// A genuinely earlier observation is not future-dated.
	if future, _ := futureDated("2026-07-19T10:00:00Z", asOfSec); future {
		t.Errorf("an earlier observation must not be flagged future-dated")
	}
	// Exactly at asOf is not past it.
	if future, _ := futureDated("2026-07-19T23:00:00Z", asOfSec); future {
		t.Errorf("occurredAt == asOf is not past asOf")
	}
	// Fail closed: an unparseable occurredAt cannot prove freshness.
	if _, bad := futureDated("not-a-time", asOfSec); !bad {
		t.Errorf("an unparseable occurredAt must report unparseable (fail closed)")
	}
}

// D759: the boundary check is the other home of the closed set (spec/state.schema.json
// is the first). A collector emitting a platform guarantee must be able to SAY so, and an
// invented basis must still be rejected — the point of a closed set.
//
// The first version of this test asked the MAP directly, so the mutant that disarmed the
// boundary survived it: it measured the data, not the enforcement. Same trap as D726,
// caught by the meter rather than by me.
func TestBoundaryAcceptsPlatformInvariantAndStillRejectsInventedBases(t *testing.T) {
	for _, c := range []struct {
		derivation string
		wantReject bool
	}{
		{"measured", false},
		{"config-intent", false},
		{"platform-invariant", false},
		{"", true},
		{"inferred", true},
		{"platform", true}, // near-miss: a closed set is closed
	} {
		o := measured()
		o["derivation"] = c.derivation
		rep := Certify(capsuleWith(t, o))
		rejected := hasKind(rep, "derivation")
		if rejected != c.wantReject {
			t.Errorf("derivation %q: boundary rejected=%v, want %v — this drives Certify, "+
				"which is what actually closes the set (D759)", c.derivation, rejected, c.wantReject)
		}
	}
}
