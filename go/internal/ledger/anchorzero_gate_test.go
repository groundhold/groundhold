package ledger

import "testing"

// D613. An anchor exists to detect a rewrite: it pins "this ledger, at this length,
// hashed to this". `CheckAnchor` had two ways to say yes to an anchor that pins
// nothing about the ledger in front of it.
//
// (1) A zero-event anchor over a NON-EMPTY ledger returned "verified". The inflating
// direction — 0 events but a non-genesis head — had been closed by an adversarial
// review with the comment "don't rubber-stamp any ledger"; the deflating direction was
// left. Measured: a 19-event ledger with a tampered tip, checked against
// `{"events":0,"head":"genesis"}`, returned `{"status":"verified"}` at exit 0, and
// `attest` republished that word to the console.
//
// (2) `LedgerId` was never compared, so an anchor built for a different ledger
// verified. D312 had already built `RequireIdentity` for exactly this and wired it into
// `restore` and `capsule --verify`; `anchor --check` — the verb whose whole job is this
// question — did not call it.
//
// "I could not check" is not "I checked". The zero-event case is now `unverifiable`,
// which the CLI exits 5 on, with a reason that tells the operator to treat the document
// as no anchor rather than as a passed check.
func TestZeroEventAnchorDoesNotVerifyANonEmptyLedger(t *testing.T) {
	led := &Ledger{EventHashes: []string{"sha256:1", "sha256:2", "sha256:3",
		"sha256:4", "sha256:5"}}
	if led.TotalEvents() != 5 {
		t.Fatalf("fixture holds %d events, want 5 — the gate would test nothing",
			led.TotalEvents())
	}

	res := CheckAnchor(led, &Anchor{Events: 0, Head: "genesis"})
	if res.Status == "verified" {
		t.Error("a zero-event anchor was accepted as proof over a five-event ledger — " +
			"it witnesses nothing, so it cannot detect the rewrite it exists to detect")
	}
	if res.Status != "unverifiable" {
		t.Errorf("status = %q, want \"unverifiable\" — the anchor is not WRONG, it is "+
			"silent, and the two must not share a word", res.Status)
	}
	if len(res.Reasons) == 0 {
		t.Error("no reason given — an operator cannot act on a bare status")
	}

	// The honest empty case still passes: nothing anchored, nothing to detect.
	if got := CheckAnchor(&Ledger{}, &Anchor{Events: 0, Head: "genesis"}); got.Status != "verified" {
		t.Errorf("an empty anchor over an empty ledger = %q, want verified — the "+
			"refusal must be about silence over real history, not about strictness",
			got.Status)
	}
}

func TestForeignAnchorDoesNotWitnessThisLedger(t *testing.T) {
	led := &Ledger{EventHashes: []string{"sha256:aaaa"}}
	res := CheckAnchor(led, &Anchor{Events: 1, Head: "sha256:whatever",
		LedgerId: "sha256:bbbb"})
	if res.Status == "verified" {
		t.Error("an anchor manifesting a DIFFERENT ledger verified this one — " +
			"identity must be checked before arithmetic")
	}
	if res.Status != "diverged" {
		t.Errorf("status = %q, want diverged", res.Status)
	}
}
