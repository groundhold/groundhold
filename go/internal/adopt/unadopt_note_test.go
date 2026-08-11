package adopt

import (
	"strings"
	"testing"

	"groundhold/internal/ledger"
	"groundhold/internal/provider"
	"groundhold/internal/verify"
)

// D573. `unadopt` describes itself honestly: "removes the binding, never the
// resource". An operator reads that as leaving no trace. If groundhold CLAIMED the
// resource while it was bound, a trace stays — the ownership marker — and it has a
// consequence they meet later, not now.
//
// Measured on the live cluster. A Role carrying groundhold's labels for capability
// `app`, adopted as `legacy`, then unadopted; the next converge planned a create and
// the driver refused:
//
//	action a-create-legacy failed: a Role already exists at this name and its
//	labels are not ours — refusing to adopt it
//
// Which is right — ownership is per CAPABILITY, not per tool (D462), and it fails
// closed. But the operator meets it one verb later, with nothing connecting the two
// events, and the tool that left the marker said nothing when it left it.
//
// The note fires only when the capability was CLAIMED. Unadopting something never
// claimed leaves no marker, and warning about one would be a false statement of the
// same kind this note exists to prevent (D555: say what is true, stay quiet
// otherwise).
func TestUnadoptSaysTheOwnershipMarkerStays(t *testing.T) {
	res := unadoptClaimed(t)
	joined := strings.Join(res.Notes, " | ")
	if !strings.Contains(joined, "ownership marker") {
		t.Errorf("unadopt released a CLAIMED resource and said nothing about the marker "+
			"it leaves behind.\nnotes = %v\nA create at that name later refuses "+
			"(\"labels are not ours\") and nothing connects it to this run.", res.Notes)
	}
}

// The converse: nothing claimed, nothing to warn about.
func TestUnadoptStaysQuietWhenNothingWasClaimed(t *testing.T) {
	res := unadoptUnclaimed(t)
	for _, n := range res.Notes {
		if strings.Contains(n, "ownership marker") {
			t.Errorf("a capability that was never claimed was warned about a marker "+
				"groundhold never wrote: %q", n)
		}
	}
}

func unadoptFixture(t *testing.T, claim bool) *Result {
	t.Helper()
	c, cand, led, ledgerPath := intentFixture(t)
	_ = c
	report, _ := verify.Verify(c, cand, nil)
	prov := intentFake{Fake: &provider.Fake{}, region: "eu-central-1"}
	if r, code := Run(c, cand, report, map[string]string{"store": "fake:my-bucket"},
		prov, led, ledgerPath, "2026-07-25T11:00:00Z", ""); code != 0 {
		t.Fatalf("setup adopt: %+v", r)
	}
	if claim {
		seedClaim(t, ledgerPath, "store")
	}
	replayed, err := ledger.ReplayFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	res, code := Unadopt("store", replayed, ledgerPath, "dev", "2026-07-25T12:00:00Z")
	if code != 0 {
		t.Fatalf("unadopt refused: %+v", res)
	}
	return res
}

func unadoptClaimed(t *testing.T) *Result   { return unadoptFixture(t, true) }
func unadoptUnclaimed(t *testing.T) *Result { return unadoptFixture(t, false) }

// seedClaim records the ownership.claimed event a real claim action writes.
func seedClaim(t *testing.T, ledgerPath, capID string) {
	t.Helper()
	led, err := ledger.ReplayFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	w := &ledger.Writer{Path: ledgerPath, Led: led, Env: "dev",
		Clock: 1784979000, Actor: "t"}
	tok, err := w.AppendLease([]string{capID}, map[string]any{"ttlSeconds": 300})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append("ownership.claimed", []string{capID}, map[string]any{
		"capability": capID, "providerId": "fake:my-bucket",
	}, tok); err != nil {
		t.Fatal(err)
	}
	if err := w.Append("lease.released", []string{capID}, nil, tok); err != nil {
		t.Fatal(err)
	}
}
