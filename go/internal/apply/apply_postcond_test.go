package apply

import (
	"testing"

	"groundhold/internal/cloudfake"
	"groundhold/internal/ledger"
	"groundhold/internal/provider"
)

// worldFake is provider.Fake with its wire mutations mirrored into a cloudfake.World —
// the adapter that lets the ledger-vs-world postcondition run on a REAL apply.Apply.
// record=false simulates a driver that reports a providerId WITHOUT actually creating
// the resource (the D62 phantom-receipt bug).
type worldFake struct {
	*provider.Fake
	w      *cloudfake.World
	record bool
}

func (f *worldFake) Create(service, capability, environment string,
	attrs, impl map[string]any, key string, generation int) provider.CreateResult {
	res := f.Fake.Create(service, capability, environment, attrs, impl, key, generation)
	if f.record && res.Status == "succeeded" && res.ProviderID != "" {
		f.w.Create(res.ProviderID, service, nil) // the wire actually created it
	}
	return res
}

func boundPIDs(l *ledger.Ledger) []string {
	var out []string
	for _, pid := range l.BoundProviderIDs() {
		out = append(out, pid)
	}
	return out
}

// TestApplyLedgerWorldConsistency wires the ledger-vs-world diff (invariant 7) onto a
// REAL apply.Apply run. A faithful provider records every create on the wire and the
// diff is clean. A provider that binds a providerId it never actually created is caught
// structurally — the ledger asserts a resource the World never saw (D62). This is the
// postcondition running on real code, not a self-contained helper demo.
func TestApplyLedgerWorldConsistency(t *testing.T) {
	t.Run("faithful/clean", func(t *testing.T) {
		c, cand, plan := setupPlan(t)
		w := cloudfake.New(0)
		lp := freshLedger(t)
		res := Apply(c, cand, nil, plan, lp, &worldFake{Fake: &provider.Fake{}, w: w, record: true}, pfAt, false)
		if res.Status != "applied" {
			t.Fatalf("apply status = %s (%v)", res.Status, res.Reasons)
		}
		led, err := ledger.ReplayFile(lp)
		if err != nil {
			t.Fatal(err)
		}
		phantom, unrec := cloudfake.LedgerWorldDiff(w.CreatedIDs(), boundPIDs(led))
		if len(phantom) != 0 || len(unrec) != 0 {
			t.Fatalf("faithful apply must diff clean: phantom=%v unrecorded=%v (created=%v)",
				phantom, unrec, w.CreatedIDs())
		}
	})

	t.Run("phantom-receipt/caught", func(t *testing.T) {
		c, cand, plan := setupPlan(t)
		w := cloudfake.New(0)
		lp := freshLedger(t)
		// record=false: the provider reports success but never touched the wire.
		Apply(c, cand, nil, plan, lp, &worldFake{Fake: &provider.Fake{}, w: w, record: false}, pfAt, false)
		led, err := ledger.ReplayFile(lp)
		if err != nil {
			t.Fatal(err)
		}
		phantom, _ := cloudfake.LedgerWorldDiff(w.CreatedIDs(), boundPIDs(led))
		if len(phantom) == 0 {
			t.Fatalf("a ledger binding with no wire create must be flagged phantom (bound=%v)", boundPIDs(led))
		}
	})
}
